package henv

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const PAYLOAD_ADDRESS = ":9022"

type ProcessSocket struct {
	mtx sync.Mutex
	net.Conn
	fp      *os.File
	fd      int
	childFd int
}

func (p *Payload) WriteMessage(msgType AppMessageType, msg []byte) (err error) {
	emsg := ExternalAppMessage{
		sender:      uint32(getpid()),
		msgType:     uint32(msgType),
		payloadSize: uint32(len(msg)),
	}
	const length = unsafe.Sizeof(emsg)
	n, err := p.Write(unsafe.Slice((*byte)(unsafe.Pointer(&emsg)), length))
	if n < int(length) {
		err = fmt.Errorf("only wrote %v out of %v bytes", n, length)
	}
	if err != nil {
		log.Println(err)
		return
	}
	n, err = p.Write(msg)
	if n < len(msg) {
		err = fmt.Errorf("only wrote %v out of %v bytes", n, len(msg))
	}
	if err != nil {
		log.Println(err)
		return
	}
	return nil
}

func NewProcessSocket(name string) (s *ProcessSocket, fd int, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(err)
		return
	}
	fd = fds[1]
	fp := os.NewFile(uintptr(fds[0]), name)
	conn, err := net.FileConn(fp)
	if err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		fp.Close()
		log.Println(err)
		return
	}
	s = &ProcessSocket{
		Conn:    conn,
		fp:      fp,
		fd:      fds[0],
		childFd: fds[1],
	}
	return
}

func (s *ProcessSocket) closeUnneeded() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.fp.Close()
	syscall.Close(s.fd)
	syscall.Close(s.childFd)
	s.fd = 0

}

func (s *ProcessSocket) Close() (err error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.fd > 0 {
		err = s.Conn.Close()
		s.fd = -1
	} else if s.fd == 0 {
		err = s.Conn.Close()
		err = errors.Join(err, s.fp.Close())
		err = errors.Join(err, syscall.Close(s.fd))
		err = errors.Join(err, syscall.Close(s.childFd))
		s.fd = -1
	}
	return
}

func (hen *HenV) SpawnPayload(num int, ctx context.Context) (p *Payload, err error) {
	s, fd, err := NewProcessSocket(fmt.Sprintf("payload%d-socket", num))
	if err != nil {
		log.Println(err)
		return
	}
	pid, err := spawn(true, PAYLOAD_EBOOT_PATH, "", []string{"payload0.bin"})
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err != nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}()

	tracer, err := NewTracer(pid)
	if err != nil {
		log.Println(err)
		return
	}

	defer tracer.Detach()

	var regs Reg
	tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	tracer.ptrace(PT_CONTINUE, uintptr(regs.Rip), int(syscall.SIGCONT))

	proc := GetProc(pid)
	eboot := proc.GetEboot()
	base := eboot.GetImageBase()

	if base == 0 {
		err = ErrBadImageBase
		log.Println(err)
		return
	}

	log.Println("correcting payload heap")

	_, err = tracer.Syscall(syscall.SYS_DYNLIB_PROCESS_NEEDED_AND_RELOCATE, 0, 0, 0, 0, 0, 0)
	if err != nil {
		log.Println(err)
		return
	}

	// patch heap now
	param, err := tracer.GetProcParam()
	if err != nil {
		log.Println(err)
		return
	}

	libcparam, err := param.GetLibcParam()
	if err != nil {
		log.Println(err)
		return
	}

	libcparam.SetHeapSize(-1)
	libcparam.EnableExtendedAlloc()

	log.Printf("eboot base: %#08x\n", base)

	loop := NewLoopBuilder()

	lib := proc.GetLib(1)
	if lib == 0 {
		lib = proc.GetLib(LIBKERNEL_HANDLE)
		if lib == 0 {
			err = ErrNoLibKernel
			log.Println(err)
			return
		}
		log.Println("normal libkernel handle worked")
	}

	log.Printf("libkernel base: %#08x\n", lib.GetImageBase())

	usleep := lib.GetAddress(USLEEP_NID)
	if usleep == 0 {
		err = ErrNoUsleep
		log.Println(err)
		return
	}

	loop.setUsleepAddress(usleep)
	loop.setPid(tracer.pid)

	_, err = UserlandCopyin(tracer.pid, eboot.GetEntryPoint(), loop.data[:])
	if err != nil {
		err = errors.Join(ErrCopyLoop, err)
		log.Println(err)
		return
	}

	// patch __DT_INIT to a single RET to prevent it from loading libraries, starting threads, etc.
	ret := []byte{0xc3}
	_, err = UserlandCopyin(tracer.pid, base+0x10, ret)
	if err != nil {
		err = errors.Join(ErrCopyLoop, err)
		log.Println(err)
		return
	}

	err = tracer.Continue()
	if err != nil {
		log.Println(err)
		return
	}

	status, err := tracer.Wait(0)
	if err != nil {
		log.Println(err)
		return
	}

	if !status.Stopped() {
		var regs Reg
		tracer.GetRegisters(&regs)
		regs.Dump(log.Writer())
		log.Printf("state: %#08x\n", status)
		log.Println(status.Signal())
		err = ErrProcessNotStopped
		log.Println(err)
		return
	}

	if status.StopSignal() != syscall.SIGTRAP {
		err = getUnexpectedSignalError(status.StopSignal())
		log.Println(err)
		return
	}

	err = tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	if regs.Rip != int64(eboot.GetEntryPoint())+1 {
		err = ErrUnexpectedRip
		log.Println(err)
		return
	}

	proc.EscalatePrivileges()

	newfd, err := tracer.Syscall(syscall.SYS_RDUP, uintptr(getpid()), uintptr(fd), 0, 0, 0, 0)
	if err != nil {
		syscall.Kill(pid, syscall.SIGKILL)
		log.Println(err)
		return
	}
	if newfd != 3 {
		err = fmt.Errorf("expected child's parent socket to be 3 but was %d", newfd)
		syscall.Kill(pid, syscall.SIGKILL)
		log.Println(err)
	}
	s.closeUnneeded()
	p = &Payload{
		Conn: s,
		num:  num,
		pid:  pid,
	}
	hen.addPayload(num, p)
	hen.wg.Add(1)
	go hen.processPayloadMessages(p, ctx)
	return
}

func (hen *HenV) payloadHandler(payloads chan ElfLoadInfo) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()
	for info := range payloads {
		func() {
			defer info.Close()
			err := info.LoadElf(hen)
			if err != nil {
				log.Println(err)
				syscall.Kill(info.pid, syscall.SIGKILL)
				return
			}
			proc := GetProc(info.pid)
			if proc == 0 {
				log.Printf("Failed to get kernel proc for pid %v\n", info.pid)
				return
			}
			proc.SetName(fmt.Sprintf("Payload %v", info.payload))
		}()
	}
}

func (hen *HenV) runPayloadServer(ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()

	log.Println("payload server started")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ldr := make(chan ElfLoadInfo, 4)
	defer close(ldr)

	hen.wg.Add(1)
	go hen.payloadHandler(ldr)

	var cfg net.ListenConfig
	ln, err := cfg.Listen(ctx, "tcp", PAYLOAD_ADDRESS)
	if err != nil {
		// NO PAYLOADS FOR YOU
		log.Println(err)
		log.Println("payload server failed to start")
		return
	}

	reconnect := func() {
		ln.Close()
		log.Println("reconnecting")
		ln, err = cfg.Listen(ctx, "tcp", PAYLOAD_ADDRESS)
		if err != nil {
			// NO PAYLOADS FOR YOU
			log.Println(err)
			log.Println("payload server failed to start")
			return
		}
	}

	done := ctx.Done()

	for {
		select {
		case <-done:
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				err2 := errors.Unwrap(err)
				if err2.Error() == "accept4: errno 163" {
					// entering rest mode
					time.Sleep(time.Second)
					reconnect()
				} else {
					log.Println(err)
				}
				continue
			}

			num := hen.getNextPayloadNum()

			p, err := hen.SpawnPayload(num, ctx)
			if err != nil {
				log.Println(err)
				conn.Close()
				continue
			}

			ldr <- ElfLoadInfo{
				pid:     p.pid,
				reader:  conn,
				payload: num,
			}
		}
	}
}

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

type LocalProcessArgs struct {
	_                 int32
	fd                int32
	enableCrashReport int32
	userId            int32
	_                 uint64
	preloadPrxFlags   uint64
}

type LocalProcess struct {
	net.Conn
	num int
}

func (p *LocalProcess) WriteMessage(msgType AppMessageType, msg []byte) (err error) {
	emsg := ExternalAppMessage{
		sender:      uint32(getpid()),
		msgType:     uint32(msgType),
		payloadSize: uint32(len(msg)),
	}
	const length = unsafe.Sizeof(emsg)
	n, err := p.Write(unsafe.Slice((*byte)(unsafe.Pointer(&emsg)), length))
	if n < int(length) {
		err = fmt.Errorf("only wrote %v out of %v bytes\n", n, length)
	}
	if err != nil {
		log.Println(err)
		return
	}
	n, err = p.Write(msg)
	if n < len(msg) {
		err = fmt.Errorf("only wrote %v out of %v bytes\n", n, len(msg))
	}
	if err != nil {
		log.Println(err)
		return
	}
	return nil
}

type ProcessSocket struct {
	mtx sync.Mutex
	net.Conn
	fp      *os.File
	fd      int
	childFd int
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

func newLocalProcess(num int) (LocalProcess, int, error) {
	s, fd, err := NewProcessSocket(fmt.Sprintf("payload%d-socket", num))
	if err != nil {
		log.Println(err)
		return LocalProcess{}, -1, err
	}
	return LocalProcess{Conn: s, num: num}, fd, nil
}

func SystemServiceAddLocalProcess(num int, hen *HenV, ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			return
		}
		hen.ClosePayload(num)
	}()

	status, err := SystemServiceGetAppStatus()
	if err != nil {
		log.Println(err)
		return
	}

	hen.wg.Add(1)
	go func() {
		defer hen.wg.Done()

		p, fd, err := newLocalProcess(num)

		if err != nil {
			log.Println(err)
			return
		}

		hen.setPayloadProcess(num, p)

		param := &LocalProcessArgs{
			fd:                int32(fd),
			enableCrashReport: 0,
			userId:            -1,
		}

		argv := []uintptr{0}
		path := []byte(fmt.Sprintf("/app0/payload%d.bin\x00", num))
		res, _, _ := sceSystemServiceAddLocalProcess.Call(
			uintptr(status.id),
			uintptr(unsafe.Pointer(&path[0])),
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(param)),
		)

		if uint32(res) == uint32(0x80AA0008) {
			// we need to push an invalid value so that the elf loader will stop blocking
			hen.payloadChannel <- -1
			err = ErrTooManyPayloads
			log.Println(err)
			return
		}

		if int32(res) < 0 {
			err = fmt.Errorf("sceSystemServiceAddLocalProcess failed: %#x", int32(res))
			// we need to push an invalid value so that the elf loader will stop blocking
			hen.payloadChannel <- -1
			log.Println(err)
			return
		}

		hen.wg.Add(1)
		p.Conn.(*ProcessSocket).closeUnneeded()
		go hen.processPayloadMessages(p, ctx)
	}()

	return
}

func (hen *HenV) handlePayload(num int, ctx context.Context) error {

	err := SystemServiceAddLocalProcess(num, hen, ctx)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
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
				return
			}
			hen.setPayloadPid(info.payload, info.pid)
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

	for {
		select {
		case _, _ = <-ctx.Done():
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				err2 := errors.Unwrap(err)
				if err2.Error() != "accept4: errno 163" {
					// not entering rest mode
					log.Println(err)
				}
				reconnect()
				time.Sleep(time.Second)
				continue
			}

			num, err := hen.NextPayload()
			if err != nil {
				log.Println(err)
				continue
			}

			ldr <- ElfLoadInfo{
				pidChannel: hen.payloadChannel,
				pid:        -1,
				reader:     conn,
				payload:    num,
			}

			err = hen.handlePayload(num, ctx)
			if err != nil {
				log.Println(err)
				conn.Close()
			}
		}
	}
}

package henv

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	LOOB_BUILDER_SIZE     = 45
	ENTRYPOINT_OFFSET     = 0x70
	IPC_PATH              = "/system_tmp/IPC"
	USLEEP_NID        Nid = "QcteRwbsnV0"
	KILL_NID          Nid = "W0xkN0+ZkCE"
)

var (
	ErrProcessDied   = errors.New("process died")
	ErrNoLibKernel   = errors.New("failed to get libkernel")
	ErrNoEboot       = errors.New("failed to get eboot")
	ErrNoUsleep      = errors.New("failed to find usleep")
	ErrNoKill        = errors.New("failed to find kill")
	ErrBadImageBase  = errors.New("invalid image base")
	ErrCopyLoop      = errors.New("failed to copyin usleep loop")
	ErrUnexpectedRip = errors.New("unexpected rip value, something went wrong")
)

const IPC_PROCESS_LAUNCHED = 1

type IpcResult struct {
	cmd    int32
	pid    int32
	args   uintptr
	fun    uintptr
	prefix uint32
	_      uint32
}

type LoopBuilder struct {
	data [LOOB_BUILDER_SIZE]byte
}

func NewLoopBuilder() LoopBuilder {
	return LoopBuilder{[...]byte{
		// INT3
		0xcc,
		// MOV RAX, usleep
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// MOV RDI, 4000000 // 4 seconds chosen by fair dice roll
		0x48, 0xc7, 0xc7, 0x00, 0x09, 0x3d, 0x00,
		// CALL RAX
		0xff, 0xd0,
		// MOV RDI, pid
		0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,
		// MOV ESI, SIGKILL
		0xbe, 0x09, 0x00, 0x00, 0x00,
		// MOV RAX, kill
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// CALL RAX
		0xff, 0xd0,
		// INT3
		0xcc,
	}}
}

func (loop *LoopBuilder) setUsleepAddress(addr uintptr) {
	const LOOP_BUILDER_TARGET_OFFSET = 3
	binary.LittleEndian.PutUint64(loop.data[LOOP_BUILDER_TARGET_OFFSET:], uint64(addr))
}

func (loop *LoopBuilder) setPid(pid int) {
	const LOOP_BUILDER_TARGET_OFFSET = 24
	binary.LittleEndian.PutUint32(loop.data[LOOP_BUILDER_TARGET_OFFSET:], uint32(pid))
}

func (loop *LoopBuilder) setKillAddress(addr uintptr) {
	const LOOP_BUILDER_TARGET_OFFSET = 35
	binary.LittleEndian.PutUint64(loop.data[LOOP_BUILDER_TARGET_OFFSET:], uint64(addr))
}

func fileExists(path string) bool {
	return syscall.Access(path, syscall.F_OK) == nil
}

func startSyscoreIpc(hen *HenV, ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()

	log.Println("syscore ipc started")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for fileExists(IPC_PATH) {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Millisecond * 10)
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", IPC_PATH)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	ln.(*net.UnixListener).SetUnlinkOnClose(true)

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	reconnector := func() net.Conn {
		conn.Close()
		conn = nil
		cn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		return cn
	}

	// this goroutine may no longer be evicted
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	inflight := 0
	defer func() {
		if inflight != 0 {
			log.Println("killing launched process")
			syscall.Kill(inflight, syscall.SIGKILL)
		}
	}()

	for {
		var cmd IpcResult
		const PACKET_SIZE = unsafe.Sizeof(cmd)
		buf := unsafe.Slice((*byte)(unsafe.Pointer(&cmd)), PACKET_SIZE)
		n, err := conn.Read(buf)
		if n != int(PACKET_SIZE) {
			log.Printf("syscore ipc only read %v out of %v bytes", n, PACKET_SIZE)
			if err != nil {
				log.Println(err)
			}
			conn = reconnector()
			if n >= 8 {
				syscall.Kill(int(cmd.pid), syscall.SIGKILL)
			}
			continue
		}
		if err != nil {
			log.Println(err)
			syscall.Kill(int(cmd.pid), syscall.SIGKILL)
			conn = reconnector()
			continue
		}

		if cmd.cmd != IPC_PROCESS_LAUNCHED {
			log.Printf("ipc command %v unexpected at this time", cmd.cmd)
			conn = reconnector()
			continue
		}

		hen.listenerChannel <- cmd.pid

		if cmd.fun == 0 {
			// not homebrew
			continue
		}

		inflight = int(cmd.pid)

		tracer, err := NewTracer(int(cmd.pid))
		if err != nil {
			log.Println(err)
			inflight = 0
			// we need to kill the process or else it'll be stuck in an infinite loop
			err = syscall.Kill(int(cmd.pid), syscall.SIGKILL)
			if err != nil {
				log.Println(err)
			}

			continue
		}

		log.Println("tracer attached, sending info over channel")

		hen.homebrewChannel <- HomebrewLaunchInfo{tracer: tracer, fun: cmd.fun, args: cmd.args}
		inflight = 0
	}

}

func isProcessAlive(pid int) bool {
	const MIB_LENGTH = 4
	const CTL_KERN = 1
	const KERN_PROC = 14
	const KERN_PROC_PID = 1
	mib := [MIB_LENGTH]int32{CTL_KERN, KERN_PROC, KERN_PROC_PID, int32(pid)}
	res, _, _ := syscall.RawSyscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), MIB_LENGTH, 0, 0, 0, 0)
	return res == 0
}

func getUnexpectedSignalError(sig syscall.Signal) error {
	return fmt.Errorf("process received signal %s but SIGTRAP was expected", sig.String())
}

func handleHomebrewLaunch(hen *HenV, tracer *Tracer, fun, args uintptr) (err error) {
	defer func() {
		if err != nil {
			tracer.Kill(false)
		}
		if tracer != nil {
			tracer.Detach()
		}
	}()

	var regs Reg
	err = tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	regs.Rip = int64(fun)
	regs.Rdi = int64(args)

	err = tracer.SetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	// run until execve completion
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
		err = ErrProcessNotStopped
		log.Println(err)
		return
	}

	if status.StopSignal() != syscall.SIGTRAP {
		err = getUnexpectedSignalError(status.StopSignal())
		log.Println(err)
		return
	}

	var proc KProc
	for {
		proc = GetProc(tracer.pid)
		if proc == 0 {
			if !isProcessAlive(tracer.pid) {
				err = ErrProcessDied
				log.Println(err)
				return
			}
		} else {
			break
		}
	}

	loop := NewLoopBuilder()

	lib := proc.GetLib(LIBKERNEL_HANDLE)
	if lib == 0 {
		err = ErrNoLibKernel
		log.Println(err)
		return
	}

	usleep := lib.GetAddress(USLEEP_NID)
	if usleep == 0 {
		err = ErrNoUsleep
		log.Println(err)
		return
	}

	loop.setUsleepAddress(usleep)
	loop.setPid(tracer.pid)

	kill := lib.GetAddress(KILL_NID)
	if kill == 0 {
		err = ErrNoKill
		log.Println(err)
		return
	}

	loop.setKillAddress(usleep)

	eboot := proc.GetEboot()
	if eboot == 0 {
		err = ErrNoEboot
		log.Println(err)
		return
	}

	base := eboot.GetImageBase()

	if base == 0 {
		err = ErrBadImageBase
		log.Println(err)
		return
	}

	_, err = UserlandCopyin(tracer.pid, base+ENTRYPOINT_OFFSET, loop.data[:])
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

	status, err = tracer.Wait(0)
	if err != nil {
		log.Println(err)
		return
	}

	if !status.Stopped() {
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

	if regs.Rip != int64(base)+ENTRYPOINT_OFFSET+1 {
		err = ErrUnexpectedRip
		log.Println(err)
		return
	}

	// success

	info, err := GetAppInfo(tracer.pid)
	if err != nil {
		log.Println(err)
		return
	}

	titleid := info.TitleId()

	hen.launchChannel <- LaunchedAppInfo{pid: tracer.pid, titleid: titleid}

	path := proc.GetPath()
	if !strings.HasSuffix(path, "eboot.bin") && hen.hasPrefixHandler(titleid) {
		// prefix handlers may not handle the eboot.bin
		return
	}

	fp, err1 := os.Open("/system_ex/app/" + titleid + "/homebrew.elf")
	if err1 != nil {
		err = err1
		log.Println(err)
		return
	}
	// we load it
	hen.elfChannel <- ElfLoadInfo{
		pid:     tracer.pid,
		tracer:  nil, // detach and reattach
		reader:  fp,
		payload: -1,
	}

	return
}

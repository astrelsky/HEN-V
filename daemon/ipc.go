package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	LOOB_BUILDER_SIZE     = 21
	ENTRYPOINT_OFFSET     = 0x70
	IPC_PATH              = "/system_tmp/IPC"
	USLEEP_NID        Nid = "QcteRwbsnV0"
)

var (
	ErrProcessNotStopped = errors.New("process not stopped")
	ErrProcessDied       = errors.New("process died")
	ErrNoLibKernel       = errors.New("failed to get libkernel")
	ErrNoEboot           = errors.New("failed to get eboot")
	ErrNoUsleep          = errors.New("failed to find usleep")
	ErrCopyLoop          = errors.New("failed to copyin usleep loop")
	ErrUnexpectedRip     = errors.New("unexpected rip value, something went wrong")
)

const (
	IPC_PING             = 0
	IPC_PONG             = 1
	IPC_PROCESS_LAUNCHED = 1
)

type IpcResult struct {
	cmd int32
	pid int32
	fun uintptr
}

type LoopBuilder struct {
	data [LOOB_BUILDER_SIZE]byte
}

func NewLoopBuilder() LoopBuilder {
	return LoopBuilder{[...]byte{
		// INT3
		0xcc,
		//	MOV RAX, usleep
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// MOV RDI, 4000000 // 4 seconds chosen by fair dice roll
		0x48, 0xc7, 0xc7, 0x00, 0x09, 0x3d, 0x00,
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

func fileExists(path string) bool {
	return syscall.Access(path, syscall.F_OK) == nil
}

func handleSyscoreIpc(hen *HenV, ctx context.Context, packets <-chan any) {
	defer os.Remove(IPC_PATH)

}

func startSyscoreIpc(hen *HenV, ctx context.Context) {
	defer hen.wg.Done()
	if fileExists(IPC_PATH) {
		panic(fmt.Errorf("homebrew ipc unix socket %s already exists", IPC_PATH))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", IPC_PATH)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	const flags = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC
	fp, err := os.OpenFile(IPC_PATH, flags, 0777)
	if err != nil {
		panic(err)
	}

	fp.Close()
	defer os.Remove(IPC_PATH)

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

	for {
		var cmd IpcResult
		const PACKET_SIZE = unsafe.Sizeof(cmd)
		buf := unsafe.Slice((*byte)(unsafe.Pointer(&cmd)), PACKET_SIZE)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn = reconnector()
			continue
		}
		if n != int(PACKET_SIZE) {
			log.Printf("syscore ipc only read %v out of %v bytes", n, PACKET_SIZE)
			conn = reconnector()
			continue
		}
		if cmd.cmd == IPC_PING {
			var reply int32 = IPC_PONG
			tmp := unsafe.Slice((*byte)(unsafe.Pointer(&reply)), 4)
			n, err = conn.Write(tmp)

			// NOTE: we panic here because this should NEVER EVER EVER happen
			if err != nil {
				panic(err)
			}
			if n != len(tmp) {
				log.Panicf("syscore ipc only sent %v out of %v bytes", n, len(tmp))
			}

			n, err = conn.Read(buf)
			if err != nil {
				log.Println(err)
				conn = reconnector()
				continue
			}
			if n != int(PACKET_SIZE) {
				log.Printf("syscore ipc only read %v out of %v bytes", n, PACKET_SIZE)
				conn = reconnector()
				continue
			}
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

		tracer, err := NewTracer(int(cmd.pid))
		if err != nil {
			log.Println(err)
			continue
		}

		hen.homebrewChannel <- HomebrewLaunchInfo{tracer: tracer, fun: cmd.fun}
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

func handleHomebrewLaunch(hen *HenV, tracer *Tracer, fun uintptr) (err error) {
	defer tracer.Detach()
	defer func() {
		if err != nil {
			tracer.Kill(false)
		}
	}()
	var regs Reg
	err = tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	regs.Rip = int64(fun)

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
		return
	}

	if status.StopSignal() != syscall.SIGTRAP {
		err = getUnexpectedSignalError(status.StopSignal())
		return
	}

	var proc KProc
	for {
		proc = GetProc(tracer.pid)
		if proc == 0 {
			if !isProcessAlive(tracer.pid) {
				err = ErrProcessDied
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
		return
	}

	usleep := lib.GetAddress(USLEEP_NID)
	if usleep == 0 {
		err = ErrNoUsleep
		return
	}

	loop.setUsleepAddress(usleep)

	eboot := proc.GetEboot()
	if eboot == 0 {
		err = ErrNoEboot
		return
	}

	base := eboot.GetImageBase()

	_, err = UserlandCopyin(tracer.pid, base+ENTRYPOINT_OFFSET, loop.data[:])
	if err != nil {
		err = errors.Join(ErrCopyLoop, err)
		return
	}

	err = tracer.Continue()
	if err != nil {
		return
	}

	status, err = tracer.Wait(0)
	if err != nil {
		return
	}

	if !status.Stopped() {
		err = ErrProcessNotStopped
		return
	}

	if status.StopSignal() != syscall.SIGTRAP {
		err = getUnexpectedSignalError(status.StopSignal())
		return
	}

	err = tracer.GetRegisters(&regs)
	if err != nil {
		return
	}

	if regs.Rip != int64(base)+ENTRYPOINT_OFFSET+1 {
		err = ErrUnexpectedRip
		return
	}

	// success

	info, err := GetAppInfo(tracer.pid)
	if err != nil {
		return
	}

	titleid := info.TitleId()
	if titleid == HenVTitleId {
		// payload
		hen.payloadChannel <- int32(tracer.pid)
		return
	}

	if hen.hasPrefixHandler(titleid[:PREFIX_LENGTH]) {
		hen.prefixChannel <- LaunchedAppInfo{pid: tracer.pid, titleid: titleid}
	} else {
		fp, err1 := os.Open("/system_ex/app/" + titleid + "/homebrew.elf")
		if err1 != nil {
			err = err1
			return
		}
		// we load it
		hen.elfChannel <- ElfLoadInfo{
			pid:     tracer.pid,
			tracer:  nil, // detach and reattach
			reader:  fp,
			payload: false,
		}
	}

	return
}

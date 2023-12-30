package henv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"syscall"
	"unsafe"
)

const (
	PTRACE_DEFAULT    = 0x1
	PTRACE_EXEC       = 0x1
	PTRACE_FORK       = 0x8
	PTRACE_LWP        = 0x10
	PTRACE_SCE        = 0x2
	PTRACE_SCX        = 0x4
	PTRACE_SYSCALL    = 0x6
	PTRACE_VFORK      = 0x20
	PT_ATTACH         = 0xa
	PT_CLEARSTEP      = 0x10
	PT_CONTINUE       = 0x7
	PT_DETACH         = 0xb
	PT_FIRSTMACH      = 0x40
	PT_FOLLOW_FORK    = 0x17
	PT_GETDBREGS      = 0x25
	PT_GETFPREGS      = 0x23
	PT_GETFSBASE      = 0x47
	PT_GETGSBASE      = 0x49
	PT_GETLWPLIST     = 0xf
	PT_GETNUMLWPS     = 0xe
	PT_GETREGS        = 0x21
	PT_GETXSTATE      = 0x45
	PT_GETXSTATE_INFO = 0x44
	PT_GET_EVENT_MASK = 0x19
	PT_GET_SC_ARGS    = 0x1b
	PT_GET_SC_RET     = 0x1c
	PT_IO             = 0xc
	PT_KILL           = 0x8
	PT_LWPINFO        = 0xd
	PT_LWP_EVENTS     = 0x18
	PT_READ_D         = 0x2
	PT_READ_I         = 0x1
	PT_RESUME         = 0x13
	PT_SETDBREGS      = 0x26
	PT_SETFPREGS      = 0x24
	PT_SETFSBASE      = 0x48
	PT_SETGSBASE      = 0x4a
	PT_SETREGS        = 0x22
	PT_SETSTEP        = 0x11
	PT_SETXSTATE      = 0x46
	PT_SET_EVENT_MASK = 0x1a
	PT_STEP           = 0x9
	PT_SUSPEND        = 0x12
	PT_SYSCALL        = 0x16
	PT_TO_SCE         = 0x14
	PT_TO_SCX         = 0x15
	PT_TRACE_ME       = 0x0
	PT_VM_ENTRY       = 0x29
	PT_VM_TIMESTAMP   = 0x28
	PT_WRITE_D        = 0x5
	PT_WRITE_I        = 0x4
)

const (
	_SYSCALL_OFFSET   = 10
	_GET_AUTHINFO_NID = "igMefp4SAv0"
	_ERRNO_NID        = "9BcDykPmo1I"
)

type Tracer struct {
	syscallAddr   uintptr
	libkernelBase uintptr
	errno_addr    uintptr
	pid           int
}

type Reg struct {
	R15    int64
	R14    int64
	R13    int64
	R12    int64
	R11    int64
	R10    int64
	R9     int64
	R8     int64
	Rdi    int64
	Rsi    int64
	Rbp    int64
	Rbx    int64
	Rdx    int64
	Rcx    int64
	Rax    int64
	Trapno uint32
	Fs     uint16
	Gs     uint16
	Err    uint32
	Es     uint16
	Ds     uint16
	Rip    int64
	Cs     int64
	Rflags int64
	Rsp    int64
	Ss     int64
}

var (
	UnexpectedProcessStatusError = errors.New("Unexpected process status")
	ErrProcessNotStopped         = errors.New("process not stopped")
)

func NewTracer(pid int) (*Tracer, error) {
	tracer := &Tracer{
		syscallAddr:   0,
		libkernelBase: 0,
		errno_addr:    0,
		pid:           pid,
	}

	err := tracer.ptrace(PT_ATTACH, 0, 0)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, err := tracer.Wait(0)
	if !status.Continued() { // doesn't make sense but whatever
		return nil, UnexpectedProcessStatusError
	}
	return tracer, nil
}

func (tracer *Tracer) Detach() error {
	var err error
	if tracer.pid != 0 {
		err = tracer.ptrace(PT_DETACH, 0, 0)
		tracer.pid = 0
	}
	return err
}

func (tracer *Tracer) ptrace(request int, addr uintptr, data int) (err error) {
	callback := func() {
		_, _, e1 := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(request), uintptr(tracer.pid), uintptr(addr), uintptr(data), 0, 0)
		if e1 != 0 {
			err = e1
		}
	}
	RunWithCurrentAuthId(PTRACE_ID, callback)
	return
}

func waitpid(pid int, wstatus *syscall.WaitStatus, options int) (wpid int, err error) {
	return syscall.Wait4(pid, wstatus, options, nil)
}

func (tracer *Tracer) Wait(options int) (syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	_, err := waitpid(tracer.pid, &status, options)
	return status, err
}

func (tracer *Tracer) GetRegisters(regs *Reg) error {
	return tracer.ptrace(PT_GETREGS, uintptr(unsafe.Pointer(regs)), 0)
}

func (tracer *Tracer) SetRegisters(regs *Reg) error {
	return tracer.ptrace(PT_SETREGS, uintptr(unsafe.Pointer(regs)), 0)
}

func (tracer *Tracer) Step() error {
	err := tracer.ptrace(PT_STEP, 1, 0)
	if err != nil {
		log.Println(err)
		return err
	}
	status, err := tracer.Wait(0)
	if err != nil {
		log.Println(err)
		return err
	}
	if !status.Stopped() {
		err = fmt.Errorf("unexpected process status %#08x", status)
		log.Println(err)
		return err
	}
	return nil
}

func (tracer *Tracer) Continue() error {
	err := tracer.ptrace(PT_CONTINUE, 1, 0)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (tracer *Tracer) Kill(wait bool) error {
	err := tracer.ptrace(PT_KILL, 0, 0)
	if err != nil {
		log.Println(err)
		return err
	}

	if !wait {
		return nil
	}

	state, err := tracer.Wait(0)
	if err != nil {
		log.Println(err)
		return err
	}

	if !state.Exited() {
		return fmt.Errorf("unexpected process status %#08x", state)
		//return UnexpectedProcessStatusError
	}
	return nil
}

func (regs *Reg) Carry() bool {
	return (regs.Rflags & 1) == 1
}

func (regs *Reg) Dump(w io.Writer) {
	fmt.Fprintf(w, "rax: %#08x\n", uintptr(regs.Rax))
	fmt.Fprintf(w, "rbx: %#08x\n", uintptr(regs.Rbx))
	fmt.Fprintf(w, "rcx: %#08x\n", uintptr(regs.Rcx))
	fmt.Fprintf(w, "rdx: %#08x\n", uintptr(regs.Rdx))
	fmt.Fprintf(w, "rsi: %#08x\n", uintptr(regs.Rsi))
	fmt.Fprintf(w, "rdi: %#08x\n", uintptr(regs.Rdi))
	fmt.Fprintf(w, "r8:  %#08x\n", uintptr(regs.R8))
	fmt.Fprintf(w, "r9:  %#08x\n", uintptr(regs.R9))
	fmt.Fprintf(w, "r10: %#08x\n", uintptr(regs.R10))
	fmt.Fprintf(w, "r11: %#08x\n", uintptr(regs.R11))
	fmt.Fprintf(w, "r12: %#08x\n", uintptr(regs.R12))
	fmt.Fprintf(w, "r13: %#08x\n", uintptr(regs.R13))
	fmt.Fprintf(w, "r14: %#08x\n", uintptr(regs.R14))
	fmt.Fprintf(w, "r15: %#08x\n", uintptr(regs.R15))
	fmt.Fprintf(w, "rbp: %#08x\n", uintptr(regs.Rbp))
	fmt.Fprintf(w, "rsp: %#08x\n", uintptr(regs.Rsp))
	fmt.Fprintf(w, "rip: %#08x\n", uintptr(regs.Rip))
	fmt.Fprintf(w, "Trapno: %#08x\n", uintptr(regs.Trapno))
	fmt.Fprintf(w, "Fs: %#08x\n", uintptr(regs.Fs))
	fmt.Fprintf(w, "Gs: %#08x\n", uintptr(regs.Gs))
	fmt.Fprintf(w, "Err: %#08x\n", uintptr(regs.Err))
	fmt.Fprintf(w, "Es: %#08x\n", uintptr(regs.Es))
	fmt.Fprintf(w, "Ds: %#08x\n", uintptr(regs.Ds))
	fmt.Fprintf(w, "Cs: %#08x\n", uintptr(regs.Cs))
	fmt.Fprintf(w, "Rflags: %#08x\n", uintptr(regs.Rflags))
}

func _set_args(regs *Reg, a, b, c, d, e, f uintptr) {
	regs.Rdi = int64(a)
	regs.Rsi = int64(b)
	regs.Rdx = int64(c)
	regs.Rcx = int64(d)
	regs.R8 = int64(e)
	regs.R9 = int64(f)
}

func (tracer *Tracer) Call(addr uintptr, a, b, c, d, e, f uintptr) (int, error) {
	if addr == 0 {
		return 0, syscall.EINVAL
	}
	var jmp Reg
	err := tracer.GetRegisters(&jmp)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	backup := jmp
	jmp.Rip = int64(addr)
	_set_args(&jmp, a, b, c, d, e, f)
	return tracer.startCall(&backup, &jmp)
}

func (tracer *Tracer) startCall(backup *Reg, jmp *Reg) (int, error) {
	if tracer.libkernelBase == 0 {
		proc := GetProc(tracer.pid)
		if proc == 0 {
			return 0, errors.New("failed to get traced proc")
		}
		lib := proc.GetLib(LIBKERNEL_HANDLE)
		if lib == 0 {
			return 0, errors.New("failed to get libkernel for traced proc")
		}
		tracer.libkernelBase = lib.GetImageBase()
		if tracer.libkernelBase == 0 {
			return 0, errors.New("failed to get libkernel base for traced proc")
		}
	}

	jmp.Rsp = jmp.Rsp - 8

	err := tracer.SetRegisters(jmp)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	// set the return address to the `INT3` at the start of libkernel
	err = UserlandWrite64(tracer.pid, uintptr(jmp.Rsp), uint64(tracer.libkernelBase))
	if err != nil {
		log.Println(err)
		return 0, err
	}

	// call the function
	err = tracer.Continue()
	if err != nil {
		log.Println(err)
		return 0, err
	}

	state, err := tracer.Wait(0)

	if !state.Stopped() {
		log.Println(ErrProcessNotStopped)
		return 0, ErrProcessNotStopped
	}

	if state.StopSignal() != syscall.SIGTRAP {
		err = fmt.Errorf("process received signal %s but SIGTRAP was expected\n", state.StopSignal().String())
		log.Println(err)
		return 0, err
	}

	err = tracer.GetRegisters(jmp)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	// restore registers
	err = tracer.SetRegisters(backup)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	return int(jmp.Rax), nil
}

var (
	ErrNoProc       = errors.New("failed to get traced proc")
	ErrNoSyscall    = errors.New("failed to get syscall address for traced proc")
	ErrGetRegisters = errors.New("failed to get registers")
	ErrSetRegisters = errors.New("failed to set registers")
	ErrStep         = errors.New("failed to step traced proc")
	ErrNoErrno      = errors.New("failed to get errno address for traced proc")
)

func (tracer *Tracer) startSyscall(backup *Reg, jmp *Reg) (int, error) {
	if tracer.syscallAddr == 0 {
		proc := GetProc(tracer.pid)
		if proc == 0 {
			return 0, ErrNoProc
		}
		lib := proc.GetLib(LIBKERNEL_HANDLE)
		if lib == 0 {
			return 0, ErrNoLibKernel
		}
		addr := lib.GetAddress(_GET_AUTHINFO_NID)
		if addr == 0 {
			return 0, ErrNoSyscall
		}
		tracer.syscallAddr = addr + _SYSCALL_OFFSET
	}

	jmp.Rip = int64(tracer.syscallAddr)

	err := tracer.SetRegisters(jmp)

	if err != nil {
		log.Println(err)
		return 0, errors.Join(ErrSetRegisters, err)
	}

	// execute the syscall instruction
	err = tracer.Step()
	if err != nil {
		log.Println(err)
		err2 := tracer.SetRegisters(backup)
		if err2 != nil {
			log.Println(err2)
			err = errors.Join(err2)
		}
		return 0, errors.Join(ErrStep, err)
	}

	err = tracer.GetRegisters(jmp)

	if err != nil {
		log.Println(err)
		return 0, errors.Join(ErrGetRegisters, err)
	}

	var errno syscall.Errno
	if jmp.Carry() {
		errno = syscall.Errno(jmp.Rax)
	}

	// restore registers
	err = tracer.SetRegisters(backup)
	if err != nil {
		log.Println(err)
		return 0, errors.Join(ErrSetRegisters, err)
	}

	if errno != 0 {
		err = errno
	}

	return int(jmp.Rax), err
}

func (tracer *Tracer) Syscall(num int, a, b, c, d, e, f uintptr) (int, error) {
	var jmp Reg
	err := tracer.GetRegisters(&jmp)
	if err != nil {
		log.Println(err)
		return 0, errors.Join(ErrGetRegisters, err)
	}

	backup := jmp
	_set_args(&jmp, a, b, c, d, e, f)
	jmp.Rax = int64(num)
	jmp.R10 = jmp.Rcx
	return tracer.startSyscall(&backup, &jmp)
}

func (tracer *Tracer) Errno() error {
	if tracer.errno_addr == 0 {
		proc := GetProc(tracer.pid)
		if proc == 0 {
			log.Println(ErrNoProc)
			return ErrNoProc
		}
		lib := proc.GetLib(LIBKERNEL_HANDLE)
		if lib == 0 {
			log.Println(ErrNoLibKernel)
			return ErrNoLibKernel
		}
		addr := lib.GetAddress(_ERRNO_NID)
		if addr == 0 {
			log.Println(ErrNoErrno)
			return ErrNoErrno
		}
		tracer.errno_addr = addr
	}
	p_errno, _ := UserlandRead64(tracer.pid, tracer.errno_addr)

	err, _ := UserlandRead32(tracer.pid, uintptr(p_errno))
	return syscall.Errno(err)
}

func (tracer *Tracer) Perror(msg string) {
	err := tracer.Errno()
	if err != nil {
		log.Printf("%s: %s\n", msg, err.Error())
	}
}

func (tracer *Tracer) Pipe() (filedes [2]int, err error) {
	filedes = [2]int{-1, -1}

	var jmp Reg
	err = tracer.GetRegisters(&jmp)
	if err != nil {
		return
	}
	backup := jmp

	rsp := jmp.Rsp - 16
	jmp.Rax = syscall.SYS_PIPE2
	jmp.Rdi = rsp
	jmp.Rsi = 0
	_, err = tracer.startSyscall(&backup, &jmp)
	if err != nil {
		return
	}

	buf := make([]byte, 8)
	_, err = UserlandCopyout(tracer.pid, uintptr(rsp), buf)
	if err != nil {
		return
	}

	filedes[0] = int(binary.LittleEndian.Uint32(buf))
	filedes[1] = int(binary.LittleEndian.Uint32(buf[4:]))
	return
}

func (tracer *Tracer) Setsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen int) error {
	var jmp Reg
	err := tracer.GetRegisters(&jmp)
	if err != nil {
		return err
	}

	backup := jmp
	rsp := jmp.Rsp - int64(optlen)
	jmp.Rax = syscall.SYS_SETSOCKOPT
	jmp.Rsp = rsp
	jmp.Rdi = int64(s)
	jmp.Rsi = int64(level)
	jmp.Rdx = int64(optname)
	jmp.R10 = rsp
	jmp.R8 = int64(optlen)
	UserlandCopyinUnsafe(tracer.pid, uintptr(rsp), optval, optlen)
	_, err = tracer.startSyscall(&backup, &jmp)
	return err
}

func (tracer *Tracer) JitshmCreate(name uintptr, size uint64, flags int32) (int, error) {
	return tracer.Syscall(syscall.SYS_JITSHM_CREATE, name, uintptr(size), uintptr(flags), 0, 0, 0)
}

func (tracer *Tracer) JitshmAlias(fd int, flags int32) (int, error) {
	return tracer.Syscall(syscall.SYS_JITSHM_ALIAS, uintptr(fd), uintptr(flags), 0, 0, 0, 0)
}

func (tracer *Tracer) Mmap(addr uintptr, len uint64, prot int32, flags int32, fd int, off int) (int, error) {
	return tracer.Syscall(syscall.SYS_MMAP, addr, uintptr(len), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(off))
}

func (tracer *Tracer) Munmap(addr uintptr, len uint64) (int, error) {
	return tracer.Syscall(syscall.SYS_MUNMAP, addr, uintptr(len), 0, 0, 0, 0)
}

func (tracer *Tracer) Mprotect(addr uintptr, len uint64, prot int32) (int, error) {
	return tracer.Syscall(syscall.SYS_MPROTECT, addr, uintptr(len), uintptr(prot), 0, 0, 0)
}

func (tracer *Tracer) Close(fd int) (int, error) {
	return tracer.Syscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0, 0, 0, 0)
}

func (tracer *Tracer) Socket(domain int, socktype int, protocol int) (int, error) {
	return tracer.Syscall(syscall.SYS_SOCKET, uintptr(domain), uintptr(socktype), uintptr(protocol), 0, 0, 0)
}

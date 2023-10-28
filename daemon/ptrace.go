package main

import (
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

type Tracer struct {
	syscall_addr   uintptr
	libkernel_base uintptr
	errno_addr     uintptr
	pid            int
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

var UnexpectedProcessStatusError error = fmt.Errorf("Unexpected process status")

func NewTracer(pid int) (*Tracer, error) {
	tracer := &Tracer{
		syscall_addr:   0,
		libkernel_base: 0,
		errno_addr:     0,
		pid:            pid,
	}

	err := tracer.ptrace(PT_ATTACH, 0, 0)
	if err != nil {
		log.Print(err)
		return nil, err
	}
	status, err := tracer.wait(0)
	if !status.Stopped() {
		return nil, UnexpectedProcessStatusError
	}
	return tracer, nil
}

func (tracer *Tracer) Close() error {
	var err error
	if tracer.pid != 0 {
		err = tracer.ptrace(PT_DETACH, 0, 0)
		tracer.pid = 0
	}
	return err
}

func (tracer *Tracer) Detach() error {
	return tracer.Close()
}

func (tracer *Tracer) ptrace(request int, addr uintptr, data int) (err error) {
	callback := func() {
		_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, uintptr(request), uintptr(tracer.pid), uintptr(addr), uintptr(data), 0, 0)
	}
	GetCurrentUcred().RunWithAuthId(PTRACE_ID, callback)
	return
}

func waitpid(pid int, wstatus *syscall.WaitStatus, options int) (wpid int, err error) {
	wpid, err = syscall.Wait4(pid, wstatus, options, nil)
	return
}

func (tracer *Tracer) wait(options int) (syscall.WaitStatus, error) {
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
		log.Print(err)
		return err
	}
	status, err := tracer.wait(0)
	if err != nil {
		log.Print(err)
		return err
	}
	if !status.Stopped() {
		return UnexpectedProcessStatusError
	}
	return nil
}

func (tracer *Tracer) Continue() error {
	err := tracer.ptrace(PT_CONTINUE, 1, 0)
	if err != nil {
		log.Print(err)
		return err
	}
	return nil
}

func (tracer *Tracer) Kill(wait bool) error {
	err := tracer.ptrace(PT_KILL, 0, 0)
	if err != nil {
		log.Print(err)
		return err
	}
	if !wait {
		return nil
	}

	state, err := tracer.wait(0)
	if err != nil {
		log.Print(err)
		return err
	}

	if !state.Exited() {
		return UnexpectedProcessStatusError
	}
	return nil
}

func (regs *Reg) Dump(w io.Writer) {
	fmt.Fprintf(w, "rax: %#08x\n", regs.Rax)
	fmt.Fprintf(w, "rbx: %#08x\n", regs.Rbx)
	fmt.Fprintf(w, "rcx: %#08x\n", regs.Rcx)
	fmt.Fprintf(w, "rdx: %#08x\n", regs.Rdx)
	fmt.Fprintf(w, "rsi: %#08x\n", regs.Rsi)
	fmt.Fprintf(w, "rdi: %#08x\n", regs.Rdi)
	fmt.Fprintf(w, "r8:  %#08x\n", regs.R8)
	fmt.Fprintf(w, "r9:  %#08x\n", regs.R9)
	fmt.Fprintf(w, "r10: %#08x\n", regs.R10)
	fmt.Fprintf(w, "r11: %#08x\n", regs.R11)
	fmt.Fprintf(w, "r12: %#08x\n", regs.R12)
	fmt.Fprintf(w, "r13: %#08x\n", regs.R13)
	fmt.Fprintf(w, "r14: %#08x\n", regs.R14)
	fmt.Fprintf(w, "r15: %#08x\n", regs.R15)
	fmt.Fprintf(w, "rbp: %#08x\n", regs.Rbp)
	fmt.Fprintf(w, "rsp: %#08x\n", regs.Rsp)
	fmt.Fprintf(w, "rip: %#08x\n", regs.Rip)
}

func _set_args(regs *Reg, a, b, c, d, e, f uintptr) {
	regs.Rdi = int64(a)
	regs.Rsi = int64(b)
	regs.Rdx = int64(c)
	regs.Rcx = int64(d)
	regs.R8 = int64(e)
	regs.R9 = int64(f)
}

func (tracer *Tracer) call(addr uintptr, a, b, c, d, e, f uintptr) (int, error) {
	if addr == 0 {
		return 0, syscall.EINVAL
	}
	var jmp Reg
	err := tracer.GetRegisters(&jmp)
	if err != nil {
		log.Print(err)
		return 0, err
	}

	backup := jmp
	jmp.Rip = int64(addr)
	_set_args(&jmp, a, b, c, d, e, f)
	return tracer.startCall(&backup, &jmp)
}

func (tracer *Tracer) startCall(backup *Reg, jmp *Reg) (int, error) {
	if tracer.libkernel_base == 0 {
		proc := GetProc(tracer.pid)
		if proc == 0 {
			return 0, errors.New("failed to get traced proc")
		}
		lib := proc.GetLib(LIBKERNEL_HANDLE)
		if lib == 0 {
			return 0, errors.New("failed to get libkernel for traced proc")
		}
		tracer.libkernel_base = lib.GetImageBase()
		if tracer.libkernel_base == 0 {
			return 0, errors.New("failed to get libkernel base for traced proc")
		}
	}

	jmp.Rsp = jmp.Rsp - 8

	err := tracer.SetRegisters(jmp)
	if err != nil {
		log.Print(err)
		return 0, err
	}

	// set the return address to the `INT3` at the start of libkernel
	UserlandWrite64(tracer.pid, tracer.libkernel_base, uint64(jmp.Rsp))

	// call the function
	err = tracer.Continue()
	if err != nil {
		log.Print(err)
		return 0, err
	}

	state, err := tracer.wait(0)

	if !state.Stopped() {
		return 0, errors.New("process not stopped")
	}

	if state.Signal() != syscall.SIGTRAP {
		return 0, fmt.Errorf("process received signal %s but SIGTRAP was expected\n", state.Signal().String())
	}

	err = tracer.GetRegisters(jmp)
	if err != nil {
		log.Print(err)
		return 0, err
	}

	// restore registers
	err = tracer.SetRegisters(backup)
	if err != nil {
		log.Print(err)
		return 0, err
	}

	return int(jmp.Rax), nil
}

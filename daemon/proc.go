package main

import (
	"sync"
	"syscall"
)

const (
	_PROC_UCRED_OFFSET         = 0x40
	_PROC_PID_OFFSET           = 0xbc
	_PROC_FD_OFFSET            = 0x48
	_PROC_SHARED_OBJECT_OFFSET = 0x3e8
	_PROC_SELFINFO_NAME_OFFSET = 0x59C
	_PROC_SELFINFO_NAME_SIZE   = 32

	_FD_RDIR_OFFSET = 0x10
	_FD_JDIR_OFFSET = 0x18
)

type KProc uintptr
type KFd uintptr

var (
	_currentProc    KProc = 0
	_getCurrentProc       = sync.OnceValue(func() KProc { return GetProc(syscall.Getpid()) })
)

func _getFirstProc() KProc {
	return KProc(kread64(GetKernelBase() + GetAllprocOffset()))
}

func (proc KProc) next() KProc {
	return KProc(kread64(proc))
}

func GetProc(pid int) KProc {
	for proc := _getFirstProc(); proc != 0; proc = proc.next() {
		currentPid := proc.GetPid()
		if pid == currentPid {
			return proc
		}
	}
	return 0
}

func GetCurrentProc() KProc {
	return _getCurrentProc()
}

func (proc KProc) GetUcred() KUcred {
	return KUcred(kread64(proc + _PROC_UCRED_OFFSET))
}

func (proc KProc) GetPid() int {
	return int(kread32(proc + _PROC_PID_OFFSET))
}

func (proc KProc) GetFd() KFd {
	return KFd(kread64(proc + _PROC_FD_OFFSET))
}

func (fd KFd) GetRdir() uint64 {
	return kread64(fd + _FD_RDIR_OFFSET)
}

func (fd KFd) GetJdir() uint64 {
	return kread64(fd + _FD_JDIR_OFFSET)
}

func (fd KFd) SetRdir(value uint64) {
	kwrite64(fd+_FD_RDIR_OFFSET, value)
}

func (fd KFd) SetJdir(value uint64) {
	kwrite64(fd+_FD_JDIR_OFFSET, value)
}

func (proc KProc) Jailbreak(escapeSandbox bool) {
	ucred := proc.GetUcred()
	fd := proc.GetFd()
	kernel_base := GetKernelBase()
	root := kread64(kernel_base + GetRootVnodeOffset())

	attr_store := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}

	ucred.SetUid(0)
	ucred.SetRuid(0)
	ucred.SetSvuid(0)
	ucred.SetNgroups(0)
	ucred.SetRgid(0)

	if escapeSandbox {
		fd.SetRdir(root)
		fd.SetJdir(root)
	}

	// Escalate sony privileges
	ucred.SetAuthId(JAILBREAK_AUTHID)
	ucred.SetSceCaps(^uint64(0), ^uint64(0))
	KernelCopyin(ucred+0x83, attr_store[0:1]) // cr_sceAttr[0]
}

func (proc KProc) GetSharedObject() SharedObject {
	return SharedObject(kread64(proc + _PROC_SHARED_OBJECT_OFFSET))
}

func (proc KProc) GetLib(handle int) SharedLib {
	obj := proc.GetSharedObject()
	if obj == 0 {
		return 0
	}
	return obj.GetLib(handle)
}

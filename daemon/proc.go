package main

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	_PROC_UCRED_OFFSET         = 0x40
	_PROC_PID_OFFSET           = 0xbc
	_PROC_FD_OFFSET            = 0x48
	_PROC_SHARED_OBJECT_OFFSET = 0x3e8
	_PROC_SELFINFO_NAME_OFFSET = 0x59C
	_PROC_SELFINFO_NAME_SIZE   = 32
	_PROC_ORPHAN_OFFSET        = 0xbb0
	_PROC_ORPHANS_OFFSET       = 0xbc0
	P_TREE_ORPHANED            = 1
	P_TREE_FIRST_ORPHAN        = 2
	P_TREE_REAPER              = 4

	_FD_RDIR_OFFSET = 0x10
	_FD_JDIR_OFFSET = 0x18

	_FILEDESCENT_LENGTH = 0x30
)

type KProc uintptr
type KFd uintptr
type KFdTbl uintptr

type KProcOrphanList uintptr

func (pl KProcOrphanList) Next() KProc {
	return KProc(kread64(uintptr(pl)))
}

func (pl KProcOrphanList) Prev() uintptr {
	return uintptr(kread64(uintptr(pl) + 8))
}

func (p KProc) GetTreeFlag() uint32 {
	return kread32(uintptr(p) + 0x3c8)
}

func (p KProc) SetTreeFlag(flag uint32) {
	kwrite32(uintptr(p)+0x3c8, flag)
}

func (p KProc) GetFlag() uint32 {
	return kread32(uintptr(p) + 0xb0)
}

func (p KProc) SetFlag(flag uint32) {
	kwrite32(uintptr(p)+0xb0, flag)
}

func (p KProc) IsOrphan() bool {
	return (p.GetTreeFlag() & P_TREE_ORPHANED) != 0
}

func (p KProc) IsFirstOrphan() bool {
	return (p.GetTreeFlag() & P_TREE_FIRST_ORPHAN) != 0
}

func (p KProc) GetOriginalParentPid() int {
	return int(kread32(uintptr(p) + 0x1f8))
}

func (p KProc) SetOriginalParentPid(pid uint32) {
	kwrite32(uintptr(p)+0x1f8, pid)
}

func (p KProc) SetParentPtr(parent KProc) {
	kwrite64(uintptr(p)+0xe0, uint64(parent))
}

func (p KProc) SetStops(stops uint32) {
	kwrite32(uintptr(p)+0x378, stops)
}

func (p KProc) IsReaper() bool {
	return (p.GetTreeFlag() & P_TREE_REAPER) != 0
}

func (p KProc) GetParent() KProc {
	return KProc(kread64(uintptr(p) + 0xe0))
}

func (p KProc) GetOrphan() (orphan KProcOrphanList) {
	const size int = int(unsafe.Sizeof(orphan))
	_, err := KernelCopyoutUnsafe(uintptr(p)+_PROC_ORPHAN_OFFSET, unsafe.Pointer(&orphan), size)
	if err != nil {
		log.Println(err)
	}
	return
}

func (child KProc) GetRealParent() KProc {
	if child.IsOrphan() {
		log.Println("kernel proc is an orphan")
		oppid := child.GetOriginalParentPid()
		pptr := child.GetParent()
		if oppid == 0 || oppid == pptr.GetPid() {
			return pptr
		}
		return 0
	}

	p := child
	for !p.IsFirstOrphan() {
		// load the first member, subtract offset of third member
		// p = __containerof(p->p_orphan.le_prev, struct proc, p_orphan.le_next);
		/*prev := (p + _PROC_ORPHAN_OFFSET + 8)
		p = KProc( - _PROC_ORPHAN_OFFSET)
		log.Printf("p: %#08x\n", p)
		if p.IsOrphan() {
			log.Println("missing orphan")
			return 0
		}*/
	}
	return KProc(p.GetOrphan().Prev() - _PROC_ORPHANS_OFFSET)
}

var (
	_currentProc KProc = GetProc(syscall.Getpid())
)

func GetSyscoreProc() KProc {
	return GetProc(syscall.Getppid())
}

func _getFirstProc() KProc {
	return KProc(kread64(GetKernelBase() + GetAllprocOffset()))
}

func (proc KProc) next() KProc {
	return KProc(kread64(uintptr(proc)))
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
	return _currentProc
}

func (proc KProc) GetUcred() KUcred {
	return KUcred(kread64(uintptr(proc) + _PROC_UCRED_OFFSET))
}

func (proc KProc) GetPid() int {
	return int(kread32(uintptr(proc) + _PROC_PID_OFFSET))
}

func (proc KProc) GetFd() KFd {
	return KFd(kread64(uintptr(proc) + _PROC_FD_OFFSET))
}

func (fd KFd) GetFdTbl() KFdTbl {
	return KFdTbl(kread64(uintptr(fd)))
}

func (fd KFd) GetRdir() uint64 {
	return kread64(uintptr(fd) + _FD_RDIR_OFFSET)
}

func (fd KFd) GetJdir() uint64 {
	return kread64(uintptr(fd) + _FD_JDIR_OFFSET)
}

func (fd KFd) SetRdir(value uint64) {
	kwrite64(uintptr(fd)+_FD_RDIR_OFFSET, value)
}

func (fd KFd) SetJdir(value uint64) {
	kwrite64(uintptr(fd)+_FD_JDIR_OFFSET, value)
}

func (tbl KFdTbl) GetFile(fd int) uintptr {
	fp := uintptr(tbl) + (uintptr(fd) * _FILEDESCENT_LENGTH) + 8
	return uintptr(kread64(fp))
}

func (tbl KFdTbl) GetFileData(fd int) uint64 {
	return kread64(tbl.GetFile(fd))
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
	KernelCopyin(uintptr(ucred)+0x83, attr_store[0:1]) // cr_sceAttr[0]
}

func (proc KProc) GetSharedObject() SharedObject {
	return SharedObject(kread64(uintptr(proc) + _PROC_SHARED_OBJECT_OFFSET))
}

func (proc KProc) GetLib(handle int) SharedLib {
	obj := proc.GetSharedObject()
	if obj == 0 {
		return 0
	}
	return obj.GetLib(handle)
}

func (proc KProc) GetEboot() SharedLib {
	return proc.GetLib(0)
}

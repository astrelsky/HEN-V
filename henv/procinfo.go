package henv

import (
	"bytes"
	"errors"
	"sync"
	"unsafe"
)

type ProcessInfo struct {
	Pid  int
	Name string
	Path string
}

type procInfoListArg struct {
	buf    uintptr
	length uint64
	_      [0x30]byte
}

type procInfoArg struct {
	pid    int32
	buf    uintptr
	length uint64
	_      [0x28]byte
}

type rawProcInfo struct {
	_    [0x18]byte
	name [0x20]byte
	path [0x400]byte
	_    [0xe4]byte
}

var (
	pidBuffer [10000]int32
	pidBufMtx sync.Mutex
)

func GetPids() (pids []int32, err error) {
	pidBufMtx.Lock()
	defer pidBufMtx.Unlock()
	arg1 := dbgArg1{
		argtype: _DBG_ARG_DEFAULT_TYPE,
		cmd:     _DBG_PROCESS_LIST_CMD,
	}
	arg2 := procInfoListArg{
		buf:    uintptr(unsafe.Pointer(&pidBuffer[0])),
		length: uint64(len(pidBuffer)),
	}
	arg3 := dbgArg3{}

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1)), uintptr(unsafe.Pointer(&arg2)), uintptr(unsafe.Pointer(&arg3)))
	if err != nil {
		return
	}
	pids = make([]int32, int(arg3.length))
	copy(pids, pidBuffer[:])
	return
}

func (info *rawProcInfo) getName() string {
	index := bytes.IndexByte(info.name[:], 0)
	if index == -1 {
		return string(info.name[:])
	}
	return string(info.name[:index])
}

func (info *rawProcInfo) getPath() string {
	index := bytes.IndexByte(info.path[:], 0)
	if index == -1 {
		return string(info.path[:])
	}
	return string(info.path[:index])
}

func GetProcessInfo(pid int) (info ProcessInfo, err error) {
	arg1 := dbgArg1{
		argtype: _DBG_ARG_DEFAULT_TYPE,
		cmd:     _DBG_PROCESS_INFO_CMD,
	}
	rawinfo := rawProcInfo{}
	const length = uint64(unsafe.Sizeof(rawinfo))
	arg2 := procInfoArg{
		pid:    int32(pid),
		buf:    uintptr(unsafe.Pointer(&rawinfo)),
		length: length,
	}
	arg3 := dbgArg3{}

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1)), uintptr(unsafe.Pointer(&arg2)), uintptr(unsafe.Pointer(&arg3)))
	if err != nil {
		return
	}
	info = ProcessInfo{
		Pid:  pid,
		Name: rawinfo.getName(),
		Path: rawinfo.getPath(),
	}
	return
}

func GetProcesses() (infos []ProcessInfo, err error) {
	pids, err := GetPids()
	if err != nil {
		return
	}
	infos = make([]ProcessInfo, len(pids))
	for i := range infos {
		info, err2 := GetProcessInfo(int(pids[i]))
		err = errors.Join(err, err2)
		infos[i] = info
	}
	return
}

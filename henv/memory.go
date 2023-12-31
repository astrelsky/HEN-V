package henv

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	_DBG_ARG1_FULL_SIZE = 0x20
	_DBG_ARG2_FULL_SIZE = 0x40
	_DBG_ARG3_FULL_SIZE = 0x20

	_DBG_ARG_DEFAULT_TYPE uint32 = 1
	_DBG_CMD_READ         uint64 = 0x12
	_DBG_CMD_WRITE        uint64 = 0x13
	_DBG_PROCESS_LIST_CMD uint64 = 0x14
	_DBG_PROCESS_INFO_CMD uint64 = 0x18
)

type dbgArg1 struct {
	argtype uint32
	_       uint32
	cmd     uint64
	_       [0x10]byte
}

type dbgArg2 struct {
	pid    uint32
	src    uintptr
	dst    uintptr
	length uint64
	_      [0x20]byte
}

type dbgArg3 struct {
	_      int64
	length uint64
	_      [0x10]byte
}

//go:uintptrescapes
func _mdbg_call(arg1 uintptr, arg2 uintptr, arg3 uintptr) (err error) {
	callback := func() {
		_, _, errno := syscall.Syscall(syscall.SYS_MDBG_CALL, arg1, arg2, arg3)
		if errno != 0 {
			err = errno
		}
	}
	RunWithCurrentAuthId(DEBUGGER_AUTHID, callback)
	return
}

func UserlandWrite64(pid int, dst uintptr, value uint64) (err error) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	_, err = UserlandCopyin(pid, dst, buf)
	return
}

func UserlandWrite32(pid int, dst uintptr, value uint32) (err error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	_, err = UserlandCopyin(pid, dst, buf)
	return
}

func UserlandWrite8(pid int, dst uintptr, value uint8) (err error) {
	_, err = UserlandCopyinUnsafe(pid, dst, unsafe.Pointer(&value), 1)
	return
}

func UserlandRead64(pid int, src uintptr) (res uint64, err error) {
	buf := make([]byte, 8)
	_, err = UserlandCopyout(pid, src, buf)
	res = binary.LittleEndian.Uint64(buf)
	return
}

func UserlandRead32(pid int, src uintptr) (res uint32, err error) {
	buf := make([]byte, 4)
	_, err = UserlandCopyout(pid, src, buf)
	res = binary.LittleEndian.Uint32(buf)
	return
}

func UserlandCopyinUnsafe(pid int, dst uintptr, src unsafe.Pointer, length int) (n int, err error) {
	arg1 := dbgArg1{
		argtype: _DBG_ARG_DEFAULT_TYPE,
		cmd:     _DBG_CMD_WRITE,
	}
	arg2 := dbgArg2{
		pid:    uint32(pid),
		src:    dst,
		dst:    uintptr(src),
		length: uint64(length),
	}
	arg3 := dbgArg3{}

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1)), uintptr(unsafe.Pointer(&arg2)), uintptr(unsafe.Pointer(&arg3)))
	n = int(arg3.length)
	runtime.KeepAlive(src)
	return
}

func UserlandCopyin(pid int, dst uintptr, src []byte) (n int, err error) {
	return UserlandCopyinUnsafe(pid, dst, unsafe.Pointer(&src[0]), len(src))
}

func UserlandCopyoutUnsafe(pid int, src uintptr, dst unsafe.Pointer, length int) (n int, err error) {
	arg1 := dbgArg1{
		argtype: _DBG_ARG_DEFAULT_TYPE,
		cmd:     _DBG_CMD_READ,
	}
	arg2 := dbgArg2{
		pid:    uint32(pid),
		src:    src,
		dst:    uintptr(dst),
		length: uint64(length),
	}
	arg3 := dbgArg3{}

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1)), uintptr(unsafe.Pointer(&arg2)), uintptr(unsafe.Pointer(&arg3)))
	n = int(arg3.length)
	runtime.KeepAlive(dst)
	return
}

func UserlandCopyout(pid int, src uintptr, dst []byte) (n int, err error) {
	return UserlandCopyoutUnsafe(pid, src, unsafe.Pointer(&dst[0]), len(dst))
}

package main

import (
	"encoding/binary"
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
)

//go:uintptrescapes
func _mdbg_call(arg1 uintptr, arg2 uintptr, arg3 uintptr) (err error) {
	callback := func() {
		_, _, err = syscall.Syscall(syscall.SYS_MDBG_CALL, arg1, arg2, arg3)
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

func UserlandCopyin(pid int, dst uintptr, src []byte) (n int, err error) {
	arg1 := make([]byte, _DBG_ARG1_FULL_SIZE)
	arg2 := make([]byte, _DBG_ARG2_FULL_SIZE)
	arg3 := make([]byte, _DBG_ARG3_FULL_SIZE)

	binary.LittleEndian.PutUint32(arg1[0x0:], _DBG_ARG_DEFAULT_TYPE)
	binary.LittleEndian.PutUint64(arg1[0x8:], _DBG_CMD_WRITE)

	binary.LittleEndian.PutUint32(arg2[0x0:], uint32(pid))
	binary.LittleEndian.PutUint64(arg2[0x8:], uint64(dst))
	binary.LittleEndian.PutUint64(arg2[0x10:], uint64(uintptr(unsafe.Pointer(&src[0]))))
	binary.LittleEndian.PutUint64(arg2[0x18:], uint64(len(src)))

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1[0])), uintptr(unsafe.Pointer(&arg2[0])), uintptr(unsafe.Pointer(&arg3[0])))
	n = int(binary.LittleEndian.Uint64(arg3[8:]))
	return
}

func UserlandCopyout(pid int, src uintptr, dst []byte) (n int, err error) {
	arg1 := make([]byte, _DBG_ARG1_FULL_SIZE)
	arg2 := make([]byte, _DBG_ARG2_FULL_SIZE)
	arg3 := make([]byte, _DBG_ARG3_FULL_SIZE)

	binary.LittleEndian.PutUint32(arg1[0x0:], _DBG_ARG_DEFAULT_TYPE)
	binary.LittleEndian.PutUint64(arg1[0x8:], _DBG_CMD_READ)

	binary.LittleEndian.PutUint32(arg2[0x0:], uint32(pid))
	binary.LittleEndian.PutUint64(arg2[0x8:], uint64(src))
	binary.LittleEndian.PutUint64(arg2[0x10:], uint64(uintptr(unsafe.Pointer(&dst[0]))))
	binary.LittleEndian.PutUint64(arg2[0x18:], uint64(len(dst)))

	err = _mdbg_call(uintptr(unsafe.Pointer(&arg1[0])), uintptr(unsafe.Pointer(&arg2[0])), uintptr(unsafe.Pointer(&arg3[0])))
	n = int(binary.LittleEndian.Uint64(arg3[8:]))
	return
}

package main

import (
	"bytes"
	"log"
	"slices"
	"syscall"
	"unsafe"
)

const (
	_MAX_HANDLES            = 0x300
	_MAX_MODULE_NAME_LENGTH = 128
)

type DynlibModuleSection = syscall.ModuleSection

type DynlibModuleInfo struct {
	filename       [_MAX_MODULE_NAME_LENGTH]byte
	handle         uint64
	_              [32]byte
	_              uintptr // init
	_              uintptr // fini
	_              uintptr // eh_frame_hdr
	_              uintptr // eh_frame_hdr_sz
	_              uintptr // eh_frame
	_              uintptr // eh_frame_sz
	sections       [4]DynlibModuleSection
	_              [1176]byte
	fingerprint    [20]byte
	_              uint32
	libname        [_MAX_MODULE_NAME_LENGTH]byte
	_              uint32
	sandboxed_path [1024]byte
	sdk_version    uint64
}

func (info *DynlibModuleInfo) Name() string {
	index := bytes.IndexByte(info.filename[:], 0)
	if index == -1 {
		index = _MAX_MODULE_NAME_LENGTH
	}
	return string(info.filename[:index])
}

//go:uintptrescapes
func _sysDlGetList(pid int, handles uintptr, maxHandles uint, numHandles uintptr) (err error) {
	callback := func() {
		_, _, errno := syscall.Syscall6(syscall.SYS_DL_GET_LIST, uintptr(pid), handles, uintptr(maxHandles), numHandles, 0, 0)
		if errno != 0 {
			err = errno
		}
	}
	RunWithCurrentAuthId(DEBUGGER_AUTHID, callback)
	return
}

func GetModuleHandles(pid int) []int {
	// nobody will have that many handles
	handles := make([]int, _MAX_HANDLES)

	var numHandles uint32
	err := _sysDlGetList(pid, uintptr(unsafe.Pointer(&handles[0])), _MAX_HANDLES, uintptr(unsafe.Pointer(&numHandles)))
	if err != nil {
		log.Println(err)
		return []int{}
	}
	return slices.Clip(handles[:numHandles])
}

//go:uintptrescapes
func _sysDlGetInfo2(pid int, sandboxedPath uint, handle int, info uintptr) (err error) {
	callback := func() {
		_, _, errno := syscall.Syscall6(syscall.SYS_DL_GET_INFO_2, uintptr(pid), uintptr(sandboxedPath), uintptr(handle), info, 0, 0)
		if errno != 0 {
			err = errno
		}
	}
	RunWithCurrentAuthId(DEBUGGER_AUTHID, callback)
	return
}

func GetModuleInfo(pid int, handle int, info *DynlibModuleInfo) error {
	info.handle = 0 // forces a NPE instead of it crashing in the syscall
	return _sysDlGetInfo2(pid, 1, handle, uintptr(unsafe.Pointer(info)))
}

func GetModuleHandle(pid int, name string) int {
	if len(name) > _MAX_MODULE_NAME_LENGTH {
		return -1
	}

	handles := GetModuleHandles(pid)
	if len(handles) == 0 {
		return -1
	}

	var info DynlibModuleInfo
	for i := range handles {
		err := GetModuleInfo(pid, handles[i], &info)
		if err != nil {
			log.Println(err)
			return -1
		}
		if info.Name() == name {
			return handles[i]
		}
	}
	return -1
}

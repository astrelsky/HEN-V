package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const TITLEID_LENGTH = 9

type AppStatus struct {
	id uint32
	_  [28]byte
}

type AppInfo struct {
	_       uint64
	_       uint64
	titleId [TITLEID_LENGTH]byte
	_       [0x3f]byte
}

func (info *AppInfo) TitleId() string {
	return string(info.titleId[:])
}

func GetAppInfo(pid int) (*AppInfo, error) {
	const MIB_LENGTH = 4
	const CTL_KERN = 1
	const KERN_PROC = 14
	const KERN_PROC_APPINFO = 35
	const APP_INFO_SIZE = unsafe.Sizeof(AppInfo{})
	mib := [MIB_LENGTH]int32{CTL_KERN, KERN_PROC, KERN_PROC_APPINFO, int32(pid)}
	info := &AppInfo{}
	var length uint64 = uint64(APP_INFO_SIZE)
	res, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		MIB_LENGTH,
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(&length)),
		0,
		0,
	)
	if errno != 0 {
		return info, fmt.Errorf("res: %v, err %s", int(res), errno)
	}
	return info, nil
}

func SystemServiceGetAppStatus() (*AppStatus, error) {
	status := &AppStatus{}
	res, _, _ := sceSystemServiceGetAppStatus.Call(uintptr(unsafe.Pointer(status)))
	if int(res) < 0 {
		return nil, fmt.Errorf("sceSystemServiceGetAppStatus failed: %v", int(res))
	}
	return status, nil
}

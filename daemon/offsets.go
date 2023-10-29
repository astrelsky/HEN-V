package main

import (
	"fmt"
	"syscall"
)

const (
	VERSION_MASK = 0xffff0000
	V300         = 0x3000000
	V310         = 0x3100000
	V320         = 0x3200000
	V321         = 0x3210000
	V400         = 0x4000000
	V402         = 0x4020000
	V403         = 0x4030000
	V450         = 0x4500000
	V451         = 0x4510000
)

var (
	_version       uint32  = 0
	_allprocOffset uintptr = 0
)

func GetSystemSoftwareVersion() uint32 {
	if _version != 0 {
		return _version
	}
	version, err := syscall.SysctlUint32("kern.sdk_version")
	if err != nil {
		panic("failed to get kernel.sdk_version")
	}
	_version = version
	return _version
}

func GetAllprocOffset() uintptr {
	if _allprocOffset != 0 {
		return _allprocOffset
	}

	version := GetSystemSoftwareVersion() & VERSION_MASK

	switch version {
	case V300:
		fallthrough
	case V310:
		fallthrough
	case V320:
		fallthrough
	case V321:
		_allprocOffset = 0x276DC58
	case V400:
		fallthrough
	case V402:
		fallthrough
	case V403:
		fallthrough
	case V450:
		fallthrough
	case V451:
		_allprocOffset = 0x27EDCB8
	default:
		panic(fmt.Errorf("unsupported kernel version %#08x", version))
	}

	return _allprocOffset
}

func GetSecurityFlagsOffset() uintptr {
	version := GetSystemSoftwareVersion() & VERSION_MASK
	switch version {
	case V300:
		fallthrough
	case V310:
		fallthrough
	case V320:
		fallthrough
	case V321:
		return 0x6466474
	case V400:
		return 0x6506474
	case V402:
		fallthrough
	case V403:
		fallthrough
	case V450:
		fallthrough
	case V451:
		return 0x6505474
	default:
		panic(fmt.Errorf("unsupported kernel version %#08x", version))
	}
}

func GetQaFlagsOffset() uintptr {
	version := GetSystemSoftwareVersion() & VERSION_MASK
	switch version {
	case V300:
		fallthrough
	case V310:
		fallthrough
	case V320:
		fallthrough
	case V321:
		return 0x6466498
	case V400:
		return 0x6506498
	case V402:
		return 0x6505498
	case V403:
		fallthrough
	case V450:
		fallthrough
	case V451:
		return 0x6506498
	default:
		panic(fmt.Errorf("unsupported kernel version %#08x", version))
	}
}

func GetUtokenFlagsOffset() uintptr {
	version := GetSystemSoftwareVersion() & VERSION_MASK
	switch version {
	case V300:
		fallthrough
	case V310:
		fallthrough
	case V320:
		fallthrough
	case V321:
		return 0x6466500
	case V400:
		return 0x6506500
	case V402:
		return 0x6505500
	case V403:
		fallthrough
	case V450:
		fallthrough
	case V451:
		return 0x6506500
	default:
		panic(fmt.Errorf("unsupported kernel version %#08x", version))
	}
}

func GetRootVnodeOffset() uintptr {
	version := GetSystemSoftwareVersion() & VERSION_MASK
	switch version {
	case V300:
		fallthrough
	case V310:
		fallthrough
	case V320:
		fallthrough
	case V321:
		return 0x67AB4C0
	case V400:
		return 0x66E74C0
	case V402:
		return 0x66E64C0
	case V403:
		fallthrough
	case V450:
		fallthrough
	case V451:
		return 0x66E74C0
	default:
		panic(fmt.Errorf("unsupported kernel version %#08x", version))
	}
}

package main

import (
	"encoding/binary"
	"runtime"
	"sync"
	"syscall"
)

type KernelAddress interface {
	~uintptr
}

var kmemMtx sync.Mutex

func KernelCopyout[T KernelAddress](ksrc T, p []byte) (n int, err error) {
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
	return syscall.KernelCopyout(uintptr(ksrc), p)
}

func kread64[T KernelAddress](ksrc T) uint64 {
	buf := make([]byte, 8)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint64(buf)
}

func kread32[T KernelAddress](ksrc T) uint32 {
	buf := make([]byte, 4)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint32(buf)
}

func kwrite64[T KernelAddress](ksrc T, value uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	KernelCopyin(ksrc, buf)
}

func kwrite32[T KernelAddress](ksrc T, value uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	KernelCopyin(ksrc, buf)
}

func KernelCopyin[T KernelAddress](kdest T, p []byte) (n int, err error) {
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
	return syscall.KernelCopyin(uintptr(kdest), p)
}

func GetKernelBase() uintptr {
	return runtime.GetKernelBase()
}

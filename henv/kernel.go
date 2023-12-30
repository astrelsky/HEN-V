package henv

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var kmemMtx sync.Mutex

func KernelCopyout(ksrc uintptr, p []byte) (n int, err error) {
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
	return syscall.KernelCopyout(uintptr(ksrc), p)
}

func Kread64(ksrc uintptr) uint64 {
	buf := make([]byte, 8)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint64(buf)
}

func Kread32(ksrc uintptr) uint32 {
	buf := make([]byte, 4)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint32(buf)
}

func Kwrite64(ksrc uintptr, value uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	KernelCopyin(ksrc, buf)
}

func Kwrite32(ksrc uintptr, value uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	KernelCopyin(ksrc, buf)
}

func KernelCopyin(kdest uintptr, p []byte) (n int, err error) {
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
	return syscall.KernelCopyin(uintptr(kdest), p)
}

func KernelCopyoutString(ksrc uintptr) (s string, err error) {
	const BUF_SIZE = 16
	buf := make([]byte, BUF_SIZE)
	pos := 0
	for err == nil {
		_, err = KernelCopyout(ksrc+uintptr(pos), buf[pos:])
		i := bytes.IndexByte(buf[pos:], 0)
		if i != -1 {
			s = string(buf[:pos+i])
			return
		}
		buf = append(buf, make([]byte, BUF_SIZE)...)
		pos += BUF_SIZE
	}
	return
}

func KernelCopyoutUnsafe(ksrc uintptr, dst unsafe.Pointer, length int) (int, error) {
	return KernelCopyout(ksrc, unsafe.Slice((*byte)(dst), length))
}

func GetKernelBase() uintptr {
	return runtime.GetKernelBase()
}

func (hen *HenV) KernelCopyout(ksrc uintptr, p []byte) (n int, err error) {
	hen.kmemMtx.Lock()
	defer hen.kmemMtx.Unlock()
	return syscall.KernelCopyout(uintptr(ksrc), p)
}

func (hen *HenV) Kread64(ksrc uintptr) uint64 {
	buf := make([]byte, 8)
	hen.KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint64(buf)
}

func (hen *HenV) Kread32(ksrc uintptr) uint32 {
	buf := make([]byte, 4)
	hen.KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint32(buf)
}

func (hen *HenV) Kwrite64(ksrc uintptr, value uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	hen.KernelCopyin(ksrc, buf)
}

func (hen *HenV) Kwrite32(ksrc uintptr, value uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	hen.KernelCopyin(ksrc, buf)
}

func (hen *HenV) KernelCopyin(kdest uintptr, p []byte) (n int, err error) {
	hen.kmemMtx.Lock()
	defer hen.kmemMtx.Unlock()
	return syscall.KernelCopyin(uintptr(kdest), p)
}

func (hen *HenV) KernelCopyoutString(ksrc uintptr) (s string, err error) {
	const BUF_SIZE = 16
	buf := make([]byte, BUF_SIZE)
	pos := 0
	for err == nil {
		_, err = hen.KernelCopyout(ksrc+uintptr(pos), buf[pos:])
		i := bytes.IndexByte(buf[pos:], 0)
		if i != -1 {
			s = string(buf[:pos+i])
			return
		}
		buf = append(buf, make([]byte, BUF_SIZE)...)
		pos += BUF_SIZE
	}
	return
}

func (hen *HenV) KernelCopyoutUnsafe(ksrc uintptr, dst unsafe.Pointer, length int) (int, error) {
	return hen.KernelCopyout(ksrc, unsafe.Slice((*byte)(dst), length))
}

package henv

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var kmemMtx *sync.Mutex

type KernelMemoryReader struct {
	Address uintptr
}

func KernelCopyout(ksrc uintptr, p []byte) (n int, err error) {
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
	return syscall.KernelCopyout(uintptr(ksrc), p)
}

func kread64(ksrc uintptr) uint64 {
	buf := make([]byte, 8)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint64(buf)
}

func kread32(ksrc uintptr) uint32 {
	buf := make([]byte, 4)
	KernelCopyout(ksrc, buf)
	return binary.LittleEndian.Uint32(buf)
}

func kwrite64(ksrc uintptr, value uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	KernelCopyin(ksrc, buf)
}

func kwrite32(ksrc uintptr, value uint32) {
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
	kmemMtx.Lock()
	defer kmemMtx.Unlock()
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
	panic("unreachable")
}

func KernelCopyoutUnsafe(ksrc uintptr, dst unsafe.Pointer, length int) (int, error) {
	return KernelCopyout(ksrc, unsafe.Slice((*byte)(dst), length))
}

func (r KernelMemoryReader) Read(p []byte) (n int, err error) {
	return KernelCopyout(r.Address, p)
}

// the same rules for binary.Read apply to the data parameter
func (r KernelMemoryReader) ReadStruct(data any) error {
	return binary.Read(r, binary.LittleEndian, data)
}

func GetKernelBase() uintptr {
	return runtime.GetKernelBase()
}

package henv

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"unsafe"
)

const PAYLOAD_EBOOT_PATH string = "/system/vsh/app/NPXS40112/eboot.bin"
const (
	_TRACE_OFFSET        = 0x34
	_TRACE_MAGIC  uint64 = 0xA845C748
	_TRACE_PATCH         = 0x90909090a8758948
)

var spawnProc = getSpawnProc()
var patchSpawn = sync.OnceFunc(spawnPatcher)

func getSpawnProc() *syscall.Proc {
	libkernel := syscall.Prx{Handle: LIBKERNEL_HANDLE}
	return libkernel.MustFindProc("sceKernelSpawn")
}

func spawnPatcher() {
	addr := spawnProc.Addr()
	pid := getpid()
	log.Printf("reading at addr: %#08x\n", addr+_TRACE_OFFSET)
	val, err := UserlandRead64(pid, addr+_TRACE_OFFSET)
	if err != nil {
		panic(err)
	}
	if val != _TRACE_MAGIC {
		panic(fmt.Errorf("expected %#08x in spawn but found %#08x", _TRACE_MAGIC, val))
	}
	err = UserlandWrite64(pid, addr, _TRACE_PATCH)
	if err != nil {
		panic(err)
	}
}

func spawn(ptrace bool, path string, root string, argv []string) (int, error) {
	patchSpawn()
	log.Println("spawning")
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		log.Println(err)
		return -1, err
	}
	var follow uintptr
	if ptrace {
		follow = 1
	}
	var croot *byte
	if root != "" {
		croot, err = syscall.BytePtrFromString(root)
		if err != nil {
			log.Println(err)
			return -1, err
		}
	}
	cargv, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		log.Println(err)
		return -1, err
	}
	// int sceKernelSpawn(int *pid,long dbg,char *path,char *root,char **argv)
	pid := int32(-1)
	res, _, _ := spawnProc.Call(
		uintptr(unsafe.Pointer(&pid)),
		follow,
		uintptr(unsafe.Pointer(cpath)),
		uintptr(unsafe.Pointer(croot)),
		uintptr(unsafe.Pointer(&cargv[0])),
	)
	if res != 0 {
		err = fmt.Errorf("sceKernelSpawn failed: %#08x", res)
		log.Println(err)
		return -1, err
	}
	return int(pid), nil
}

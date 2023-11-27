package main

import (
	"log"
	"syscall"
	"unsafe"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func enableVerboseSyscoreLogging() {
	syscore := GetSyscoreProc()
	if syscore == 0 {
		log.Println("failed to get syscore kernel process")
		return
	}
	eboot := syscore.GetEboot()
	if eboot == 0 {
		log.Println("failed to get syscore eboot")
		return
	}
	imagebase := eboot.GetImageBase()
	if imagebase == 0 {
		log.Println("failed to get syscore imagebase")
		return
	}
	err := UserlandWrite8(syscall.Getppid(), imagebase+0x684691, 1)
	if err != nil {
		log.Println("failed to enable syscore verbose logging")
	}
	err = UserlandWrite8(syscall.Getppid(), imagebase+0x684692, 1)
	if err != nil {
		log.Println("failed to enable syscore verbose logging")
	}
	err = UserlandWrite8(syscall.Getppid(), imagebase+0x684693, 1)
	if err != nil {
		log.Println("failed to enable syscore verbose logging")
	}
	err = UserlandWrite8(syscall.Getppid(), imagebase+0x684694, 1)
	if err != nil {
		log.Println("failed to enable syscore verbose logging")
	}
	err = UserlandWrite8(syscall.Getppid(), imagebase+0x684695, 0) // this one is a lock
	if err != nil {
		log.Println("failed to enable syscore verbose logging")
	}
}

func changeCoredumpMode() {
	prx := syscall.LazyPrx{Name: "libSceRegMgr.sprx"}
	sceRegMgrGetInt := prx.NewProc("sceRegMgrGetInt")
	var coredumpDumpMode int32 = -1
	r1, _, _ := sceRegMgrGetInt.Call(0x6e010000, uintptr(unsafe.Pointer(&coredumpDumpMode)))
	log.Printf("sceRegMgrGetInt: %#08x\n", sceRegMgrGetInt.Addr())
	log.Printf("sceRegMgrGetInt returned %v\n", int(r1))
	log.Printf("Coredump Mode: %v\n", coredumpDumpMode)
}

func main() {
	enableVerboseSyscoreLogging()
	changeCoredumpMode()
	hen, ctx := NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

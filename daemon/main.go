package main

import (
	"henv"
	"log"
	"runtime"
)

const CANCEL_ADDRESS = ":9050"

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func shutup() {
	/*
		name := [...]int32{4, 0x1c, 0x29, 0x7ffffc4e}
		var value int32
		_, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), 0, 0, uintptr(unsafe.Pointer(&value)), 4)
		if errno != 0 {
			panic(errno.Error())
		}
	*/
	if henv.GetSystemSoftwareVersion() == henv.V450 {
		dad_enhanced := runtime.GetKernelBase() + 0x16AE290
		henv.Kwrite32(dad_enhanced, 0)
	}
}

func main() {
	shutup()
	hen, ctx := henv.NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

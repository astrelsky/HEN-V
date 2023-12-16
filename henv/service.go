package henv

import "syscall"

const (
	SCE_APP_MESSAGING_SEND_MSG_NID    = "+zuv20FsXrA"
	SCE_APP_MESSAGING_RECEIVE_MSG_NID = "jKgAUl6cLy0"
)

var (
	libSceSystemService             = &syscall.LazyPrx{Name: "libSceSystemService.sprx"}
	sceSystemServiceGetAppStatus    = libSceSystemService.NewProc("sceSystemServiceGetAppStatus")
	sceSystemServiceAddLocalProcess = libSceSystemService.NewProc("sceSystemServiceAddLocalProcess")
	sceAppMessagingSendMsg          = libSceSystemService.NewProc("sceAppMessagingSendMsg")
	sceAppMessagingReceiveMsg       = libSceSystemService.NewProc("sceAppMessagingReceiveMsg")
)

func init() {
	println("service init reached")
	err := libSceSystemService.Load()
	if err != nil {
		panic(err)
	}
	handle := libSceSystemService.Handle()
	lib := GetCurrentProc().GetLib(int(handle))
	if lib == 0 {
		panic("Failed to obtain Kernel SharedLib for libSceSystemService")
	}
	addr := lib.GetAddress(SCE_APP_MESSAGING_SEND_MSG_NID)
	if addr == 0 {
		panic("failed to resolve sceAppMessagingSendMsg")
	}
	sceAppMessagingSendMsg.SetAddr(addr)
	addr = lib.GetAddress(SCE_APP_MESSAGING_RECEIVE_MSG_NID)
	if addr == 0 {
		panic("failed to resolve sceAppMessagingReceiveMsg")
	}
	sceAppMessagingReceiveMsg.SetAddr(addr)
}

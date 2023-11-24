package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
	"unsafe"
)

const (
	INTERNAL_APP_MESSAGE_PAYLOAD_SIZE = 0x2000
	POLLHUP                           = 0x0010
	POLLRDNORM                        = 0x0040
)

type InternalAppMessage struct {
	sender      uint32
	msgType     uint32
	payload     [INTERNAL_APP_MESSAGE_PAYLOAD_SIZE]byte
	payloadSize uint32
	timestamp   uint64
}

type AppMessageType uint32

const (
	BREW_MSG_TYPE_REGISTER_PREFIX_HANDLER    AppMessageType = 0x1000000
	BREW_MSG_TYPE_UNREGISTER_PREFIX_HANDLER  AppMessageType = 0x1000001
	BREW_MSG_TYPE_REGISTER_LAUNCH_LISTENER   AppMessageType = 0x1000002
	BREW_MSG_TYPE_UNREGISTER_LAUNCH_LISTENER AppMessageType = 0x1000003
	BREW_MSG_TYPE_APP_LAUNCHED               AppMessageType = 0x1000004
	BREW_MSG_TYPE_KILL                       AppMessageType = 0x1000005
)

type AppLaunchedMessage struct {
	msgType AppMessageType
	pid     int32
	titleid [TITLEID_LENGTH]byte
}

// unknown, for now just use 0
type AppMessagingFlags uint32

type AppMessage struct {
	sender    uint32
	msgType   AppMessageType
	payload   []byte
	timestamp time.Time
	rw        io.ReadWriter
}

type ExternalAppMessage struct {
	sender      uint32
	msgType     uint32
	payloadSize uint64
	// payload     [INTERNAL_APP_MESSAGE_PAYLOAD_SIZE]byte
}

var internalMessageBuffer InternalAppMessage
var internalMessageBufferMtx sync.Mutex

func NewAppLaunchedMessage(pid int32, titleid string) AppLaunchedMessage {
	return AppLaunchedMessage{
		msgType: BREW_MSG_TYPE_APP_LAUNCHED,
		pid:     pid,
		titleid: *(*[TITLEID_LENGTH]byte)([]byte(titleid)),
	}
}

func SceAppMessagingReceiveMsg() (AppMessage, error) {
	internalMessageBufferMtx.Lock()
	defer internalMessageBufferMtx.Unlock()
	res, _, _ := sceAppMessagingReceiveMsg.Call(uintptr(unsafe.Pointer(&internalMessageBuffer)))
	if int(res) < 0 {
		return AppMessage{}, fmt.Errorf("sceAppMessagingReceiveMsg failed %v", int(res))
	}
	//tstamp := time. internalMessageBuffer.timestamp // I don't know what the format is
	msg := AppMessage{
		sender:  internalMessageBuffer.sender,
		msgType: AppMessageType(internalMessageBuffer.msgType),
		payload: make([]byte, internalMessageBuffer.payloadSize),
		//timestamp: tstamp,
	}
	copy(msg.payload, internalMessageBuffer.payload[:])
	return msg, nil
}

func SceAppMessagingSendMsg(appId AppId, msgType AppMessageType, msg []byte, flags AppMessagingFlags) error {
	res, _, _ := sceAppMessagingSendMsg.Call(
		uintptr(appId),
		uintptr(msgType),
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(flags),
	)
	if int(res) < 0 {
		return fmt.Errorf("sceAppMessagingSendMsg failed %v", int(res))
	}
	return nil
}

func (hen *HenV) processPayloadMessages(p *LocalProcess, ctx context.Context) {
	defer hen.wg.Done()
	defer p.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := ctx.Done()
	for {
		select {
		case <-done:
			return
		default:
			emsg := ExternalAppMessage{}
			const length = unsafe.Sizeof(emsg)
			buf := unsafe.Slice((*byte)(unsafe.Pointer(&emsg)), length)
			n, err := p.Read(buf)
			if n < int(length) {
				log.Printf("only read %v out of %v bytes\n", n, length)
				return
			}
			if err != nil {
				log.Println(err)
				return
			}
			msg := &AppMessage{
				sender:    emsg.sender,
				msgType:   AppMessageType(emsg.msgType),
				payload:   make([]byte, emsg.payloadSize),
				timestamp: time.Now(),
				rw:        p,
			}
			hen.msgChannel <- msg
		}
	}
}

/*
type PollFd struct {
	fd      int32
	events  int16
	revents int16
}

func (hen *HenV) msgInterrupt() {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	syscall.Close(hen.kqueue)
	kqueue, err := syscall.Kqueue()
	if err != nil {
		kqueue = -1
		log.Println(err)
	}
	hen.kqueue = kqueue
}

func (hen *HenV) getPayloadFileDescriptors() []PollFd {
	hen.payloadMtx.RLock()
	defer hen.payloadMtx.RUnlock()
	fds := []PollFd{{fd: int32(hen.kqueue), events: POLLHUP | POLLRDNORM}}
	for i := range hen.payloads {
		if hen.payloads[i] != nil {
			fd := hen.payloads[i].fds[0]
			if fd > 0 {
				pfd := PollFd{fd: int32(fd), events: POLLHUP | POLLRDNORM}
				fds = append(fds, pfd)
			}
		}
	}
	return fds
}

func readUint32(fd int) (uint32, error) {
	var value uint32
	_, err := syscall.Read(fd, unsafe.Slice((*byte)(unsafe.Pointer(&value)), 4))
	if err != nil {
		log.Println(err)
	}
	return value, err
}

func readUint64(fd int) (uint64, error) {
	var value uint64
	_, err := syscall.Read(fd, unsafe.Slice((*byte)(unsafe.Pointer(&value)), 8))
	if err != nil {
		log.Println(err)
	}
	return value, err
}

type FileDescriptor struct {
	fd int
}

func (fd *FileDescriptor) Read(p []byte) (n int, err error) {
	n, err = syscall.Read(fd.fd, p)
	return
}

func (fd *FileDescriptor) Write(p []byte) (n int, err error) {
	n, err = syscall.Write(fd.fd, p)
	return
}

func readAppMessage(fd int) (*AppMessage, error) {
	id, err := readUint32(fd)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	msgType, err := readUint32(fd)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	length, err := readUint64(fd)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	payload := make([]byte, length)
	_, err = syscall.Read(fd, payload)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	msg := &AppMessage{
		sender:    id,
		msgType:   AppMessageType(msgType),
		payload:   payload,
		timestamp: time.Now(),
		rw:        &FileDescriptor{fd: fd},
	}
	return msg, nil
}

func (hen *HenV) pollPayloadMessages() error {
	const INFINITE_TIME uintptr = 0xffffffffffffffff
	fds := hen.getPayloadFileDescriptors()
	_, _, err := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(&fds[0])), uintptr(len(fds)), INFINITE_TIME)
	if err != 0 {
		log.Println(err.Error())
		return err
	}
	for i := range fds[1:] {
		if (fds[i].revents & POLLHUP) != 0 {
			log.Printf("payload with socket %v closed\n", fds[i].fd)
			continue
		}
		if (fds[i].revents & POLLRDNORM) != 0 {
			msg, err := readAppMessage(int(fds[i].fd))
			if err != nil {
				log.Println(err)
				continue
			}
			hen.msgChannel <- msg
		}
	}
	return nil
}

func (hen *HenV) payloadMessageReceiver(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := hen.pollPayloadMessages()
			if err != nil {
				log.Println(err)
			}
		}
	}
}
*/

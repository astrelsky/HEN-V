package henv

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"syscall"
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
	BREW_MSG_TYPE_GET_PAYLOAD_NUMBER         AppMessageType = 0x1000006
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
	payloadSize uint32
	//payload   [INTERNAL_APP_MESSAGE_PAYLOAD_SIZE]byte
	//timestamp uint64
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

func (hen *HenV) processPayloadMessages(p LocalProcess, ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()
	defer hen.ClosePayload(p.num)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	defer log.Printf("finished processing messages for payload %v\n", p.num)

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
			if n == 0 {
				// connection closed
				return
			}
			if n < int(length) {
				log.Printf("only read %v out of %v bytes\n", n, length)
				return
			}
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("received message from payload %v\n", p.num)
			if AppMessageType(emsg.msgType) == BREW_MSG_TYPE_GET_PAYLOAD_NUMBER {
				emsg = ExternalAppMessage{
					sender:      uint32(syscall.Getpid()),
					msgType:     uint32(BREW_MSG_TYPE_GET_PAYLOAD_NUMBER),
					payloadSize: 2,
				}
				n, err = p.Write(unsafe.Slice((*byte)(unsafe.Pointer(&emsg)), length))
				if n < int(length) {
					log.Printf("only wrote %v out of %v bytes\n", n, length)
					return
				}
				if err != nil {
					log.Println(err)
					return
				}
				num := uint16(p.num)
				n, err = p.Write(unsafe.Slice((*byte)(unsafe.Pointer(&num)), 2))
				if n < 2 {
					log.Printf("only wrote %v out of %v bytes\n", n, 2)
					return
				}
				if err != nil {
					log.Println(err)
					return
				}
				continue
			}
			msg := &AppMessage{
				sender:    emsg.sender,
				msgType:   AppMessageType(emsg.msgType),
				payload:   make([]byte, emsg.payloadSize),
				timestamp: time.Now(),
				rw:        p,
			}
			n, err = p.Read(msg.payload)
			if n < int(emsg.payloadSize) {
				log.Printf("only read %v out of %v bytes\n", n, emsg.payloadSize)
				return
			}
			if err != nil {
				log.Println(err)
				return
			}
			hen.msgChannel <- msg
		}
	}
}

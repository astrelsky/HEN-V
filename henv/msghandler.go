package henv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"unsafe"
)

var (
	ErrNonPayloadNumRequester = errors.New("HENV_MSG_TYPE_GET_PAYLOAD_NUMBER may only be used by a payload")
)

type MsgBuffer struct {
	bytes.Buffer
}

func (b *MsgBuffer) PutUint16(v uint16) {
	b.Write(unsafe.Slice((*byte)(unsafe.Pointer(&v)), 2))
}

func (b *MsgBuffer) PutUint32(v uint32) {
	b.Write(unsafe.Slice((*byte)(unsafe.Pointer(&v)), 4))
}

func (b *MsgBuffer) PutUint64(v uint64) {
	b.Write(unsafe.Slice((*byte)(unsafe.Pointer(&v)), 8))
}

func (b *MsgBuffer) PutString(v string) {
	b.PutUint32(uint32(len(v)))
	b.WriteString(v)
}

func (hen *HenV) handleMsg(msg *AppMessage) (err error) {
	switch msg.msgType {
	case HENV_MSG_TYPE_REGISTER_PREFIX_HANDLER:
		handler := readAppLaunchPrefixHandler(msg.rw, uint32(msg.sender), msg.payload)
		err = hen.addPrefixHandler(handler)
	case HENV_MSG_TYPE_UNREGISTER_PREFIX_HANDLER:
		handler := readAppLaunchPrefixHandler(msg.rw, uint32(msg.sender), msg.payload)
		err = hen.removePrefixHandler(handler.prefix, handler.id)
	case HENV_MSG_TYPE_REGISTER_LAUNCH_LISTENER:
		handler := readAppLaunchListener(msg.rw, msg.sender, msg.payload)
		err = hen.addLaunchListener(handler)
	case HENV_MSG_TYPE_UNREGISTER_LAUNCH_LISTENER:
		err = hen.removeLaunchListener(msg.sender)
	case HENV_MSG_TYPE_APP_LAUNCHED:
		return
	case HENV_MSG_TYPE_KILL:
		panic("killed as requested")
	case HENV_MSG_TYPE_GET_PAYLOAD_NUMBER:
		err = replyPayloadNumberRequest(msg.rw)
	default:
		err = fmt.Errorf("unknown message type %v", msg.msgType)
	}
	if err != nil {
		replyFailed(msg.rw, msg.msgType, err)
	} else {
		replyOk(msg.rw, msg.msgType)
	}
	return
}

func replyOk(rw AppMessageReadWriter, msgType AppMessageType) error {
	ok := [4]uint8{}
	return rw.WriteMessage(msgType, ok[:])
}

func replyFailed(rw AppMessageReadWriter, msgType AppMessageType, err error) error {
	msg := err.Error()
	buf := make([]byte, len(msg)+4)
	binary.LittleEndian.PutUint32(buf, uint32(len(msg)))
	copy(buf[4:], msg)
	return rw.WriteMessage(msgType, buf)
}

func readAppLaunchPrefixHandler(rw AppMessageReadWriter, id uint32, buf []byte) AppLaunchPrefixHandler {
	var name string
	i := bytes.IndexByte(buf, 0)
	if i != -1 {
		name = string(buf[:i])
		buf = buf[i:]
	}
	prefix := string(buf[:PREFIX_LENGTH])
	return AppLaunchPrefixHandler{
		AppMessageReadWriter: rw,
		Name:                 name,
		prefix:               prefix,
		id:                   id,
	}
}

func readAppLaunchListener(rw AppMessageReadWriter, id uint32, buf []byte) AppLaunchListener {
	var name string
	i := bytes.IndexByte(buf, 0)
	if i != -1 {
		name = string(buf[:i])
		buf = buf[i:]
	}
	return AppLaunchListener{
		AppMessageReadWriter: rw,
		Name:                 name,
		id:                   id,
	}
}

func replyPayloadNumberRequest(rw AppMessageReadWriter) (err error) {
	p, ok := rw.(*LocalProcess)
	if !ok {
		log.Println(ErrNonPayloadNumRequester)
		return ErrNonPayloadNumRequester
	}
	msg := unsafe.Slice((*byte)(unsafe.Pointer(&p.num)), 2)
	rw.WriteMessage(HENV_MSG_TYPE_GET_PAYLOAD_NUMBER, msg)
	return
}

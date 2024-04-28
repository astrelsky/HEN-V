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
	b.PutUint32(uint32(len(v) + 1))
	b.WriteString(v)
	b.WriteByte(0)
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
		handler := AppLaunchListener{
			AppMessageReadWriter: msg.rw,
			id:                   msg.sender,
		}
		err = hen.addLaunchListener(handler)
	case HENV_MSG_TYPE_UNREGISTER_LAUNCH_LISTENER:
		err = hen.removeLaunchListener(msg.sender)
	case HENV_MSG_TYPE_APP_LAUNCHED:
		return
	case HENV_MSG_TYPE_KILL:
		panic("killed as requested")
	case HENV_MSG_TYPE_GET_PAYLOAD_NUMBER:
		replyPayloadNumberRequest(msg.rw)
		return
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
	prefix := string(buf[:PREFIX_LENGTH])
	return AppLaunchPrefixHandler{
		AppMessageReadWriter: rw,
		prefix:               prefix,
		id:                   id,
	}
}

func replyPayloadNumberRequest(rw AppMessageReadWriter) {
	p, ok := rw.(*Payload)
	if !ok {
		log.Println(ErrNonPayloadNumRequester)
		msg := MsgBuffer{}
		msg.PutUint16(0xffff)
		msg.PutString(ErrNonPayloadNumRequester.Error())
		rw.WriteMessage(HENV_MSG_TYPE_GET_PAYLOAD_NUMBER, msg.Bytes())
		return
	}
	msg := make([]byte, 2)
	binary.LittleEndian.PutUint16(msg, uint16(p.num))
	log.Printf("sending payload number: %v\n", p.num)
	p.Write(msg)
}

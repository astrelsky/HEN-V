package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"
)

const PAYLOAD_ADDRESS = ":9020"

var ErrTooManyPayloads = errors.New("Too many payloads are already running")

type LocalProcessArgs struct {
	fds [2]int32
	a   int32
	b   int32
	_   [2]uint64
}

type LocalProcess struct {
	num int
	fds [2]int
	pid int32
}

func SystemServiceAddLocalProcess(pidChannel <-chan int32, num int) (LocalProcess, error) {
	path := []byte(fmt.Sprintf("/app0/payload%d.bin\x00", num))
	param := &LocalProcessArgs{a: 1, b: -1}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(err)
		return LocalProcess{}, err
	}

	cleanup := func() {
		e := syscall.Close(fds[0])
		if e != nil {
			log.Panicln(e)
		}
		e = syscall.Close(fds[1])
		if e != nil {
			log.Panicln(e)
		}
	}

	info := LocalProcess{num: num, fds: [2]int{fds[0], fds[1]}}
	param.fds[0] = int32(fds[0])
	param.fds[1] = int32(fds[1])

	status, err := SystemServiceGetAppStatus()
	if err != nil {
		log.Println(err)
		cleanup()
		return LocalProcess{}, err
	}

	argv := []uintptr{0}

	res, _, _ := sceSystemServiceAddLocalProcess.Call(
		uintptr(status.id),
		uintptr(unsafe.Pointer(&path[0])),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(param)),
	)
	if int(res) < 0 {
		err = fmt.Errorf("sceSystemServiceAddLocalProcess failed: %v", int(res))
		cleanup()
		return LocalProcess{}, err
	}

	info.pid = <-pidChannel

	return info, nil
}

func (hen *HenV) getNextPayloadNum() int {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	for i := range hen.payloads {
		if hen.payloads[i] == nil {
			hen.payloads[i] = &Payload{} // in progress
			return i
		}
	}
	return -1
}

func (hen *HenV) setPayloadPid(pid int32, num int) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	hen.payloads[num].pid = int(pid)
}

func (hen *HenV) clearPayloadSlot(num int) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	hen.payloads[num] = nil
}

func (hen *HenV) setPayloadInfo(num int, pid int, fds [2]int) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	*hen.payloads[num] = Payload{pid: pid, fds: fds}
}

func (hen *HenV) handlePayload(conn net.Conn, ldr chan<- ElfLoadInfo) error {
	defer func() {
		// ownership gets transfered to the channel receiver
		if conn != nil {
			conn.Close()
		}
	}()
	num := hen.getNextPayloadNum()
	if num == -1 {
		return ErrTooManyPayloads
	}
	proc, err := SystemServiceAddLocalProcess(hen.payloadChannel, num)
	if err != nil {
		hen.clearPayloadSlot(num)
		log.Println(err)
		return err
	}
	ldr <- ElfLoadInfo{
		pid:     int(proc.pid),
		tracer:  nil,
		reader:  conn,
		payload: true,
	}
	conn = nil
	hen.setPayloadInfo(num, int(proc.pid), proc.fds)

	// send a SIGUSR1 so we can poll the new local process socket
	err = syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	if err != nil {
		// only log this one
		log.Println(err)
	}
	return nil
}

func (hen *HenV) payloadHandler(payloads chan ElfLoadInfo) {
	defer hen.wg.Done()
	for info := range payloads {
		err := loadElf(info)
		if err != nil {
			log.Println(err)
		}
	}
}

func (hen *HenV) runPayloadServer(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ldr := make(chan ElfLoadInfo, 4)
	defer close(ldr)
	hen.wg.Add(1)
	go hen.payloadHandler(ldr)
	var cfg net.ListenConfig
	ln, err := cfg.Listen(ctx, "tcp", PAYLOAD_ADDRESS)
	if err != nil {
		// NO PAYLOADS FOR YOU
		log.Println(err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			err = hen.handlePayload(conn, ldr)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

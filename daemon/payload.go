package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const PAYLOAD_ADDRESS = ":9020"

type LocalProcessArgs struct {
	_                 int32
	fd                int32
	enableCrashReport int32
	userId            int32
	_                 uint64
	preloadPrxFlags   uint64
}

type LocalProcess struct {
	net.Conn
	num int
}

type ProcessSocket struct {
	net.Conn
	fp      *os.File
	fd      int
	childFd int
}

func NewProcessSocket(name string) (s *ProcessSocket, fd int, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(err)
		return
	}
	fd = fds[1]
	fp := os.NewFile(uintptr(fds[0]), name)
	conn, err := net.FileConn(fp)
	if err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		fp.Close()
		log.Println(err)
		return
	}
	s = &ProcessSocket{
		Conn:    conn,
		fp:      fp,
		fd:      fds[0],
		childFd: fds[1],
	}
	return
}

func (s *ProcessSocket) Close() (err error) {
	if s.fd != -1 {
		err = s.Conn.Close()
		err = errors.Join(err, s.fp.Close())
		err = errors.Join(err, syscall.Close(s.fd))
		err = errors.Join(err, syscall.Close(s.childFd))
		s.fd = -1
	}
	return
}

func newLocalProcess(num int) (LocalProcess, int, error) {
	s, fd, err := NewProcessSocket(fmt.Sprintf("payload%d-socket", num))
	if err != nil {
		log.Println(err)
		return LocalProcess{}, -1, err
	}
	return LocalProcess{Conn: s, num: num}, fd, nil
}

func SystemServiceAddLocalProcess(num int, hen *HenV, ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			return
		}
		hen.payloads.Clear(num)
	}()

	status, err := SystemServiceGetAppStatus()
	if err != nil {
		log.Println(err)
		return
	}

	hen.wg.Add(1)
	go func() {
		defer hen.wg.Done()

		p, fd, err := newLocalProcess(num)

		if err != nil {
			log.Println(err)
			return
		}

		param := &LocalProcessArgs{
			fd:                int32(fd),
			enableCrashReport: 0,
			userId:            -1,
		}

		argv := []uintptr{0}
		path := []byte(fmt.Sprintf("/app0/payload%d.bin\x00", num))
		res, _, _ := sceSystemServiceAddLocalProcess.Call(
			uintptr(status.id),
			uintptr(unsafe.Pointer(&path[0])),
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(param)),
		)

		if int(res) < 0 {
			err = fmt.Errorf("sceSystemServiceAddLocalProcess failed: %v", int(res))
			log.Println(err)
			hen.payloads.Clear(num)
			p.Close()
			return
		}

		hen.wg.Add(1)
		go hen.processPayloadMessages(p, ctx)
	}()

	return
}

func (hen *HenV) handlePayload(ctx context.Context) error {
	num, err := hen.payloads.Next()
	if err != nil {
		log.Println(err)
		return err
	}

	err = SystemServiceAddLocalProcess(num, hen, ctx)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (hen *HenV) payloadHandler(payloads chan ElfLoadInfo) {
	defer hen.wg.Done()
	for info := range payloads {
		func() {
			defer info.Close()
			err := info.LoadElf(hen)
			if err != nil {
				log.Println(err)
			}
		}()
	}
}

func (hen *HenV) runPayloadServer(ctx context.Context) {
	defer hen.wg.Done()

	log.Println("payload server started")

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
		log.Println("payload server failed to start")
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

			ldr <- ElfLoadInfo{
				pidChannel: hen.payloadChannel,
				pid:        -1,
				reader:     conn,
				payload:    true,
			}

			err = hen.handlePayload(ctx)
			if err != nil {
				log.Println(err)
				conn.Close()
			}
		}
	}
}

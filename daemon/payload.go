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
	fds [2]int32
	a   int32
	b   int32
	_   [2]uint64
}

type LocalProcess struct {
	num    int
	writer net.Conn
	reader net.Conn
}

func (p *LocalProcess) Close() (err error) {
	if p.writer != nil {
		err = p.writer.Close()
		p.writer = nil
	}
	if p.reader != nil {
		err = errors.Join(p.reader.Close())
		p.reader = nil
	}
	return
}

func (lp *LocalProcess) Read(p []byte) (int, error) {
	return lp.reader.Read(p)
}

func (lp *LocalProcess) Write(p []byte) (int, error) {
	return lp.writer.Write(p)
}

type ProcessSocket struct {
	net.Conn
	fp *os.File
	fd int
}

func NewProcessSocket(fd int, name string) (s *ProcessSocket, err error) {
	fp := os.NewFile(uintptr(fd), name)
	conn, err := net.FileConn(fp)
	if err != nil {
		fp.Close()
		log.Println(err)
		return
	}
	s = &ProcessSocket{Conn: conn, fp: fp, fd: fd}
	return
}

func (s *ProcessSocket) Close() (err error) {
	if s.fd != -1 {
		err = s.Conn.Close()
		err = errors.Join(err, s.fp.Close())
		err = errors.Join(err, syscall.Close(s.fd))
		s.fd = -1
	}
	return
}

func newLocalProcess(num int, fd0, fd1 *int32) (p *LocalProcess, err error) {
	var writeFile *ProcessSocket
	var readFile *ProcessSocket

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(err)
		return
	}

	defer func() {
		if err == nil {
			return
		}
		if writeFile != nil {
			writeFile.Close()
		} else {
			syscall.Close(fds[0])
		}
		if readFile != nil {
			readFile.Close()
		} else {
			syscall.Close(fds[1])
		}
	}()

	writeFile, err = NewProcessSocket(fds[0], fmt.Sprintf("payload%d-write-socket", num))
	if err != nil {
		log.Println(err)
		return
	}
	*fd0 = int32(fds[0])

	readFile, err = NewProcessSocket(fds[1], fmt.Sprintf("payload%d-read-socket", num))
	if err != nil {
		log.Println(err)
		return
	}

	*fd1 = int32(fds[1])

	p = &LocalProcess{num: num, writer: writeFile, reader: readFile}
	writeFile = nil
	readFile = nil
	return
}

func SystemServiceAddLocalProcess(num int, hen *HenV, ctx context.Context) (err error) {
	var p *LocalProcess
	defer func() {
		if err == nil {
			return
		}
		hen.payloads.Clear(num)
		if p != nil {
			p.Close()
		}
	}()

	param := &LocalProcessArgs{a: 1, b: -1}
	p, err = newLocalProcess(num, &param.fds[0], &param.fds[1])

	if err != nil {
		log.Println(err)
		return
	}

	status, err := SystemServiceGetAppStatus()
	if err != nil {
		log.Println(err)
		return
	}

	hen.wg.Add(1)
	go func() {
		defer hen.wg.Done()

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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"syscall"
	"unsafe"
)

const (

	// 16 processes per application, one is consumed by this process
	MAX_PAYLOADS = 15

	// this should be more then enough to never block
	CHANNEL_BUFFER_SIZE = 16

	PREFIX_LENGTH = 4
)

var HenVTitleId string
var ErrProcNotFound = errors.New("proccess not found")

func init() {
	info, err := GetAppInfo(syscall.Getpid())
	if err != nil {
		panic(err)
	}
	HenVTitleId = info.TitleId()
}

type AppId uint32

type HomebrewLaunchInfo struct {
	tracer *Tracer
	fun    uintptr
}

type LaunchedAppInfo struct {
	pid     int
	titleid string
}

type ElfLoadInfo struct {
	pid     int
	tracer  *Tracer
	reader  io.ReadCloser
	payload bool
}

type Payload struct {
	pid int
	fds [2]int
}

type HenV struct {
	wg               sync.WaitGroup
	listenerMtx      sync.RWMutex
	prefixHandlerMtx sync.RWMutex
	payloadMtx       sync.RWMutex
	prefixHandlers   map[string]AppLaunchPrefixHandler
	launchListeners  []AppLaunchListener
	payloadChannel   chan int32
	listenerChannel  chan int32
	prefixChannel    chan LaunchedAppInfo
	homebrewChannel  chan HomebrewLaunchInfo
	elfChannel       chan ElfLoadInfo
	msgChannel       chan *AppMessage
	payloads         [MAX_PAYLOADS]*Payload
	cancel           context.CancelFunc
}

type AppLaunchListener struct {
	io.ReadWriter
	id uint32
}

type AppLaunchPrefixHandler struct {
	io.ReadWriter
	Name   string
	prefix string
	id     uint32
}

func NewHenV() (HenV, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return HenV{
		payloadChannel:  make(chan int32), // unbuffered
		listenerChannel: make(chan int32, CHANNEL_BUFFER_SIZE),
		prefixChannel:   make(chan LaunchedAppInfo, CHANNEL_BUFFER_SIZE),
		elfChannel:      make(chan ElfLoadInfo), // unbuffered
		msgChannel:      make(chan *AppMessage, CHANNEL_BUFFER_SIZE),
		cancel:          cancel,
	}, ctx
}

func (hen *HenV) Wait() {
	hen.wg.Wait()
}

func (hen *HenV) Close() error {
	log.Println("NO HOMEBREW FOR YOU!")
	hen.cancel()
	return nil
}

func (hen *HenV) Start(ctx context.Context) {
	hen.wg.Add(1)
	go hen.runProcessMonitor(ctx)
	go hen.homebrewHandler(ctx)
	go hen.prefixHandler(ctx)
	go hen.launchListenerHandler(ctx)
	go hen.elfLoadHandler(ctx)
}

func (hen *HenV) addPrefixHandler(handler AppLaunchPrefixHandler) error {
	hen.prefixHandlerMtx.Lock()
	defer hen.prefixHandlerMtx.Unlock()
	currentHandler, ok := hen.prefixHandlers[handler.prefix]
	if ok {
		return fmt.Errorf("Prefix %s is already being handled by %s", handler.prefix, currentHandler.Name)
	}
	hen.prefixHandlers[handler.prefix] = handler
	return nil
}

func (hen *HenV) addLaunchHandler(handler AppLaunchListener) {
	hen.listenerMtx.Lock()
	defer hen.listenerMtx.Unlock()
	hen.launchListeners = append(hen.launchListeners, handler)
}

func (hen *HenV) removeRegisteredPid(pid uint32) {
	func() {
		hen.listenerMtx.Lock()
		defer hen.listenerMtx.Unlock()
		index := -1
		// realiztically there will never be that many so this is fine
		for i := range hen.launchListeners {
			if hen.launchListeners[i].id == pid {
				index = i
				break
			}
		}
		if index != -1 {
			// replace the one at index with the last one and reslice
			last := len(hen.launchListeners) - 1
			hen.launchListeners[index] = hen.launchListeners[last]
			hen.launchListeners = hen.launchListeners[:last]
		}
	}()
	func() {
		hen.prefixHandlerMtx.Lock()
		defer hen.prefixHandlerMtx.Unlock()
		index := ""
		// realiztically there will never be that many so this is fine
		for key := range hen.prefixHandlers {
			if hen.prefixHandlers[key].id == pid {
				index = key
				break
			}
		}
		if index != "" {
			delete(hen.prefixHandlers, index)
		}
	}()
}

func (hen *HenV) exitedProcessHandler(pids <-chan uint32) {
	defer hen.wg.Done()
	for pid := range pids {
		hen.removeRegisteredPid(pid)
	}
}

func (hen *HenV) runProcessMonitor(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	pids := make(chan uint32, 4)
	hen.wg.Add(1)
	go hen.exitedProcessHandler(pids)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(pids)
			return
		default:
			// we should be interrupted frequently enough that waitpid blocking shouldn't matter
			var status syscall.WaitStatus
			pid, err := waitpid(0, &status, syscall.WEXITED)
			if err != nil {
				log.Println(err)
			} else {
				if status.Exited() {
					pids <- uint32(pid)
				}
			}
		}
	}
}

func (hen *HenV) homebrewHandler(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(hen.homebrewChannel)
			return
		case info := <-hen.homebrewChannel:
			err := handleHomebrewLaunch(hen, info.tracer, info.fun)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func (hen *HenV) notifyPrefixHandler(info LaunchedAppInfo) error {
	hen.prefixHandlerMtx.RLock()
	defer hen.prefixHandlerMtx.RUnlock()
	handler := hen.prefixHandlers[info.titleid[:PREFIX_LENGTH]]
	msg := NewAppLaunchedMessage(int32(info.pid), info.titleid)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&msg)), unsafe.Sizeof(msg))
	_, err := handler.Write(buf)
	return err
}

func (hen *HenV) notifyLaunchListeners(info LaunchedAppInfo) error {
	hen.listenerMtx.RLock()
	defer hen.listenerMtx.RUnlock()
	var err error
	msg := NewAppLaunchedMessage(int32(info.pid), info.titleid)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&msg)), unsafe.Sizeof(msg))
	for i := range hen.launchListeners {
		_, e := hen.launchListeners[i].Write(buf)
		if e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

func (hen *HenV) launchListenerHandler(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(hen.listenerChannel)
			return
		case pid := <-hen.listenerChannel:
			info, err := GetAppInfo(int(pid))
			if err != nil {
				log.Println(err)
				continue
			}
			err = hen.notifyLaunchListeners(LaunchedAppInfo{pid: int(pid), titleid: info.TitleId()})
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func (hen *HenV) prefixHandler(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(hen.prefixChannel)
			return
		case info := <-hen.prefixChannel:
			err := hen.notifyPrefixHandler(info)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func (hen *HenV) hasPrefixHandler(prefix string) bool {
	hen.prefixHandlerMtx.RLock()
	defer hen.prefixHandlerMtx.Unlock()
	_, ok := hen.prefixHandlers[prefix]
	return ok
}

func loadElf(info ElfLoadInfo) error {
	defer info.reader.Close()
	data, err := io.ReadAll(info.reader)
	if err != nil {
		log.Println(err)
		if info.tracer != nil {
			info.tracer.Detach()
			return err
		}
	}
	proc := GetProc(info.pid)
	if proc == 0 {
		return ErrProcNotFound
	}
	proc.Jailbreak(info.payload)
	ldr, err := NewElfLoader(info.pid, info.tracer, data)
	if err != nil {
		return err
	}
	return ldr.Run()
}

func (hen *HenV) elfLoadHandler(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(hen.elfChannel)
			return
		case info := <-hen.elfChannel:
			err := loadElf(info)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func readAppLaunchPrefixHandler(rw io.ReadWriter, id uint32, buf []byte) AppLaunchPrefixHandler {
	var name string
	i := bytes.IndexByte(buf, 0)
	if i != -1 {
		name = string(buf[:i])
		buf = buf[i:]
	}
	prefix := string(buf[:PREFIX_LENGTH])
	return AppLaunchPrefixHandler{
		ReadWriter: rw,
		Name:       name,
		prefix:     prefix,
		id:         id,
	}
}

func (hen *HenV) handleMsg(msg *AppMessage) error {
	switch msg.msgType {
	case BREW_MSG_TYPE_REGISTER_PREFIX_HANDLER:
		handler := readAppLaunchPrefixHandler(msg.rw, uint32(msg.sender), msg.payload)
		hen.addPrefixHandler(handler)
	}
	return nil
}

func (hen *HenV) msgHandler(ctx context.Context) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			cancel()
			close(hen.msgChannel)
			return
		case msg := <-hen.msgChannel:
			err := hen.handleMsg(msg)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

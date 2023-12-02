package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
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

var (
	HenVTitleId        string
	ErrProcNotFound    = errors.New("proccess not found")
	ErrTooManyPayloads = errors.New("max payload limit reached")
)

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
	reader     io.ReadCloser
	pidChannel chan int
	pid        int
	tracer     *Tracer
	payload    bool
}

type PayloadFlag struct {
	mtx   sync.Mutex
	value uint16
}

type Payload struct {
	pid int
	fds [2]int
}

type HenV struct {
	wg               sync.WaitGroup
	listenerMtx      sync.RWMutex
	prefixHandlerMtx sync.RWMutex
	pidMtx           sync.RWMutex
	payloadMtx       sync.RWMutex
	prefixHandlers   map[string]AppLaunchPrefixHandler
	launchListeners  []AppLaunchListener
	monitoredPids    chan int
	payloadChannel   chan int
	listenerChannel  chan int32
	prefixChannel    chan LaunchedAppInfo
	homebrewChannel  chan HomebrewLaunchInfo
	elfChannel       chan ElfLoadInfo
	msgChannel       chan *AppMessage
	childChannel     chan os.Signal
	payloads         PayloadFlag
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

func (f *PayloadFlag) Set(i int) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.value |= 1 << i
}

func (f *PayloadFlag) Clear(i int) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.value &= ^(1 << i)
}

func (f *PayloadFlag) Next() (n int, err error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for i := 0; i <= MAX_PAYLOADS; i++ {
		var mask uint16 = 1 << i
		if (f.value & mask) == 0 {
			n = i
			f.value |= mask
			return
		}
	}
	err = ErrTooManyPayloads
	log.Println(err)
	return
}

func NewHenV() (HenV, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return HenV{
		launchListeners: []AppLaunchListener{},
		monitoredPids:   make(chan int), // unbuffered
		payloadChannel:  make(chan int), // unbuffered
		listenerChannel: make(chan int32, CHANNEL_BUFFER_SIZE),
		prefixChannel:   make(chan LaunchedAppInfo, CHANNEL_BUFFER_SIZE),
		homebrewChannel: make(chan HomebrewLaunchInfo), // unbuffered
		elfChannel:      make(chan ElfLoadInfo),        // unbuffered
		msgChannel:      make(chan *AppMessage, CHANNEL_BUFFER_SIZE),
		childChannel:    make(chan os.Signal, CHANNEL_BUFFER_SIZE),
		cancel:          cancel,
	}, ctx
}

func (hen *HenV) Wait() {
	hen.wg.Wait()
	signal.Stop(hen.childChannel)
}

func (hen *HenV) Close() error {
	log.Println("NO MORE HOMEBREW FOR YOU!")
	hen.cancel()
	close(hen.monitoredPids)
	close(hen.payloadChannel)
	close(hen.listenerChannel)
	close(hen.prefixChannel)
	close(hen.homebrewChannel)
	close(hen.elfChannel)
	close(hen.msgChannel)
	return nil
}

func childMonitor(wg *sync.WaitGroup, signals <-chan os.Signal) {
	defer wg.Done()
	for sig := range signals {
		log.Printf("%s received", sig.String())
	}
}

func (hen *HenV) Start(ctx context.Context) {
	hen.wg.Add(7)

	signal.Notify(hen.childChannel, syscall.SIGCHLD)

	go childMonitor(&hen.wg, hen.childChannel)
	//go hen.runProcessMonitor(ctx)
	go hen.homebrewHandler(ctx)
	go hen.prefixHandler(ctx)
	go hen.launchListenerHandler(ctx)
	go hen.elfLoadHandler(ctx)
	go hen.runPayloadServer(ctx)
	go startSyscoreIpc(hen, ctx)
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
		// realistically there will never be that many so this is fine
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

func mountProcFs() (int, error) {
	if !fileExists("/mnt/proc") {
		err := syscall.Mkdir("/mnt/proc", 0777)
		if err != nil {
			return -1, err
		}
		name, err := syscall.BytePtrFromString("procfs")
		if err != nil {
			return -1, err
		}
		path, err := syscall.BytePtrFromString("/mnt/proc")
		if err != nil {
			return -1, err
		}
		_, _, errno := syscall.Syscall(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(path)), 0)
		if errno != 0 {
			panic(errno)
		}
	}
	return syscall.Open("/mnt/proc", syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0666)
}

func procWait(wg *sync.WaitGroup, pid int) {
	defer wg.Done()

	tracer, err := NewTracer(pid)

	if err != nil {
		log.Println(err)
		return
	}

	defer tracer.Detach()

	tracer.Continue()

	for {
		state, err := tracer.Wait(0)
		if err != nil {
			log.Println(err)
			return
		}
		if state.Exited() {
			log.Printf("proceess %v exited\n", pid)
			return
		}
		if state.Signaled() {
			log.Printf("process %v received signal %s\n", pid, state.Signal())
		} else if state.Stopped() {
			sig := state.StopSignal()

			if sig == syscall.SIGKILL {
				err = tracer.Kill(false)
				if err != nil {
					log.Println(err)
				}
				return
			}

			if sig == syscall.SIGILL || sig == syscall.SIGSEGV {
				// TODO: print backtrace and then kill

				tracer.Close(3)
				return
			}

			log.Printf("process %v stopped on signal %s\n", pid, sig)

			err = tracer.Continue()
			if err != nil {
				log.Println(err)
				return
			}
		} else {
			log.Println("wait returned for no reason?")
		}
	}
}

func (hen *HenV) runProcessMonitor(ctx context.Context) {
	defer hen.wg.Done()
	log.Println("process monitor started")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := ctx.Done()

	for {
		select {
		case <-done:
			return
		case pid := <-hen.monitoredPids:
			hen.wg.Add(1)
			go procWait(&hen.wg, pid)
		}
	}
}

func (hen *HenV) homebrewHandler(ctx context.Context) {
	defer hen.wg.Done()

	log.Println("homebrew handler started")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case info := <-hen.homebrewChannel:
			log.Println("received hombrew info")
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
	log.Println("listener handler started")
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
	log.Println("prefix handler started")
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

func (hen *HenV) elfLoadHandler(ctx context.Context) {
	defer hen.wg.Done()
	log.Println("elf loader started")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(hen.elfChannel)
	for {
		select {
		case <-ctx.Done():
			return
		case info := <-hen.elfChannel:
			func() {
				defer info.Close()
				err := info.LoadElf(hen)
				if err != nil {
					log.Println(err)
				}
			}()
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

package henv

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
	payload    int
}

type Payload struct {
	proc LocalProcess
	pid  int
}

type HenV struct {
	wg               sync.WaitGroup
	listenerMtx      sync.RWMutex
	prefixHandlerMtx sync.RWMutex
	pidMtx           sync.RWMutex
	payloadMtx       sync.Mutex
	prefixHandlers   map[string]AppLaunchPrefixHandler
	launchListeners  []AppLaunchListener
	payloadChannel   chan int
	listenerChannel  chan int32
	prefixChannel    chan LaunchedAppInfo
	homebrewChannel  chan HomebrewLaunchInfo
	elfChannel       chan ElfLoadInfo
	msgChannel       chan *AppMessage
	payloads         [15]Payload
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

func (p *Payload) Close() error {
	p.pid = -1
	return p.proc.Close()
}

func (p *Payload) IsAlive() bool {
	if p.pid == -1 {
		return false
	}
	return syscall.Kill(p.pid, 0) == nil
}

func (p *Payload) Kill() error {
	if p.pid <= 0 {
		return nil
	}
	return syscall.Kill(p.pid, syscall.SIGKILL)
}

func (hen *HenV) ClosePayload(num int) (err error) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	p := &hen.payloads[num]
	if p.pid > 0 {
		if p.IsAlive() {
			p.Kill()
		}
		err = p.Close()
	} else if p.pid == 0 {
		p.pid = -1
	}
	return
}

func (hen *HenV) setPayloadPid(num, pid int) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	hen.payloads[num].pid = pid
}

func (hen *HenV) setPayloadProcess(num int, proc LocalProcess) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	hen.payloads[num].proc = proc
}

func (hen *HenV) checkPayloads() {
	for i := range hen.payloads {
		p := &hen.payloads[i]
		if p.pid > 0 {
			if !p.IsAlive() {
				p.Close()
			}
		}
	}
}

func (hen *HenV) NextPayload() (int, error) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	//hen.checkPayloads()
	for i := range hen.payloads {
		if hen.payloads[i].pid < 0 {
			hen.payloads[i].pid = 0
			return i, nil
		}
	}
	return -1, ErrTooManyPayloads
}

func NewHenV() (HenV, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return HenV{
		launchListeners: []AppLaunchListener{},
		payloadChannel:  make(chan int), // unbuffered
		listenerChannel: make(chan int32, CHANNEL_BUFFER_SIZE),
		prefixChannel:   make(chan LaunchedAppInfo, CHANNEL_BUFFER_SIZE),
		homebrewChannel: make(chan HomebrewLaunchInfo), // unbuffered
		elfChannel:      make(chan ElfLoadInfo),        // unbuffered
		msgChannel:      make(chan *AppMessage, CHANNEL_BUFFER_SIZE),
		cancel:          cancel,
	}, ctx
}

func (hen *HenV) Wait() {
	hen.wg.Wait()
}

func (hen *HenV) Close() error {
	log.Println("NO MORE HOMEBREW FOR YOU!")
	hen.cancel()
	close(hen.payloadChannel)
	close(hen.listenerChannel)
	close(hen.prefixChannel)
	close(hen.homebrewChannel)
	close(hen.elfChannel)
	close(hen.msgChannel)
	return nil
}

func (hen *HenV) Start(ctx context.Context) {
	hen.wg.Add(6)

	for i := range hen.payloads {
		hen.payloads[i].pid = -1
	}

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

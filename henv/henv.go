package henv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const (

	// 16 processes per application, one is consumed by this process
	MAX_PAYLOADS = 15

	// this should be more then enough to never block
	CHANNEL_BUFFER_SIZE = 16

	PREFIX_LENGTH = 4
)

var (
	HenVTitleId                  string
	ErrProcNotFound              = errors.New("proccess not found")
	ErrTooManyPayloads           = errors.New("max payload limit reached")
	ErrNotRegisteredHandler      = errors.New("handlers may only unregister themselves")
	ErrListenerAlreadyRegistered = errors.New("launch listener is already registered")
	ErrUnregisteredListener      = errors.New("launch listener is not registered")
)

func init() {
	info, err := GetAppInfo(getpid())
	if err != nil {
		panic(err)
	}
	HenVTitleId = info.TitleId()
}

type AppId uint32

type HomebrewLaunchInfo struct {
	tracer *Tracer
	fun    uintptr
	args   uintptr
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

type SharedGlobals struct {
	kmemMtx          sync.Mutex
	currentAuthIdMtx sync.Mutex
}

var globals SharedGlobals

func InitGlobals(globals *SharedGlobals) {
	kmemMtx = &globals.kmemMtx
	currentAuthIdMtx = &globals.currentAuthIdMtx
	_currentProc = GetProc(getpid())
	_currentUcred = GetCurrentProc().GetUcred()
}

func init() {
	// init in plugins is only called for modules not yet in the program
	InitGlobals(&globals)
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
	launchChannel    chan LaunchedAppInfo
	homebrewChannel  chan HomebrewLaunchInfo
	elfChannel       chan ElfLoadInfo
	msgChannel       chan *AppMessage
	sendMsgChannel   chan *OutgoingAppMessage
	payloads         [15]Payload
	cancel           context.CancelFunc
	cancelChannel    chan os.Signal
}

type AppLaunchListener struct {
	AppMessageReadWriter
	Name string
	id   uint32
}

type AppLaunchPrefixHandler struct {
	AppMessageReadWriter
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
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	return HenV{
		launchListeners: []AppLaunchListener{},
		payloadChannel:  make(chan int), // unbuffered
		listenerChannel: make(chan int32, CHANNEL_BUFFER_SIZE),
		launchChannel:   make(chan LaunchedAppInfo, CHANNEL_BUFFER_SIZE),
		homebrewChannel: make(chan HomebrewLaunchInfo), // unbuffered
		elfChannel:      make(chan ElfLoadInfo),        // unbuffered
		msgChannel:      make(chan *AppMessage, CHANNEL_BUFFER_SIZE),
		sendMsgChannel:  make(chan *OutgoingAppMessage, CHANNEL_BUFFER_SIZE),
		cancel:          cancel,
		cancelChannel:   c,
	}, ctx
}

func (hen *HenV) Wait() {
	hen.wg.Wait()
}

func (hen *HenV) Close() error {
	log.Println("NO MORE HOMEBREW FOR YOU!")
	hen.cancel()
	close(hen.cancelChannel)
	close(hen.payloadChannel)
	close(hen.listenerChannel)
	close(hen.launchChannel)
	close(hen.homebrewChannel)
	close(hen.elfChannel)
	close(hen.msgChannel)
	close(hen.sendMsgChannel)
	return nil
}

func (hen *HenV) Start(ctx context.Context) {
	hen.wg.Add(7)

	for i := range hen.payloads {
		hen.payloads[i].pid = -1
	}

	go hen.homebrewHandler(ctx)
	go hen.launchHandler(ctx)
	go hen.launchListenerHandler(ctx)
	go hen.elfLoadHandler(ctx)
	go hen.runPayloadServer(ctx)
	go hen.runMessageSender(ctx)
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

func (hen *HenV) removePrefixHandler(prefix string, id uint32) error {
	hen.prefixHandlerMtx.Lock()
	defer hen.prefixHandlerMtx.Unlock()
	handler, ok := hen.prefixHandlers[prefix]
	if !ok {
		return nil
	}
	if handler.id != id {
		return ErrNotRegisteredHandler
	}
	delete(hen.prefixHandlers, prefix)
	return nil
}

func (hen *HenV) findLaunchListener(id uint32) int {
	for i := range hen.launchListeners {
		if hen.launchListeners[i].id == id {
			return i
		}
	}
	return -1
}

func (hen *HenV) addLaunchListener(handler AppLaunchListener) error {
	hen.listenerMtx.Lock()
	defer hen.listenerMtx.Unlock()
	i := hen.findLaunchListener(handler.id)
	if i == -1 {
		hen.launchListeners = append(hen.launchListeners, handler)
		return nil
	}
	return ErrListenerAlreadyRegistered
}

func (hen *HenV) removeLaunchListener(id uint32) error {
	hen.listenerMtx.Lock()
	defer hen.listenerMtx.Unlock()
	i := hen.findLaunchListener(id)
	if i == -1 {
		return ErrUnregisteredListener
	}
	n := len(hen.launchListeners)
	if i+1 != n {
		copy(hen.launchListeners[i:], hen.launchListeners[i+1:])
	}
	hen.launchListeners = hen.launchListeners[:n-1]
	return nil
}

func (hen *HenV) homebrewHandler(ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()

	log.Println("homebrew handler started")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case _, _ = <-ctx.Done():
			return
		case info := <-hen.homebrewChannel:
			log.Println("received hombrew info")
			err := handleHomebrewLaunch(hen, info.tracer, info.fun, info.args)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func (hen *HenV) notifyPrefixHandler(info LaunchedAppInfo) (err error) {
	hen.prefixHandlerMtx.RLock()
	defer hen.prefixHandlerMtx.RUnlock()
	handler, ok := hen.prefixHandlers[info.titleid[:PREFIX_LENGTH]]
	if !ok {
		return
	}
	buf := MsgBuffer{}
	buf.PutUint32(uint32(info.pid))
	buf.WriteString(info.titleid)
	err = handler.WriteMessage(HENV_MSG_TYPE_APP_LAUNCHED, buf.Bytes())
	return
}

func (hen *HenV) notifyLaunchListeners(info LaunchedAppInfo) (err error) {
	hen.listenerMtx.RLock()
	defer hen.listenerMtx.RUnlock()
	buf := MsgBuffer{}
	buf.PutUint32(uint32(info.pid))
	buf.WriteString(info.titleid)
	for i := range hen.launchListeners {
		e := hen.launchListeners[i].WriteMessage(HENV_MSG_TYPE_APP_LAUNCHED, buf.Bytes())
		if e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

func (hen *HenV) launchListenerHandler(ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()
	log.Println("listener handler started")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(hen.listenerChannel)
	for {
		select {
		case _, _ = <-ctx.Done():
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

func (hen *HenV) launchHandler(ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()
	log.Println("launch handler started")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(hen.launchChannel)
	for {
		select {
		case _, _ = <-ctx.Done():
			return
		case info := <-hen.launchChannel:
			if hen.hasPrefixHandler(info.titleid) {
				err := hen.notifyPrefixHandler(info)
				if err != nil {
					log.Println(err)
				}
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
		case _, _ = <-ctx.Done():
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

func (hen *HenV) msgHandler(ctx context.Context) {
	defer func() {
		hen.wg.Done()
		log.Println("Done")
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(hen.msgChannel)
	for {
		select {
		case _, _ = <-ctx.Done():

			return
		case msg := <-hen.msgChannel:
			err := hen.handleMsg(msg)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

var getpid = sync.OnceValue(func() int { return syscall.Getpid() })

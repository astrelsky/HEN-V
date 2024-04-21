package henv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net"
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
	reader  io.ReadCloser
	pid     int
	tracer  *Tracer
	payload int
}

type Payload struct {
	net.Conn
	num int
	pid int
}

type HenV struct {
	wg               sync.WaitGroup
	listenerMtx      sync.RWMutex
	prefixHandlerMtx sync.RWMutex
	payloadMtx       sync.Mutex
	prefixHandlers   map[string]AppLaunchPrefixHandler
	launchListeners  []AppLaunchListener
	listenerChannel  chan int32
	launchChannel    chan LaunchedAppInfo
	homebrewChannel  chan HomebrewLaunchInfo
	elfChannel       chan ElfLoadInfo
	msgChannel       chan *AppMessage
	sendMsgChannel   chan *OutgoingAppMessage
	payloads         map[int]*Payload
	cancel           context.CancelFunc
	cancelChannel    chan os.Signal
	currentAuthIdMtx *sync.Mutex
	kmemMtx          *sync.Mutex
	payloadCount     uint64
}

type AppLaunchListener struct {
	AppMessageReadWriter
	id uint32
}

type AppLaunchPrefixHandler struct {
	AppMessageReadWriter
	prefix string
	id     uint32
}

func (p *Payload) Close() error {
	if p.IsAlive() {
		p.Kill()
	}
	p.pid = -1
	return p.Conn.Close()
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
	p := hen.payloads[num]
	if p.pid > 0 {
		if p.IsAlive() {
			p.Kill()
		}
		err = p.Close()
	} else if p.pid == 0 {
		p.pid = -1
	}
	hen.payloadCount |= ^(1 << num)
	return
}

func (hen *HenV) getNextPayloadNum() int {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	num := bits.TrailingZeros64(hen.payloadCount)
	if num == 64 {
		return -1
	}
	hen.payloadCount ^= (1 << num)
	return num
}

func (hen *HenV) addPayload(num int, p *Payload) {
	hen.payloadMtx.Lock()
	defer hen.payloadMtx.Unlock()
	hen.payloads[num] = p
}

func NewHenV() (HenV, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	return HenV{
		prefixHandlers:   map[string]AppLaunchPrefixHandler{},
		launchListeners:  []AppLaunchListener{},
		listenerChannel:  make(chan int32, CHANNEL_BUFFER_SIZE),
		launchChannel:    make(chan LaunchedAppInfo, CHANNEL_BUFFER_SIZE),
		homebrewChannel:  make(chan HomebrewLaunchInfo), // unbuffered
		elfChannel:       make(chan ElfLoadInfo),        // unbuffered
		msgChannel:       make(chan *AppMessage, CHANNEL_BUFFER_SIZE),
		sendMsgChannel:   make(chan *OutgoingAppMessage, CHANNEL_BUFFER_SIZE),
		payloads:         map[int]*Payload{},
		cancel:           cancel,
		cancelChannel:    c,
		currentAuthIdMtx: &currentAuthIdMtx,
		kmemMtx:          &kmemMtx,
		payloadCount:     0xffffffffffffffff,
	}, ctx
}

func (hen *HenV) Wait() {
	hen.wg.Wait()
}

func (hen *HenV) Close() error {
	log.Println("NO MORE HOMEBREW FOR YOU!")
	hen.cancel()
	close(hen.cancelChannel)
	close(hen.listenerChannel)
	close(hen.launchChannel)
	close(hen.homebrewChannel)
	close(hen.elfChannel)
	close(hen.msgChannel)
	close(hen.sendMsgChannel)
	return nil
}

func (hen *HenV) Start(ctx context.Context) {
	hen.wg.Add(9)

	for i := range hen.payloads {
		hen.payloads[i].pid = -1
	}

	go hen.homebrewHandler(ctx)
	go hen.launchHandler(ctx)
	go hen.launchListenerHandler(ctx)
	go hen.elfLoadHandler(ctx)
	go hen.runPayloadServer(ctx)
	go hen.runMessageSender(ctx)
	go hen.msgHandler(ctx)
	go hen.processAppMessages(ctx)
	go startSyscoreIpc(hen, ctx)
}

func (hen *HenV) addPrefixHandler(handler AppLaunchPrefixHandler) error {
	hen.prefixHandlerMtx.Lock()
	defer hen.prefixHandlerMtx.Unlock()
	currentHandler, ok := hen.prefixHandlers[handler.prefix]
	if ok {
		return fmt.Errorf("prefix %s is already being handled by %#x", handler.prefix, currentHandler.id)
	}
	log.Printf("adding prefix handler for prefix %s\n", handler.prefix)
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

	done := ctx.Done()

	for {
		select {
		case <-done:
			return
		case info := <-hen.homebrewChannel:
			log.Println("received homebrew info")
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

	done := ctx.Done()
	for {
		select {
		case <-done:
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

	done := ctx.Done()
	for {
		select {
		case <-done:
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
	defer hen.prefixHandlerMtx.RUnlock()
	_, ok := hen.prefixHandlers[prefix[:PREFIX_LENGTH]]
	return ok
}

func (hen *HenV) elfLoadHandler(ctx context.Context) {
	defer hen.wg.Done()

	log.Println("elf loader started")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(hen.elfChannel)
	done := ctx.Done()
	for {
		select {
		case <-done:
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
	done := ctx.Done()
	for {
		select {
		case <-done:
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

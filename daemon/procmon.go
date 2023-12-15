package main

import (
	"context"
	"log"
	"slices"
	"syscall"
)

func (hen *HenV) runProcessMonitor(ctx context.Context) {
	defer hen.wg.Done()
	log.Println("process monitor started")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := ctx.Done()

	dead := make(chan int, 16)
	defer close(dead)

	closer, err := syscall.Kqueue()
	if err != nil {
		// shouldn't occur
		panic(err)
	}
	defer syscall.Close(closer)

	kq, err := syscall.Kqueue()
	if err != nil {
		panic(err)
	}

	var pids []int
	pidChan := make(chan []int)
	hen.wg.Add(1)
	go hen.runWaiter(ctx, kq, closer, dead, pidChan)

	for {
		select {
		case <-done:
			return
		case pid := <-dead:
			log.Printf("pid %v exited\n", pid)
			i := slices.Index(pids, pid)
			copy(pids[i:], pids[i+1:])
			pids = pids[:len(pids)-1]
		case pid := <-hen.monitoredPids:
			log.Printf("received pid %v to monitor", pid)
			stopWaiting(kq, closer)
			pids = append(pids, pid)
			pidChan <- pids
		}
	}
}

func stopWaiting(kq, closer int) error {
	events := []syscall.Kevent_t{
		{
			Ident:  uint64(closer),
			Filter: syscall.EVFILT_USER,
			Fflags: syscall.NOTE_TRIGGER,
		},
	}
	_, err := syscall.Kevent(kq, nil, events, nil)
	return err
}

func (hen *HenV) runWaiter(ctx context.Context, kq int, closer int, dead chan<- int, pids <-chan []int) {
	defer hen.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := ctx.Done()
	for {
		select {
		case <-done:
			return
		default:
			waitForExit(kq, <-pids, closer, dead)
		}
	}
}

func waitForExit(kq int, pids []int, closer int, dead chan<- int) {
	events := make([]syscall.Kevent_t, len(pids)+1)
	events[0] = syscall.Kevent_t{
		Ident:  uint64(closer),
		Filter: syscall.EVFILT_USER,
		Flags:  syscall.EV_ADD | syscall.EV_CLEAR,
	}
	for i := range pids {
		events[i+1] = syscall.Kevent_t{
			Ident:  uint64(pids[i]),
			Filter: syscall.EVFILT_PROC,
			Flags:  syscall.EV_ADD,
			Fflags: syscall.NOTE_EXIT,
		}
	}
	// kevent(kq, len(events), events, 0, NULL, NULL)
	_, err := syscall.Kevent(kq, events, nil, nil)
	if err != nil {
		log.Println(err)
	}
	log.Printf("waiting for pids to exit")
	// kevent(kq, 0, NULL, len(events), events, NULL)
	_, err = syscall.Kevent(kq, nil, events, nil)
	if err != nil {
		log.Println(err)
	}
	events = events[1:]
	for i := range events {
		if events[i].Fflags == syscall.NOTE_EXIT {
			dead <- pids[i]
		}
	}
}

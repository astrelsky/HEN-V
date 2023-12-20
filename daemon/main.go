package main

import (
	"context"
	"henv"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

const CANCEL_ADDRESS = ":9050"

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func klog(ctx context.Context) {
	//done := ctx.Done()

	fp, err := os.Open("/dev/klog")
	if err != nil {
		//panic(err)
		return
	}
	defer fp.Close()

	config := net.ListenConfig{}

	ln, err := config.Listen(ctx, "tcp", ":9081")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		func() {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
				return
			}
			defer conn.Close()
			tcp := conn.(*net.TCPConn)
			for {

				log.Printf("runtime.NumCPU: %v\n", runtime.NumCPU())
				m, err := syscall.SysctlUint32("kern.ipc.soacceptqueue")
				if err != nil {
					log.Println(err)
				}
				log.Printf("kern.ipc.soacceptqueue: %v\n", m)
				host, err := syscall.Sysctl("kern.hostname")
				if err != nil {
					log.Println(err)
				}
				log.Printf("kern.hostname: %v\n", host)
				ips, err := net.LookupIP("192.168.1.5")
				if err != nil {
					log.Println(err)
				}
				log.Println("ips:")
				for i := range ips {
					log.Println(ips[i])
				}
				log.Printf("NumGoroutine: %v\n", runtime.NumGoroutine())
				//runtime.Breakpoint()
				n, err := tcp.ReadFrom(fp)
				log.Printf("read %v bytes from klog\n", n)
				if err != nil {
					log.Println(err)
					return
				}

			}
		}()
	}
}

func canceller() {
	ln, err := net.Listen("tcp", CANCEL_ADDRESS)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		log.Println(err)
	}
	if conn != nil {
		conn.Close()
	}
	log.Println("cancelled")
	err = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	if err != nil {
		log.Println(err)
	}
	time.Sleep(time.Second * 5)
	runtime.Breakpoint()
}

func main() {
	//log.Printf("runtime.NumCPU: %v\n", runtime.NumCPU())
	//go canceller()
	hen, ctx := henv.NewHenV()
	//klogctx, cancel := context.WithCancel(ctx)
	//defer cancel()
	hen.Start(ctx)
	//go klog(klogctx)
	hen.Wait()
}

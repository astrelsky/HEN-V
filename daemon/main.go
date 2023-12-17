package main

import (
	"context"
	"henv"
	"log"
	"net"
	"os"
	"runtime"
)

const CANCEL_ADDRESS = ":9050"

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func klog(ctx context.Context) {
	done := ctx.Done()

	fp, err := os.Open("/dev/klog")
	if err != nil {
		panic(err)
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
				select {
				case <-done:
					return
				default:
					log.Printf("runtime.NumCPU: %v\n", runtime.NumCPU())
					n, err := tcp.ReadFrom(fp)
					log.Printf("read %v bytes from klog\n", n)
					if err != nil {
						log.Println(err)
						return
					}
				}
			}
		}()
	}
}

func canceller() context.Context {
	ln, err := net.Listen("tcp", CANCEL_ADDRESS)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			if conn != nil {
				conn.Close()
			}
			cancel()
		}
	}()
	return ctx
}

func main() {
	log.Printf("runtime.NumCPU: %v\n", runtime.NumCPU())
	ctx := canceller()
	hen, ctx := henv.NewHenV(ctx)
	klogctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hen.Start(ctx)
	go klog(klogctx)
	hen.Wait()
}

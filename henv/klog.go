package henv

import (
	"bufio"
	"net"
	"os"
	"sync"
)

func sendKlog(conn net.Conn, fp *os.File) {
	defer conn.Close()

	reader := bufio.NewReader(fp)

	for {
		_, err := reader.WriteTo(conn)
		if err != nil {
			print(err.Error())
			return
		}
	}
}

func runKlog(wg *sync.WaitGroup) {
	defer wg.Done()

	fp, err := os.OpenFile("/dev/klog", 0, 0)

	if err != nil {
		print(err.Error())
		return
	}

	defer fp.Close()

	ln, err := net.Listen("tcp", ":9081")
	if err != nil {
		print(err.Error())
		return
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			print(err.Error())
			return
		}
		sendKlog(conn, fp)
	}
}

package main

import (
	"fmt"
	"log"
	"syscall"
)

func main() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	println("Hello World")
	handles, err := syscall.DynlibGetList()
	if err != 0 {
		panic(err)
	}
	for i := range handles {
		handle := handles[i]
		info, err := syscall.DynlibGetInfo(handle)
		if err != 0 {
			panic(err)
		}
		fmt.Printf("%s: %v\n", info.Name(), handle)
	}
}

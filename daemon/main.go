package main

import (
	"fmt"
	"log"
	"syscall"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}

func main() {

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

	ldr := NewElfLoader(0, nil)
	ldr.Run()
}

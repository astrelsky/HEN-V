package main

import (
	"log"
)

func init() {
	println("main.init reached")
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func main() {
	println("Hello World")
	hen, ctx := NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

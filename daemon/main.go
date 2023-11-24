package main

import (
	"log"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func main() {
	hen, ctx := NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

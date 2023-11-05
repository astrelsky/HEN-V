package main

import (
	"log"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}

func main() {
	hen, ctx := NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

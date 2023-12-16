package main

import (
	"henv"
	"log"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func main() {
	hen, ctx := henv.NewHenV()
	hen.Start(ctx)
	hen.Wait()
}

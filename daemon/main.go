package main

import (
	"log"
)

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	log.SetPrefix("[HEN-V] ")
}

func main() {
	hen, ctx, err := NewHenV()
	if err != nil {
		log.Println(err)
		return
	}
	hen.Start(ctx)
	hen.Wait()
}

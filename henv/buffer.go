package henv

import (
	"io"
	"log"
	"sync/atomic"
	"time"
)

type ByteBuilder struct {
	buf []byte
	off int
}

func NewByteBuilder() ByteBuilder {
	return ByteBuilder{buf: []byte{}}
}

func (b *ByteBuilder) Grow(n int) {
	m := len(b.buf) - b.off
	if m < n {
		b.buf = append(b.buf, make([]byte, n-m)...)
	}
}

func (b *ByteBuilder) ReadFrom(r io.ReadCloser) (n int64, err error) {
	// overkill timeout but it'll ensure we never get stuck
	// unless the runtime itself is stuck because that happened :(
	done := atomic.Bool{}
	go func() {
		time.Sleep(time.Second * 4)
		if !done.Load() {
			log.Println("read timeout reached, assuming read finished")
			r.Close()
		}
	}()
	off := b.off
	b.off = len(b.buf)
	m, err := io.ReadFull(r, b.buf[off:])
	done.Store(true)
	n = int64(m)
	return
}

func (b *ByteBuilder) Bytes() []byte {
	return b.buf
}

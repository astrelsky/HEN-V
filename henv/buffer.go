package henv

import (
	"io"
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

func (b *ByteBuilder) ReadFrom(r io.Reader) (n int64, err error) {
	off := b.off
	b.off = len(b.buf)
	m, err := io.ReadFull(r, b.buf[off:])
	n = int64(m)
	return
}

func (b *ByteBuilder) Bytes() []byte {
	return b.buf
}

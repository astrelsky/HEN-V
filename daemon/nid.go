package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
)

var NID_KEY = []byte{
	0x51, 0x8D, 0x64, 0xA6,
	0x35, 0xDE, 0xD8, 0xC1,
	0xE6, 0xB0, 0x39, 0xB1,
	0xC3, 0xE5, 0x52, 0x30,
}

func GetNid(symbol string) string {
	h := sha1.New()
	io.WriteString(h, symbol)
	h.Write(NID_KEY)
	hash := h.Sum(nil)
	digest := make([]byte, 8)
	binary.BigEndian.PutUint64(digest, binary.LittleEndian.Uint64(hash))
	return base64.StdEncoding.EncodeToString(digest)[:11]
}

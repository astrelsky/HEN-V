package henv

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
)

var NidEncoding = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-")

type Nid string

var NID_KEY = []byte{
	0x51, 0x8D, 0x64, 0xA6,
	0x35, 0xDE, 0xD8, 0xC1,
	0xE6, 0xB0, 0x39, 0xB1,
	0xC3, 0xE5, 0x52, 0x30,
}

func GetNid(symbol string) Nid {
	h := sha1.New()
	io.WriteString(h, symbol)
	h.Write(NID_KEY)
	hash := h.Sum(nil)
	digest := make([]byte, 8)
	binary.BigEndian.PutUint64(digest, binary.LittleEndian.Uint64(hash))
	return Nid(NidEncoding.EncodeToString(digest)[:11])
}

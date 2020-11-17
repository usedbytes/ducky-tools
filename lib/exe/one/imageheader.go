// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package one

import (
	"encoding/binary"
)

type imageHeader struct {
	idx     byte
	size    uint32
	rawData []byte
}

func (ih *imageHeader) crcValue() uint16 {
	if len(ih.rawData) >= 0x12 {
		return binary.LittleEndian.Uint16(ih.rawData[0x10:])
	}
	return 0
}

func (ih *imageHeader) crcData() []byte {
	if len(ih.rawData) >= 0x52 {
		return ih.rawData[0x12:0x52]
	}
	return []byte{}
}

func newImageHeader(rawData []byte, key [4]byte) (*imageHeader, error) {
	hdr := &imageHeader{
		rawData: rawData,
	}

	for i, _ := range hdr.rawData {
		hdr.rawData[i] = hdr.rawData[i] ^ key[i%4] ^ byte(i)
	}

	hdr.idx = hdr.rawData[3]

	hdr.size = binary.LittleEndian.Uint32(hdr.rawData[4:8])

	return hdr, nil
}

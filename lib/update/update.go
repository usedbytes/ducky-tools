// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

type Update struct {
	Name       string
	Version    FWVersion
	IAPVersion IAPVersion
	FileKey    uint32

	APVID, APPID uint16
	IAPVID, IAPPID uint16

	Images     map[ImageNumber]*Image
}

type Image struct {
	CheckCRC uint16
	Data     []byte
	ExtraCRC []byte
	XferKey  []byte
}

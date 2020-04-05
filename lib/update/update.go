// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"fmt"
)

type Update struct {
	Name       string
	Version    FWVersion
	IAPVersion IAPVersion
	FileKey    uint32

	APVID, APPID   uint16
	IAPVID, IAPPID uint16

	Images map[ImageNumber]*Image
}

func (u *Update) String() string {
	str := ""
	str += fmt.Sprintf("Name:             %s\n", u.Name)
	str += fmt.Sprintf("Firmware version: %s\n", u.Version)
	str += fmt.Sprintf("IAP version:      %s\n", u.IAPVersion)
	str += fmt.Sprintf("File Key:         0x%08x\n", u.FileKey)
	str += fmt.Sprintf("AP VID:PID:       %04x:%04x\n", u.APVID, u.APPID)
	str += fmt.Sprintf("IAP VID:PID:      %04x:%04x", u.IAPVID, u.IAPPID)

	for k, v := range u.Images {
		if v == nil {
			continue
		}
		str += "\n"
		str += fmt.Sprintf("Image '%s':\n", k)
		str += v.String()
	}

	return str
}

type Image struct {
	CheckCRC uint16
	Data     []byte
	ExtraCRC []byte
	XferKey  []byte
}

func (i *Image) String() string {
	str := ""
	str += fmt.Sprintf("CheckCRC: 0x%04x\n", i.CheckCRC)
	str += fmt.Sprintf("Data:     (%d bytes)\n", len(i.Data))
	str += fmt.Sprintf("ExtraCRC: (%d bytes)\n", len(i.ExtraCRC))
	str += fmt.Sprintf("XferKey:  (%d bytes)\n", len(i.XferKey))

	return str
}

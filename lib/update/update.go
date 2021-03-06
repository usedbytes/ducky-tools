// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/sigurn/crc16"
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

func (u *Update) Validate() error {
	if u.IAPVersion != IAPVersion100 {
		return errors.Errorf("unsupported IAP Version '%s'", u.IAPVersion)
	}

	for _, v := range u.Images {
		if v == nil {
			continue
		}

		if len(v.XferKey) != 0 {
			crc, err := v.CalculateCheckCRC()
			if err != nil {
				return err
			}

			if v.CheckCRC != 0 && v.CheckCRC != crc {
				return errors.Errorf("calculated CheckCRC doesn't match. Have: 0x%04x, calculated: 0x%04x", v.CheckCRC, crc)
			}
			v.CheckCRC = crc
		}
	}

	return nil
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

func (i *Image) CalculateCheckCRC() (uint16, error) {
	if len(i.XferKey) == 0 {
		return 0, errors.New("XferKey is needed to calculate CheckCRC")
	} else if len(i.XferKey) != 52 {
		return 0, errors.New("XferKey is expected to be to be 52 bytes")
	}

	// Image is always in wire encoding
	data := XORDecode(i.Data, i.XferKey, false)

	// secret is hard-coded in the IAP code
	secret := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	crct := crc16.MakeTable(crc16.CRC16_XMODEM)
	crc := crc16.Checksum(data, crct)
	crc = crc16.Update(crc, secret, crct)

	return crc, nil
}

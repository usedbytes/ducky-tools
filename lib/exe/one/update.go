// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package one

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/sigurn/crc16"

	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/xor"
)

type Update struct {
	Name       string
	Version    config.FWVersion
	IAPVersion config.IAPVersion
	FileKey    uint32

	APVID, APPID   uint16
	IAPVID, IAPPID uint16

	Images map[ImageNumber]*Image
}

func (u *Update) ToConfig() *config.Config {
	cfg := &config.Config{
		Exe: &config.Exe {
			Name: u.Name,
			IAPVersion: &u.IAPVersion,
			FileKey: u.FileKey,
		},
		Devices: []*config.Device{
			&config.Device{
				Name: u.Name,
				Application: &config.Application{
					VID: u.APVID,
					PID: u.APPID,
					Protocol: config.One,
				},
				Bootloader: &config.Application{
					VID: u.IAPVID,
					PID: u.IAPPID,
					Protocol: config.One,
				},
				Firmwares: []*config.Firmware{
					&config.Firmware{
						DeviceName: u.Name,
						Version: &u.Version,
						Images: make(map[string]*config.Image),
					},
				},
			},
		},
	}

	for k, v := range u.Images {
		name := k.String()
		cfg.Devices[0].Firmwares[0].Images[name] = &config.Image{
			CheckCRC: v.CheckCRC,
			Data: v.Data,
			// Image is always XferEncoded in the 'one' code
			XferEncoded: true,
		}

		// XXX: What if the ExtraCRCs are different for different
		// images? The file structure allows it, even if the bootloader
		// doesn't
		if v.ExtraCRC != nil {
			cfg.Devices[0].Bootloader.ExtraCRC = v.ExtraCRC
		}
	}

	cfg.Devices[0].GenerateFilenames()

	return cfg
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
	if u.IAPVersion != config.IAPVersion100 {
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
	data := xor.Decode(i.Data, i.XferKey, false)

	// secret is hard-coded in the IAP code
	secret := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	crct := crc16.MakeTable(crc16.CRC16_XMODEM)
	crc := crc16.Checksum(data, crct)
	crc = crc16.Update(crc, secret, crct)

	return crc, nil
}

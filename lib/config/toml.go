// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package config

import (
	"fmt"
	"strconv"
)

func stringIfNotEmpty(prefix, val string) string {
	if len(val) > 0 {
		return fmt.Sprintf("%s %s\n", prefix, val)
	}
	return ""
}

type Exe struct {
	Name         string      `toml:"name"`
	IAPVersion   *IAPVersion `toml:"iap_version,omitempty"`
	FileKey      uint32      `toml:"file_key,omitempty"`
	ExtraCRCFile string      `toml:"extra_crc_data_file,omitempty"`
	ExtraCRC     []byte      `toml:"-"`
	ByteSwapping bool        `toml:"byte_swapping"`
}

func (e *Exe) String() string {
	var s string
	s += "Exe:\n"
	s += stringIfNotEmpty("   Name:", e.Name)
	if e.IAPVersion != nil {
		s += stringIfNotEmpty("   IAPVersion:", e.IAPVersion.String())
	}
	if e.FileKey != 0 {
		s += fmt.Sprintf("   FileKey: 0x%08x\n", e.FileKey)
	}
	s += stringIfNotEmpty("   ExtraCRCFile:", e.ExtraCRCFile)
	s += fmt.Sprintf("   ByteSwapping: %s\n", strconv.FormatBool(e.ByteSwapping))
	return s
}

type Device struct {
	Name        string       `toml:"name,omitempty"`
	Application *Application `toml:"application,omitempty"`
	Bootloader  *Application `toml:"bootloader,omitempty"`
	Firmwares   []*Firmware  `toml:"firmware,omitempty"`
}

func (d *Device) String() string {
	var s string
	s += "Device:\n"
	s += stringIfNotEmpty("   Name:", d.Name)
	s += fmt.Sprintf("   AP VID:PID: 0x%04x:0x%04x\n", d.Application.VID, d.Application.PID)
	s += fmt.Sprintf("   IAP VID:PID: 0x%04x:0x%04x\n", d.Bootloader.VID, d.Bootloader.PID)
	// TODO: Indentation for Firmwares.
	for _, fw := range d.Firmwares {
		s += fw.String()
	}
	return s
}

type Application struct {
	VID      uint16   `toml:"vid"`
	PID      uint16   `toml:"pid"`
	Protocol Protocol `toml:"protocol,omitempty"`
}

type Firmware struct {
	DeviceName string            `toml:"device_name,omitempty"`
	Name       string            `toml:"name,omitempty"`
	Version    *FWVersion        `toml:"version"`
	Images     map[string]*Image `toml:"images,omitempty"`
}

func (f *Firmware) String() string {
	var s string
	s += "Firmware:\n"
	s += stringIfNotEmpty("   DeviceName:", f.DeviceName)
	s += stringIfNotEmpty("   Name:", f.Name)
	s += stringIfNotEmpty("   Version:", f.Version.String())
	for k, v := range f.Images {
		s += fmt.Sprintf("   Image %s:\n", k)
		if v.CheckCRC != 0 {
			s += fmt.Sprintf("      CheckCRC: 0x%04x\n", v.CheckCRC)
		}
		s += stringIfNotEmpty("      DataFile:", v.DataFile)
		if len(v.Data) != 0 {
			s += fmt.Sprintf("      Size: %d (0x%x) bytes\n", len(v.Data), len(v.Data))
		}
		s += fmt.Sprintf("      XferEncoded: %s\n", strconv.FormatBool(v.XferEncoded))
	}
	return s
}

type Image struct {
	CheckCRC    uint16 `toml:"check_crc,omitempty"`
	DataFile    string `toml:"data_file,omitempty"`
	XferEncoded bool   `toml:"xfer_encoded"`
	Data        []byte `toml:"-"`
}

type Config struct {
	Exe     *Exe      `toml:"exe,omitempty"`
	Devices []*Device `toml:"device,omitempty"`
}

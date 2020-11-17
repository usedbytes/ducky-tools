// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package exe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/pkg/errors"
	"github.com/usedbytes/ducky-tools/lib/config"
)

// Implements an unpacker for the One2-style multi-device multi-image
// FWUpdate.exe

const (
	infoLen int = 0x2b58
	firstSizeOffsetBytes = 0x22d8
	checkStringOffsetBytes = 0x2b4b
	layoutStrideBytes = 0x14 * 4
	deviceStrideBytes = 0x1b8 * 4
	deviceHeaderStrideBytes = 0x28

	numDevices int = 5
	numLayouts = 9
)

func swapBytes(data []byte) {
	// Swap every 5th in blocks of 5
	idx := 4
	i := ((len(data) - 6) / 5) + 1
	for ; i > 0; i-- {
		tmp := data[idx - 4]
		data[idx - 4] = data[idx]
		data[idx] = tmp
		idx += 5
	}

	// Swap every other in blocks of 2
	idx = 1
	i = ((len(data) - 2) / 2) + 1
	for ; i > 0; i-- {
		tmp := data[idx - 1]
		data[idx - 1] = data[idx]
		data[idx] = tmp
		idx += 2
	}

	// Offset and adjust result
	for i := range data {
		data[i] = byte(uint(data[i] - 7) * 16 + uint(data[i] >> 4))
	}
}

func getInfoBlock(rd io.ReadSeeker) ([]byte, error) {
	rd.Seek(-int64(infoLen), 2)

	data := make([]byte, infoLen)
	n, err := rd.Read(data)
	if n != infoLen {
		return nil, fmt.Errorf("wrong read length")
	} else if err != nil {
		return nil, err
	}

	return data, nil
}

type layout struct {
	info []byte
	meta []byte
	data []byte
}

type device struct {
	header []byte
	info []byte

	layouts []layout
}

func utf16BytesToString(a []byte) (string, error) {
	if len(a)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16 length: %d", len(a))
	}
	u16 := make([]uint16, len(a)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(a[i*2]) | uint16(a[i*2+1])<<8
	}
	runes := utf16.Decode(u16)
	return string(runes), nil
}

func readString(b []byte, maxLen int, wide bool) (string, error) {
	var s string
	if wide {
		var err error
		s, err = utf16BytesToString(b[:maxLen])
		if err != nil {
			return "", fmt.Errorf("parsing wide string: %v", err)
		}
	} else {
		s = string(b[:maxLen])
	}

	return strings.TrimRight(s, "\x00"), nil
}

// TODO: This function is a monster and should be broken up
func loadFWUpdateExe(file string) (*config.Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := getInfoBlock(f)
	if err != nil {
		return nil, err
	}

	swapBytes(data)

	// data should end with ".maaV105"
	// The offset is hard-coded, and it's not clear what the meaning of
	// the value is. This might not be stable between versions?
	check := []byte(".maaV105")
	if bytes.Compare(check, data[checkStringOffsetBytes:checkStringOffsetBytes+len(check)]) != 0 {
		return nil, errors.New("couldn't match check string")
	}

	cfg := &config.Config{
		Exe: &config.Exe{
			ByteSwapping: true,
		},
	}

	// After the first device section, there seems to be two bytes of
	// padding containing "00 01", then info about the updater as a whole,
	// which is the same size as deviceStrideBytes
	exeData := data[firstSizeOffsetBytes + layoutStrideBytes + 2:]
	s, err := readString(exeData, 128, true)
	if err != nil {
		return nil, err
	}
	cfg.Exe.Name = s

	s, err = readString(exeData[0x410:], 128, true)
	if err != nil {
		return nil, err
	}
	cfg.Exe.Name += " - " + s

	s, err = readString(exeData[0x208:], 0x30, true)
	if err != nil {
		return nil, err
	}
	iapVersion, err := config.ParseIAPVersion(s[len("IAP Version "):])
	if err != nil {
		return nil, err
	}
	cfg.Exe.IAPVersion = &iapVersion

	var devices []device

	var offset int = -infoLen
	for dev := 0; dev < numDevices; dev++ {
		deviceEnd := (firstSizeOffsetBytes + layoutStrideBytes) - (dev * deviceStrideBytes)
		headerEnd := deviceHeaderStrideBytes * (numDevices - dev)

		device := device{
			header: data[headerEnd - deviceHeaderStrideBytes:headerEnd],
			info: data[deviceEnd - deviceStrideBytes:deviceEnd],
		}

		for lay := 0; lay < numLayouts; lay++ {
			layoutEnd := len(device.info) - lay * layoutStrideBytes
			layout := layout{
				info: device.info[layoutEnd - layoutStrideBytes:layoutEnd],
			}

			metaSize := binary.LittleEndian.Uint32(layout.info[4:])
			if metaSize != 0 {
				layout.meta = make([]byte, metaSize)
				offset -= int(metaSize)
				f.Seek(int64(offset), 2)
				n, err := f.Read(layout.meta)
				if n != int(metaSize) {
					return nil, fmt.Errorf("short read: device %d layout %d metadata", dev, lay)
				} else if err != nil {
					return nil, err
				}
				swapBytes(layout.meta)
			}

			dataSize := binary.LittleEndian.Uint32(layout.info[:4])
			if dataSize != 0 {
				layout.data = make([]byte, dataSize)
				offset -= int(dataSize)
				f.Seek(int64(offset), 2)
				n, err := f.Read(layout.data)
				if n != int(dataSize) {
					return nil, fmt.Errorf("short read: device %d layout %d data", dev, lay)
				} else if err != nil {
					return nil, err
				}
				swapBytes(layout.data)
			}

			if metaSize != 0 || dataSize != 0 {
				device.layouts = append(device.layouts, layout)
			}
		}

		if len(device.layouts) != 0 {
			devices = append(devices, device)
		}
	}

	for _, d := range devices {
		cfgDev := &config.Device{ }

		// No idea what the right length is for any of the strings.
		// I've made conservative guesses based on the empty space in
		// the example I have
		s, err = readString(d.info, 128, true)
		if err != nil {
			return nil, err
		}
		cfgDev.Name = s

		cfgDev.Application = &config.Application{
			VID: uint16(binary.LittleEndian.Uint32(d.header[0x1c:])),
			PID: uint16(binary.LittleEndian.Uint32(d.header[0x20:])),
			Protocol: config.One2,
		}

		cfgDev.Bootloader = &config.Application{
			VID: uint16(binary.LittleEndian.Uint32(d.header[0x14:])),
			PID: uint16(binary.LittleEndian.Uint32(d.header[0x18:])),
			Protocol: config.One2,
		}

		s, err = readString(d.info[0x208:], 128, true)
		if err != nil {
			return nil, err
		}
		fwv, err := config.ParseFWVersion(s)
		if err != nil {
			return nil, err
		}

		cfg.Devices = append(cfg.Devices, cfgDev)

		for _, l := range d.layouts {
			fw := &config.Firmware{
				Version: &fwv,
				Images: make(map[string]*config.Image),
			}

			s, err := readString(l.info[0x8:], 0x28, true)
			if err != nil {
				return nil, err
			}
			fw.Name = s
			fw.DeviceName = cfgDev.Name

			fw.Images[string(config.Metadata)] = &config.Image{
				Data: l.meta,
			}
			fw.Images[string(config.Internal)] = &config.Image{
				Data: l.data,
			}

			fw.GenerateFilenames()

			cfg.Firmwares = append(cfg.Firmwares, fw)
		}
	}

	fmt.Println(cfg)

	return cfg, nil
}

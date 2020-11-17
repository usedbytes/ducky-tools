// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package one

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/pkg/errors"
	"github.com/usedbytes/ducky-tools/lib/config"
)

type fileHeader struct {
	fileKey        [4]byte
	apVID, apPID   uint16
	iapVID, iapPID uint16
	wchars         bool
	fwVersion      config.FWVersion
	iapVersion     config.IAPVersion
	name           string
	layout         string

	rawData []byte
}

func utf16BytesToString(a []byte) (string, error) {
	if len(a)%2 != 0 {
		return "", fmt.Errorf("Invalid UTF-16 length: %d", len(a))
	}
	u16 := make([]uint16, len(a)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(a[i*2]) | uint16(a[i*2+1])<<8
	}
	runes := utf16.Decode(u16)
	return string(runes), nil
}

func readString(b []byte, maxLen int, wide bool) string {
	var s string
	if wide {
		var err error
		s, err = utf16BytesToString(b[:maxLen])
		if err != nil {
			fmt.Println("WARNING: Failed parsing wide string", err)
		}
	} else {
		s = string(b[:maxLen])
	}

	return strings.TrimRight(s, "\x00")
}

func (fh *fileHeader) decodeFirmwareVersion() error {
	str := readString(fh.rawData[0x28:], 128, fh.wchars)

	fwv, err := config.ParseFWVersion(str)
	if err != nil {
		return err
	}

	fh.fwVersion = fwv
	return nil
}

func (fh *fileHeader) decodeIAPVersion() error {
	prefix := "IAP Version "
	str := readString(fh.rawData[0x128:], 0x80, fh.wchars)

	if !strings.HasPrefix(str, prefix) {
		return fmt.Errorf("Can't parse: '%s'", str)
	}
	str = strings.TrimPrefix(str, prefix)

	v, err := config.ParseIAPVersion(str)
	fh.iapVersion = v

	return err
}

func (fh *fileHeader) crcValue() uint16 {
	if len(fh.rawData) > 0x228+0x44 {
		return binary.LittleEndian.Uint16(fh.rawData[0x228:])
	}
	return 0
}

func (fh *fileHeader) crcData() []byte {
	if len(fh.rawData) > 0x228+0x44 {
		return fh.rawData[0x22a:0x26a]
	}
	return []byte{}
}

func hexByteString(a []byte) string {
	var chars []string
	for _, v := range a {
		chars = append(chars, fmt.Sprintf("%2x", v))
	}
	return strings.Join(chars, " ")
}

func (fh fileHeader) String() string {
	str := ""
	str += fmt.Sprintf("Firmware version: %s\n", fh.fwVersion)
	str += fmt.Sprintf("Name:             %s\n", fh.name)
	str += fmt.Sprintf("IAP version:      %s\n", fh.iapVersion)
	str += fmt.Sprintf("Layout:           %s\n", fh.layout)
	str += fmt.Sprintf("File Key:         %s", hexByteString(fh.fileKey[:]))
	return str
}

func newFileHeader(rawData []byte) (*fileHeader, error) {
	hdr := &fileHeader{
		rawData: rawData,
	}

	// This isn't the method the proprietary code uses, but this is
	// simpler, assuming the first 4 bytes are always the Holtek VID
	// This doesn't leave the data in the exact same state as the
	// proprietary code, as the "check values" aren't modified in the same
	// way, but they don't appear to be used anywhere in the updater.
	vid := [4]byte{'0', '4', 'D', '9'}
	for i, _ := range hdr.rawData[:4] {
		hdr.fileKey[i] = hdr.rawData[i] ^ vid[i] ^ byte(i)
	}

	for i, _ := range hdr.rawData {
		hdr.rawData[i] = hdr.rawData[i] ^ hdr.fileKey[i%4] ^ byte(i)
	}

	tmp, err := strconv.ParseUint(string(hdr.rawData[:4]), 16, 16)
	if err != nil {
		return nil, errors.Wrap(err, "Parsing AP VID")
	}
	hdr.apVID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[8:12]), 16, 16)
	if err != nil {
		return nil, errors.Wrap(err, "Parsing AP PID")
	}
	hdr.apPID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[20:24]), 16, 16)
	if err != nil {
		return nil, errors.Wrap(err, "Parsing IAP VID")
	}
	hdr.iapVID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[28:32]), 16, 16)
	if err != nil {
		return nil, errors.Wrap(err, "Parsing IAP PID")
	}
	hdr.iapPID = uint16(tmp)

	hdr.wchars = (hdr.rawData[41] == 0)

	err = hdr.decodeFirmwareVersion()
	if err != nil {
		return nil, errors.Wrap(err, "Decoding firmware version")
	}

	hdr.name = readString(hdr.rawData[168:], 128, hdr.wchars)

	err = hdr.decodeIAPVersion()
	if err != nil {
		return nil, errors.Wrap(err, "Decoding IAP version")
	}

	if !hdr.iapVersion.Matches(config.NewIAPVersion(1, 0, 0)) {
		return nil, fmt.Errorf("Unsupported IAP version: %s", hdr.iapVersion)
	}

	hdr.layout = readString(hdr.rawData[424:], 128, hdr.wchars)

	return hdr, nil
}

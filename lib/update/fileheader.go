// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/pkg/errors"
)

type fileHeader struct {
	fileKey        [4]byte
	apVID, apPID   uint16
	iapVID, iapPID uint16
	headerVersion  HeaderVersion
	wchars         bool
	fwVersion      FWVersion
	iapVersion     IAPVersion
	name           string
	layout         string

	rawData []byte
}

type HeaderVersion int

const (
	V1 HeaderVersion = 1
	V2               = 2
)

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

type IAPVersion struct {
	a, b, c int
}

func (iapv IAPVersion) Matches(other IAPVersion) bool {
	return iapv.a == other.a && iapv.b == other.b && iapv.c == other.c
}

func (iapv IAPVersion) String() string {
	return fmt.Sprintf("v%0d.%0d.%0d", iapv.a, iapv.b, iapv.c)
}

var hvsRE *regexp.Regexp = regexp.MustCompile("V([0-9])\\.")

func (fh *fileHeader) decodeHeaderVersion() (int, error) {
	fh.wchars = (fh.rawData[0x29] == 0)
	hvsLen := bytes.Index(fh.rawData[0x28:], []byte{'.'}) + 1
	if fh.wchars {
		hvsLen++
	}

	str := readString(fh.rawData[0x28:], hvsLen, fh.wchars)
	matches := hvsRE.FindStringSubmatch(str)
	if len(matches) != 2 {
		return 0, fmt.Errorf("Can't parse: '%s'", str)
	}
	tmp, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("Can't parse: '%s'", str)
	}
	fh.headerVersion = HeaderVersion(tmp)

	return hvsLen, nil
}

func (fh *fileHeader) decodeFirmwareVersion(start int) error {
	str := readString(fh.rawData[start:], 0xa8-start, fh.wchars)
	var val float64
	n, err := fmt.Sscanf(str, "%f", &val)
	if n != 1 || err != nil {
		return fmt.Errorf("Can't parse: '%s'", str)
	}

	major, minor := math.Modf(val)

	fh.fwVersion = FWVersion{
		major:    int(math.Floor(major)),
		minor100: int(math.Floor(minor * 100)),
	}
	return nil
}

var iapRE *regexp.Regexp = regexp.MustCompile("IAP Version V([0-9]+)\\.([0-9]+)\\.([0-9]+)")

func (fh *fileHeader) decodeIAPVersion() error {
	str := readString(fh.rawData[0x128:], 0x80, fh.wchars)

	matches := iapRE.FindStringSubmatch(str)
	if len(matches) != 4 {
		return fmt.Errorf("Can't parse: '%s'", str)
	}
	a, err := strconv.Atoi(matches[1])
	if err != nil {
		return fmt.Errorf("Can't parse: '%s'", str)
	}
	b, err := strconv.Atoi(matches[2])
	if err != nil {
		return fmt.Errorf("Can't parse: '%s'", str)
	}
	c, err := strconv.Atoi(matches[3])
	if err != nil {
		return fmt.Errorf("Can't parse: '%s'", str)
	}

	fh.iapVersion = IAPVersion{a: a, b: b, c: c}

	return nil
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

func (fh fileHeader) String() string {
	str := ""
	str += fmt.Sprintf("Header version:   V%d\n", fh.headerVersion)
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

	hvsLen, err := hdr.decodeHeaderVersion()
	if err != nil {
		return nil, errors.Wrap(err, "Decoding header version")
	}

	err = hdr.decodeFirmwareVersion(0x28 + hvsLen)
	if err != nil {
		return nil, errors.Wrap(err, "Decoding firmware version")
	}

	hdr.name = readString(hdr.rawData[168:], 128, hdr.wchars)

	err = hdr.decodeIAPVersion()
	if err != nil {
		return nil, errors.Wrap(err, "Decoding IAP version")
	}

	if !hdr.iapVersion.Matches(IAPVersion{1, 0, 0}) {
		return nil, fmt.Errorf("Unsupported IAP version: %s", hdr.iapVersion)
	}

	hdr.layout = readString(hdr.rawData[424:], 128, hdr.wchars)

	return hdr, nil
}

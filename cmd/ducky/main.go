// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/log"
)

type FWVersion struct {
	major, minor100 int
}

func (fwv FWVersion) Matches(other FWVersion) bool {
	return fwv.major == other.major && fwv.minor100 == other.minor100
}

func (fwv FWVersion) String() string {
	return fmt.Sprintf("v%.2f", float64(fwv.major)+float64(fwv.minor100)/100)
}

type Version struct {
	version   FWVersion
	headerLen int
	chunkLen  int
}

var versions map[string]*Version = map[string]*Version{
	"1.01": &Version{
		version: FWVersion{
			major:    1,
			minor100: 1,
		},
		headerLen: 0x23c,
		chunkLen:  0x54,
	},
	"1.03r": &Version{
		version: FWVersion{
			major:    1,
			minor100: 3,
		},
		headerLen: 0x288,
		chunkLen:  0x10,
	},
}

func hexByteString(a []byte) string {
	var chars []string
	for _, v := range a {
		chars = append(chars, fmt.Sprintf("%2x", v))
	}
	return strings.Join(chars, " ")
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
	if wide {
		s, err := utf16BytesToString(b[:maxLen])
		if err != nil {
			fmt.Println("WARNING: Failed parsing wide string", err)
		}
		return s
	}
	return string(b[:maxLen])
}

type HeaderVersion int

const (
	V1 HeaderVersion = 1
	V2               = 2
)

type IAPVersion struct {
	a, b, c int
}

func (iapv IAPVersion) Matches(other IAPVersion) bool {
	return iapv.a == other.a && iapv.b == other.b && iapv.c == other.c
}

func (iapv IAPVersion) String() string {
	return fmt.Sprintf("v%0d.%0d.%0d", iapv.a, iapv.b, iapv.c)
}

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

type imageHeader struct {
	idx     uint32
	size    uint32
	rawData []byte
}

type Update struct {
	version                  *Version
	fileHdr                  *fileHeader
	internalHdr, externalHdr *imageHeader
}

type ImageNumber int

const (
	Internal ImageNumber = iota
	External
)

func NewUpdate(version string) *Update {
	v := versions[version]
	if v.headerLen == 0 {
		return nil
	}
	return &Update{
		version: v,
	}
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

func (fh fileHeader) String() string {
	str := ""
	str += fmt.Sprintf("Header version:   V%d\n", fh.headerVersion)
	str += fmt.Sprintf("Firmware version: %s\n", fh.fwVersion)
	str += fmt.Sprintf("Name:             %s\n", fh.name)
	str += fmt.Sprintf("IAP version:      %s\n", fh.iapVersion)
	str += fmt.Sprintf("Layout:           %s\n", fh.layout)
	str += fmt.Sprintf("File Key:         %s\n", hexByteString(fh.fileKey[:]))
	return str
}

func (u *Update) loadFileHeader(f *os.File) error {
	_, err := f.Seek(-int64(u.version.headerLen), 2)
	if err != nil {
		return errors.Wrap(err, "Seeking file header")
	}

	hdr := &fileHeader{
		rawData: make([]byte, u.version.headerLen),
	}
	n, err := f.Read(hdr.rawData)
	if n != len(hdr.rawData) || err != nil {
		return errors.Wrap(err, "Reading file header")
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
		return errors.Wrap(err, "Parsing AP VID")
	}
	hdr.apVID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[8:12]), 16, 16)
	if err != nil {
		return errors.Wrap(err, "Parsing AP PID")
	}
	hdr.apVID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[20:24]), 16, 16)
	if err != nil {
		return errors.Wrap(err, "Parsing IAP VID")
	}
	hdr.iapVID = uint16(tmp)

	tmp, err = strconv.ParseUint(string(hdr.rawData[28:32]), 16, 16)
	if err != nil {
		return errors.Wrap(err, "Parsing IAP PID")
	}
	hdr.iapVID = uint16(tmp)

	hvsLen, err := hdr.decodeHeaderVersion()
	if err != nil {
		return errors.Wrap(err, "Decoding header version")
	}

	err = hdr.decodeFirmwareVersion(0x28 + hvsLen)
	if err != nil {
		return errors.Wrap(err, "Decoding firmware version")
	}

	if !hdr.fwVersion.Matches(u.version.version) {
		return fmt.Errorf("Expected firmware version %s but got %s", u.version.version, hdr.fwVersion)
	}

	hdr.name = readString(hdr.rawData[168:], 128, hdr.wchars)

	err = hdr.decodeIAPVersion()
	if err != nil {
		return errors.Wrap(err, "Decoding IAP version")
	}

	if !hdr.iapVersion.Matches(IAPVersion{1, 0, 0}) {
		return fmt.Errorf("Unsupported IAP version: %s", hdr.iapVersion)
	}

	hdr.layout = readString(hdr.rawData[424:], 128, hdr.wchars)

	u.fileHdr = hdr
	log.Println(hdr)

	return nil
}

func (u *Update) loadImageHeader(f *os.File, num ImageNumber) error {
	_, err := f.Seek(-int64(u.version.headerLen+u.version.chunkLen*int(num+1)), 2)
	if err != nil {
		return errors.Wrap(err, "Seeking image header")
	}

	hdr := &imageHeader{
		rawData: make([]byte, u.version.chunkLen),
	}
	n, err := f.Read(hdr.rawData)
	if n != len(hdr.rawData) || err != nil {
		return errors.Wrap(err, "Reading image header")
	}

	for i, _ := range hdr.rawData {
		hdr.rawData[i] = hdr.rawData[i] ^ u.fileHdr.fileKey[i%4] ^ byte(i)
	}

	switch num {
	case Internal:
		u.internalHdr = hdr
	case External:
		u.externalHdr = hdr
	default:
		return fmt.Errorf("Unrecognised image number")
	}

	return nil
}

func (u *Update) Load(f *os.File) error {

	err := u.loadFileHeader(f)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(u.fileHdr.rawData))

	err = u.loadImageHeader(f, Internal)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(u.internalHdr.rawData))

	err = u.loadImageHeader(f, External)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(u.externalHdr.rawData))

	return nil
}

func run(ctx *cli.Context) error {
	u := NewUpdate(ctx.String("version"))
	if u == nil {
		return fmt.Errorf("Unrecognised version '%s'", ctx.String("version"))
	}

	if ctx.Args().Len() != 1 {
		return fmt.Errorf("INPUT_FILE is required")
	}

	f, err := os.Open(ctx.Args().First())
	defer f.Close()
	if err != nil {
		return errors.Wrap(err, "Opening input file")
	}

	err = u.Load(f)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:      "ducky",
		Usage:     "A tool for working with Ducky One firmware udpates",
		ArgsUsage: "INPUT_FILE",
		// Just ignore errors - we'll handle them ourselves in main()
		ExitErrHandler: func(c *cli.Context, e error) {},
		Action:         run,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "verbose",
				Aliases:  []string{"v"},
				Usage:    "Enable more output",
				Required: false,
				Value:    true,
			},
			&cli.StringFlag{
				Name:     "version",
				Aliases:  []string{"V"},
				Usage:    "Specify the version number of the updater",
				Required: false,
				Value:    "1.03r",
			},
		},
	}

	app.Before = func(ctx *cli.Context) error {
		log.SetUseLog(false)

		log.SetVerbose(ctx.Bool("verbose"))
		log.Verboseln("Extra output enabled.")
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Println("ERROR:", err)
		if v, ok := err.(cli.ExitCoder); ok {
			os.Exit(v.ExitCode())
		} else {
			os.Exit(1)
		}
	}
}

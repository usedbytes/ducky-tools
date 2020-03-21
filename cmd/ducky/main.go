// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	//"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/log"
)

type Version struct {
	headerLen int
	chunkLen  int
}

var versions map[string]*Version = map[string]*Version{
	"1.01": &Version{
		headerLen: 0x23c,
		chunkLen:  0x54,
	},
	"1.03r": &Version{
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

type fileHeader struct {
	fileKey [4]byte
	rawData []byte
}

type imageHeader struct {
	idx uint32
	size uint32
	rawData []byte
}

type Update struct {
	version *Version
	fileHdr *fileHeader
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

	log.Verboseln("FileKey:", hexByteString(hdr.fileKey[:]))

	for i, _ := range hdr.rawData {
		hdr.rawData[i] = hdr.rawData[i] ^ hdr.fileKey[i%4] ^ byte(i)
	}

	// TODO: Extract the fields
	u.fileHdr = hdr

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

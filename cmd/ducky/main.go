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

func readAndDecodeHeader(f *os.File, version *Version) (*fileHeader, error) {
	_, err := f.Seek(-int64(version.headerLen), 2)
	if err != nil {
		return nil, errors.Wrap(err, "Seeking header")
	}

	hdr := &fileHeader{
		rawData: make([]byte, version.headerLen),
	}
	n, err := f.Read(hdr.rawData)
	if n != len(hdr.rawData) || err != nil {
		return nil, errors.Wrap(err, "Reading header")
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

	return hdr, nil
}

func readRawChunk(f *os.File, version *Version, num int, fileKey [4]byte) ([]byte, error) {
	_, err := f.Seek(-int64(version.headerLen+version.chunkLen*num), 2)
	if err != nil {
		return nil, errors.Wrap(err, "Seeking chunk")
	}

	rawData := make([]byte, version.chunkLen)
	n, err := f.Read(rawData)
	if n != len(rawData) || err != nil {
		return nil, errors.Wrap(err, "Reading chunk")
	}

	for i, _ := range rawData {
		rawData[i] = rawData[i] ^ fileKey[i%4] ^ byte(i)
	}

	return rawData, nil
}

func run(ctx *cli.Context) error {
	vstr := ctx.String("version")
	version := versions[vstr]
	if version.headerLen == 0 {
		return fmt.Errorf("Unrecognised version '%s'", vstr)
	}

	if ctx.Args().Len() != 1 {
		return fmt.Errorf("INPUT_FILE is required")
	}

	f, err := os.Open(ctx.Args().First())
	defer f.Close()
	if err != nil {
		return errors.Wrap(err, "Opening input file")
	}

	hdr, err := readAndDecodeHeader(f, version)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(hdr.rawData))

	chunk1, err := readRawChunk(f, version, 1, hdr.fileKey)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(chunk1))

	chunk2, err := readRawChunk(f, version, 2, hdr.fileKey)
	if err != nil {
		return err
	}

	log.Println(hex.Dump(chunk2))

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

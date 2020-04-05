// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/iap"
	"github.com/usedbytes/ducky-tools/lib/update"
	"github.com/usedbytes/log"

	"github.com/sigurn/crc16"
)

func loadUpdateFile(ctx *cli.Context) (*update.Update, string, error) {
	if ctx.Args().Len() != 1 {
		return nil, "", fmt.Errorf("INPUT_FILE is required")
	}
	fname := ctx.Args().First()

	var u *update.Update
	var err error

	ext := filepath.Ext(fname)
	switch ext {
	case ".exe":
		ver := ctx.String("version")
		// Attempt to automatically get the version, based on Ducky's file
		// naming convention
		if !ctx.IsSet("version") {
			ver, err = update.ParseExeVersion(fname)
			if err != nil {
				return nil, "", err
			}
		}

		u, err = update.LoadExeUpdate(fname, ver)
		if err != nil {
			return nil, "", err
		}
	case ".toml":
		u, err = update.LoadTOMLUpdate(fname)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", errors.New("unrecognised file extension")
	}

	err = u.Validate()
	if err != nil {
		return nil, "", err
	}

	log.Verbosef("Update loaded:\n%s", u)

	return u, filepath.Base(fname), nil
}

func extractAction(ctx *cli.Context) error {
	u, fname, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if ctx.IsSet("out") {
		fname = ctx.String("out")
	} else {
		fname = filepath.Base(fname)
		if filepath.Ext(fname) != ".toml" {
			fname = fname + ".toml"
		}
	}
	u.Name = filepath.Base(fname)

	if ctx.IsSet("xferkey") {
		key, err := ioutil.ReadFile(ctx.String("xferkey"))
		if err != nil {
			return err
		}

		for _, v := range u.Images {
			if len(v.XferKey) == 0 {
				v.XferKey = key
			}
		}
	}

	err = u.WriteTOML(fname)
	if err != nil {
		return err
	}

	log.Println("Wrote to", fname)

	return nil
}

func extractKeyAction(ctx *cli.Context) error {
	u, _, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	img := u.Images[update.Internal]
	if len(img.Data) == 0 {
		return errors.New("no data for internal image")
	}

	counts := [52][256]int{}

	// Count occurrence
	for i := 0; i < len(img.Data); i += 52 {
		for j := 0; j < 52 && i+j < len(img.Data); j++ {
			val := img.Data[i+j]
			counts[j][val] = counts[j][val] + 1
		}
	}

	// Find max occurrence
	maxVals := [52]byte{}
	for i, val := range counts {
		maxVal := 0
		maxIdx := 0
		for j, v := range val {
			if v > maxVal {
				maxVal = v
				maxIdx = j
			}
		}
		maxVals[i] = byte(maxIdx)
	}

	// Expect the last couple of chunks to be zeroes (not guaranteed)
	idx := ((len(img.Data) / 52) - 1) * 52
	a := img.Data[idx:idx+52]
	b := img.Data[idx+52:]
	key := [52]byte{}
	fixedUp := false

	for i := 0; i < 52; i++ {
		// TODO: This could be smarter.
		if maxVals[i] != a[i] {
			fixedUp = true
			log.Verbosef("maxVal[%d] (%d) != a[%d] (%d) %d\n", i, maxVals[i], i, a[i], len(b))
			if i < len(b) {
				if a[i] == b[i] {
					key[i] = a[i]
					log.Verbosef("Using a[%d] (%d)\n", i, a[i])
				} else if maxVals[i] == b[i] {
					log.Verbosef("Keeping maxVals[%d] (%d), matches b[%d]\n", i, maxVals[i], i)
					key[i] = maxVals[i]
				} else {
					log.Verbosef("Keeping maxVals[%d] (%d), all different: %d %d %d\n",
							i, maxVals[i], maxVals[i], a[i], b[i])
					key[i] = maxVals[i]
				}
			} else {
				countA := counts[i][a[i]]

				// Sorting destroys the indexing, so need to make a copy
				sorted := append([]int(nil), counts[i][:]...)
				sort.Ints(sorted)
				idx := sort.SearchInts(sorted, countA)
				if idx > 250 {
					log.Verbosef("Using a[%d] (%d), sorted at position %d\n", i, a[i], 256 - idx)
					key[i] = a[i]
				} else {
					log.Verbosef("Keeping maxVals[%d] (%d), a[%d] sorted at position %d\n",
							i, maxVals[i], i, a[i], 256 - idx)
					key[i] = maxVals[i]
				}
			}
		} else {
			key[i] = maxVals[i]
		}
	}

	if fixedUp {
		log.Println("WARNING: Some values were ambiguous")
	}

	fmt.Println(hex.Dump(key[:]))

	if ctx.IsSet("out") {
		err := ioutil.WriteFile(ctx.String("out"), key[:], 0644)
		if err != nil {
			return err
		}
		log.Println("Wrote to", ctx.String("out"))
	}

	return nil
}

func iapTestAction(ctx *cli.Context) error {
	log.Println(">>> Loading update file...")
	u, _, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	vid, pid := u.APVID, u.APPID

	log.Println(">>> Connecting in AP mode...")
	iapCtx, err := iap.NewContext(uint16(vid), uint16(pid))
	if err != nil {
		return err
	}
	defer iapCtx.Close()

	log.Print(">>> Attempt Ping... ")
	pong, _ := iapCtx.Ping(42)
	log.Println("pong")

	log.Println(">>> Get Version:")
	fwv, err := iapCtx.APGetVersion()
	if err != nil {
		return err
	}

	log.Println(fwv)
	if !u.Version.Compatible(fwv) {
		return fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.Version, fwv)
	}

	log.Println(">>> Reset to IAP mode...")
	iapCtx.Reset(false)

	log.Println(">>> Connecting in IAP mode...")
	vid, pid = u.IAPVID, u.IAPPID
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		iapCtx, err = iap.NewContext(vid, pid)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}

	defer func() {
		log.Println("Reset back to AP mode...")
		iapCtx.Reset(false)
	}()

	img := u.Images[update.Internal]

	iapCtx.SetExtraCRCData(img.ExtraCRC)

	info, err := iapCtx.GetInformation()
	if err != nil {
		return err
	}

	log.Println(">>> Info:")
	log.Println(info.String())

	fwv2, err := iapCtx.GetVersion(info)
	if err != nil {
		return err
	}

	log.Println(">>> Version:", fwv2)
	if !fwv2.Matches(fwv) {
		return fmt.Errorf("version inconsistent. AP: %s, IAP: %s", fwv, fwv2)
	}

	log.Print(">>> Attempt Ping (should time out)... ")
	pong, err = iapCtx.Ping(42)
	if pong && err != nil {
		return errors.New("Ping() shouldn't work in IAP mode")
	}
	log.Println("timed out")

	return nil
}

func enterIAP(u *update.Update) (*iap.Context, error) {
	vid, pid := u.IAPVID, u.IAPPID
	iapCtx, err := iap.NewContext(vid, pid)
	if err != nil {
		v, p := u.APVID, u.APPID
		iapCtx, err = iap.NewContext(v, p)
		if err != nil {
			return nil, err
		}
		// This is redundant if we reach the .Reset(), but Close-ing
		// twice is fine
		defer iapCtx.Close()

		fwv, err := iapCtx.APGetVersion()
		if err != nil {
			return nil, err
		}
		if !u.Version.Compatible(fwv) {
			return nil, fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.Version, fwv)
		}

		iapCtx.Reset(true)

		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			iapCtx, err = iap.NewContext(vid, pid)
			if err == nil {
				return iapCtx, nil
			}
		}
	}

	return iapCtx, err
}

func updateAction(ctx *cli.Context) error {
	u, _, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	iapCtx, err := enterIAP(u)
	if err != nil {
		return err
	}
	defer iapCtx.Reset(false)

	img := u.Images[update.Internal]

	iapCtx.SetExtraCRCData(img.ExtraCRC)

	info, err := iapCtx.GetInformation()
	if err != nil {
		return err
	}

	log.Println("Device Info:")
	log.Println(info)

	fwv, err := iapCtx.GetVersion(info)
	if err != nil {
		if !iap.IsVersionErased(err) {
			return err
		}

		if !ctx.Bool("force") {
			return errors.New("version string appears to be erased. Use --force to skip this check (DANGEROUS!)")
		}

		log.Println("!!! Version already erased. --force skipping")
	} else {
		log.Println("Device Version:", fwv)
		if !u.Version.Compatible(fwv) {
			return fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.Version, fwv)
		}
	}

	log.Println(">>> Erase version...")
	err = iapCtx.EraseVersion(info, ctx.Bool("force"))
	if err != nil {
		return err
	}

	err = iapCtx.CheckStatus(-1)
	if err != nil {
		return err
	}

	fw := img.Data
	addr := info.StartAddr()

	log.Println(">>> Erase program...")
	err = iapCtx.ErasePage(addr, len(fw))
	if err != nil {
		return err
	}

	err = iapCtx.CheckStatus(1)
	if err != nil {
		return err
	}

	log.Println(">>> Write program...")
	i := 0
	chunkLen := 0x34
	for start := 0; start < len(fw); start += chunkLen {
		end := start + chunkLen
		if end > len(fw) {
			end = len(fw)
		}

		err = iapCtx.WriteData(addr, fw[start:end])
		if err != nil {
			return err
		}

		i++
		if i >= 16 {
			err = iapCtx.CheckStatus(i)
			if err != nil {
				return err
			}
			i = 0
		}
		addr += uint32(chunkLen)
	}

	err = iapCtx.CheckStatus(i)
	if err != nil {
		return err
	}

	log.Println(">>> Check CRC...")

	crc := img.CheckCRC
	_, err = iapCtx.CRCCheck(info.StartAddr(), 1, crc)
	if err != nil {
		return err
	}
	// CRCCheck() will drain the status buffer

	log.Println(">>> Write version...")
	err = iapCtx.WriteVersion(info, u.Version)
	if err != nil {
		return err
	}

	err = iapCtx.CheckStatus(1)
	if err != nil {
		return err
	}

	log.Println(">>> Success!")

	return nil

}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dumpAction(ctx *cli.Context) error {
	u, _, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	// Force a reset to make sure we have a clean slate
	iapCtx, err := enterIAP(u)
	if err != nil {
		return err
	}
	iapCtx.Reset(true)

	iapCtx, err = enterIAP(u)
	if err != nil {
		return err
	}
	defer iapCtx.Reset(false)

	img := u.Images[update.Internal]

	iapCtx.SetExtraCRCData(img.ExtraCRC)

	info, err := iapCtx.GetInformation()
	if err != nil {
		return err
	}

	log.Println("Device Info:")
	log.Println(info)

	err = iapCtx.CheckStatus(-1)
	if err != nil {
		return err
	}

	crct := crc16.MakeTable(crc16.CRC16_XMODEM)
	lu := make(map[uint16]byte)
	for i := 0; i < 256; i++ {
		crc := crc16.Checksum([]byte{byte(i)}, crct)
		lu[crc] = byte(i)
	}

	if len(lu) != 256 {
		return errors.New("CRC table isn't 256 long")
	}

	// The CRC we send has to match the expected value, which is updated in
	// two ways:
	// 1) On each invocation of WriteData(..., data):
	//     crc = crc16.Update(crc, XORDecode(data), crc16.MakeTable(crc16.CRC16_XMODEM))
	// 2) On each invocation of CRCCheck():
	//     crc = crc16.Update(crc, secret, crc16.MakeTable(crc16.CRC16_XMODEM))
	// We're running on a clean reset and never call WriteData(), so we just
	// need to update according to the CRCCheck() path.
	//
	// If the check fails, the firmware will be erased!

	// crc is initialised to zero at boot
	crc := uint16(0)

	// secret is hard-coded in the IAP code
	secret := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	dump := make([]byte, 16)

	start := ctx.Int("start")
	end := start + ctx.Int("length")
	log.Printf(">>> Dump range [0x%08x:0x%08x):\n", start, end)

	var f *os.File
	fname := ctx.String("outfile")
	if len(fname) != 0 {
		f, err = os.Create(fname)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	for addr, i := start, 0; addr < end; addr, i = addr+1, i+1 {
		if i%16 == 0 {
			if i > 0 {
				log.Print("\n")
				if f != nil {
					n, err := f.Write(dump)
					if err != nil {
						return err
					} else if n != len(dump) {
						return errors.New("short write to outfile")
					}
				}
			}
			log.Printf("%08x  ", addr)

			dump = dump[:0]
			i = 0
		}

		crc = crc16.Update(crc, secret, crct)

		xcrc, err := iapCtx.CRCCheck(uint32(addr), 1, crc)
		if err != nil {
			return err
		}

		val := lu[xcrc]

		log.Printf("%02x ", val)

		dump = append(dump, val)
	}
	log.Print("\n")
	if f != nil {
		n, err := f.Write(dump)
		if err != nil {
			return err
		} else if n != len(dump) {
			return errors.New("short write to outfile")
		}
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:  "ducky",
		Usage: "A tool for working with Ducky One firmware udpates",
		// Just ignore errors - we'll handle them ourselves in main()
		ExitErrHandler: func(c *cli.Context, e error) {},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "verbose",
				Aliases:  []string{"v"},
				Usage:    "Enable more output",
				Required: false,
				Value:    false,
			},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:      "extract",
			ArgsUsage: "INPUT_FILE",
			Action:    extractAction,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "version",
					Aliases:  []string{"V"},
					Usage:    "Specify the updater version if it can't be found automatically",
					Required: false,
					Value:    "1.03r",
				},
				&cli.StringFlag{
					Name:     "out",
					Aliases:  []string{"o"},
					Usage:    "Output filename (.toml)",
					Required: false,
				},
				&cli.StringFlag{
					Name:     "xferkey",
					Aliases:  []string{"x"},
					Usage:    "File containing the 52-byte transfer key (for decoding FW)",
					Required: false,
				},
			},
		},
		{
			Name:      "extractkey",
			ArgsUsage: "INPUT_FILE",
			Usage:     "Attempt to extract the xfer key via some heuristic analysis",
			Action:    extractKeyAction,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "version",
					Aliases:  []string{"V"},
					Usage:    "Specify the updater version if it can't be found automatically",
					Required: false,
					Value:    "1.03r",
				},
				&cli.StringFlag{
					Name:     "out",
					Aliases:  []string{"o"},
					Usage:    "Output filename (.bin)",
					Required: false,
				},
			},
		},
		{
			Name: "iap",
			Subcommands: []*cli.Command{
				{
					Name:      "test",
					ArgsUsage: "INPUT_FILE",
					Action:    iapTestAction,
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "version",
							Aliases:  []string{"V"},
							Usage:    "Specify the updater version if it can't be found automatically",
							Required: false,
							Value:    "1.03r",
						},
					},
				},
				{
					Name:      "update",
					Usage:     "Flash an update.",
					ArgsUsage: "INPUT_FILE",
					Action:    updateAction,
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:     "force",
							Usage:    "Don't abort if version string is already erased. Can be useful for recovery, but skips a safety check",
							Required: false,
							Value:    false,
						},
						&cli.StringFlag{
							Name:     "version",
							Aliases:  []string{"V"},
							Usage:    "Specify the updater version if it can't be found automatically",
							Required: false,
							Value:    "1.03r",
						},
					},
				},
				{
					Name:      "dump",
					Usage:     "Dump memory using CheckCRC(). Note that errors may result the firmware being erased!\n\nINPUT_FILE is required for correct packet CRC calculation.",
					ArgsUsage: "INPUT_FILE",
					Action:    dumpAction,
					Flags: []cli.Flag{
						&cli.IntFlag{
							Name:     "start",
							Aliases:  []string{"s"},
							Usage:    "Start address",
							Required: true,
						},
						&cli.IntFlag{
							Name:     "length",
							Aliases:  []string{"l"},
							Usage:    "Number of bytes to dump",
							Required: true,
						},
						&cli.StringFlag{
							Name:     "outfile",
							Aliases:  []string{"o"},
							Usage:    "Output file to write data to",
							Required: false,
						},
					},
				},
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

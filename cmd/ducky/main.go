// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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

	ver := ctx.String("version")
	// Attempt to automatically get the version, based on Ducky's file
	// naming convention
	if !ctx.IsSet("version") {
		fname = filepath.Base(fname)
		if filepath.Ext(fname) != ".exe" {
			return nil, "", fmt.Errorf("No version specified and it couldn't be determined")
		}

		toks := strings.SplitAfter(strings.TrimSuffix(fname, ".exe"), "_")
		ver = toks[len(toks)-1]
	}

	u := update.NewUpdate(ver)
	if u == nil {
		return nil, fname, fmt.Errorf("Unrecognised version '%s'", ver)
	}

	f, err := os.Open(ctx.Args().First())
	if err != nil {
		return nil, fname, errors.Wrap(err, "Opening input file")
	}
	defer f.Close()

	err = u.Load(f)
	if err != nil {
		return nil, fname, err
	}

	return u, fname, nil
}

func extractAction(ctx *cli.Context) error {
	u, fname, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	fwname := fname + ".enc.bin"
	err = ioutil.WriteFile(fwname, u.GetFWBlob(update.Internal).RawData(), 0644)
	if err != nil {
		return err
	}

	exname := fname + ".extra.bin"
	err = ioutil.WriteFile(exname, u.GetCRCData(update.Internal), 0644)
	if err != nil {
		return err
	}

	crcname := fname + ".crc.bin"
	crc := make([]byte, 2)
	binary.LittleEndian.PutUint16(crc, u.GetCRCValue(update.Internal))
	err = ioutil.WriteFile(crcname, crc, 0644)
	if err != nil {
		return err
	}

	return err
}

func iapTestAction(ctx *cli.Context) error {
	log.Println(">>> Loading update file...")
	u, _, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	vid, pid := u.GetAPVIDPID()

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
	if !u.Compatible(fwv) {
		return fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.GetVersion(), fwv)
	}

	log.Println(">>> Reset to IAP mode...")
	iapCtx.Reset(false)

	log.Println(">>> Connecting in IAP mode...")
	vid, pid = u.GetIAPVIDPID()
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

	iapCtx.SetExtraCRCData(u.GetCRCData(update.Internal))

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
	vid, pid := u.GetIAPVIDPID()
	iapCtx, err := iap.NewContext(vid, pid)
	if err != nil {
		v, p := u.GetAPVIDPID()
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
		if !u.Compatible(fwv) {
			return nil, fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.GetVersion(), fwv)
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

	iapCtx.SetExtraCRCData(u.GetCRCData(update.Internal))

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
		if !u.Compatible(fwv) {
			return fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.GetVersion(), fwv)
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

	fw := u.GetFWBlob(update.Internal).RawData()
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

	crc := u.GetCRCValue(update.Internal)
	_, err = iapCtx.CRCCheck(info.StartAddr(), 1, crc)
	if err != nil {
		return err
	}
	// CRCCheck() will drain the status buffer

	log.Println(">>> Write version...")
	err = iapCtx.WriteVersion(info, u.GetVersion())
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

	iapCtx.SetExtraCRCData(u.GetCRCData(update.Internal))

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
		if i % 16 == 0 {
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

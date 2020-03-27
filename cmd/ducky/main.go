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

func update(ctx *cli.Context) error {
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
	log.Println(info)

	log.Println("Device Info:")
	fwv, err := iapCtx.GetVersion(info)
	if err != nil {
		return err
	}
	log.Println("Device Version:", fwv)
	if !u.Compatible(fwv) {
		return fmt.Errorf("versions incompatible. Update: %s, Device: %s", u.GetVersion(), fwv)
	}

	log.Println(">>> Erase version...")
	err = iapCtx.EraseVersion(info)
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
	err = iapCtx.CRCCheck(info.StartAddr(), 1, crc)
	if err != nil {
		return err
	}

	// Drain the status buffer. It returns some different values in response
	// to the CRC check, but I don't know what they mean.
	status, err := iapCtx.GetStatus()
	if err != nil {
		return err
	}
	ok, fail := 0, 0
	for _, s := range status {
		if s.IsOK() {
			ok++
		} else if s.IsFail() {
			fail++
		}
	}
	if fail != 0 || ok != 1 {
		return errors.New("status report not OK")
	}

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
			},
			{
				Name:      "update",
				Usage:     "Flash an update.",
				ArgsUsage: "INPUT_FILE",
				Action:    update,
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

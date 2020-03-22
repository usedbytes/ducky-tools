// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/binary"
	"encoding/hex"
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
	defer f.Close()
	if err != nil {
		return nil, fname, errors.Wrap(err, "Opening input file")
	}

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

	iapCtx.SetExtraCRCData(u.GetCRCData(update.Internal))

	log.Println(">>> Attempt ReadData...")
	data := make([]byte, 64)
	addr := uint32(0x2800)
	_, err = iapCtx.ReadData(addr, data[:])
	if err != nil {
		return err
	}
	log.Printf("AP 0x%04x (%d)\n", addr, addr)
	log.Println(hex.Dump(data))

	log.Print(">>> Attempt Ping... ")
	pong, _ := iapCtx.Ping(42)
	log.Println("pong")

	log.Println(">>> Reset to IAP mode...")
	iapCtx.Reset(false)

	time.Sleep(1 * time.Second)

	vid, pid = u.GetIAPVIDPID()

	log.Println(">>> Connecting in IAP mode...")
	iapCtx, err = iap.NewContext(vid, pid)
	if err != nil {
		return err
	}
	defer iapCtx.Close()

	iapCtx.SetExtraCRCData(u.GetCRCData(update.Internal))

	log.Println(">>> Attempt ReadData...")
	addr = uint32(0x3c00)
	_, err = iapCtx.ReadData(addr, data[:])
	if err != nil {
		return err
	}
	log.Printf("IAP 0x%04x (%d)\n", addr, addr)
	log.Println(hex.Dump(data))

	log.Print(">>> Attempt Ping (should time out)... ")
	pong, err = iapCtx.Ping(42)
	if pong && err != nil {
		return errors.New("Ping() shouldn't work in IAP mode")
	}
	log.Println("timed out")

	log.Println("Reset back to AP mode...")
	iapCtx.Reset(false)

	log.Println("Success!")

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

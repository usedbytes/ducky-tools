// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/iap"
	"github.com/usedbytes/ducky-tools/lib/iap2"
	"github.com/usedbytes/ducky-tools/lib/exe/one"
	"github.com/usedbytes/ducky-tools/lib/exe"
	"github.com/usedbytes/ducky-tools/lib/xor"
	"github.com/usedbytes/log"

	"github.com/sigurn/crc16"
)

func loadUpdateFile(ctx *cli.Context) (*config.Config, error) {
	if ctx.Args().Len() != 1 {
		return nil, fmt.Errorf("INPUT_FILE is required")
	}
	fname := ctx.Args().First()

	var cfg *config.Config
	var err error

	ext := filepath.Ext(fname)
	switch ext {
	case ".exe":
		cfg, err = exe.Load(fname)
		if err != nil {
			return nil, err
		}
	case ".toml":
		cfg, err = config.LoadConfig(fname)
		if err != nil {
			_, err2 := one.LoadTOMLUpdate(fname)
			if err2 == nil {
				return nil, errors.New("old-style toml files are no longer supported." +
						"Please use 'extract' to convert it to the new config format.")
			}

			return nil, err
		}
	default:
		return nil, errors.New("unrecognised file extension")
	}

	log.Verbosef("Update loaded:\n%v", cfg)

	return cfg, nil
}

func extractAction(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		return fmt.Errorf("INPUT_FILE is required")
	}
	fname := ctx.Args().First()

	var cfg *config.Config
	var err error

	ext := filepath.Ext(fname)
	switch ext {
	case ".exe":
		cfg, err = exe.Load(fname)
		if err != nil {
			return err
		}
	case ".old":
		u, err := one.LoadTOMLUpdate(fname)
		if err != nil {
			return err
		}
		cfg = u.ToConfig()
	default:
		return fmt.Errorf("expected a .exe, got %s", ext)
	}

	if ctx.IsSet("out") {
		fname = ctx.String("out")
	} else {
		fname = filepath.Base(fname)
		if filepath.Ext(fname) != ".toml" {
			fname = fname + ".toml"
		}
	}

	err = cfg.Write(fname)
	if err != nil {
		return err
	}

	log.Println("Wrote to", fname)

	return nil
}

func decodeAction(ctx *cli.Context) error {
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	for i, d := range cfg.Devices {
		for j, fw := range d.Firmwares {
			regen := false

			for k, img := range fw.Images {
				if !img.XferEncoded || len(img.Data) == 0 {
					continue
				}

				log.Printf(">>> Device %d, Firmware %d, Image %s\n", i, j, k)
				key, err := xor.FindKey(img.Data, 0x34)
				if err != nil {
					log.Println("!!! Failed to find key", err)
					continue
				}


				img.Data = xor.Decode(img.Data, key, false)
				img.XferKey = key
				img.XferEncoded = false
				log.Println(">>> Decoded.")
				regen = true

			}

			if regen {
				fw.GenerateFilenames()
			}
		}
	}

	var fname string
	if ctx.IsSet("out") {
		fname = ctx.String("out")
	} else {
		fname = filepath.Base(ctx.Args().First())
		if filepath.Ext(fname) != ".toml" {
			fname = fname + ".toml"
		}
	}

	err = cfg.Write(fname)
	if err != nil {
		return err
	}

	log.Println("Wrote to", fname)

	return nil
}

func iapTestAction(ctx *cli.Context) error {
	log.Println(">>> Loading update file...")
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || cfg.Devices[0].Application == nil || cfg.Devices[0].Bootloader == nil {
		// XXX: This is temporary, this command will get reworked.
		return errors.New("iap test requires a single device with Application and Bootloader information")
	}

	dev := cfg.Devices[0]

	vid, pid := dev.Application.VID, dev.Application.PID

	log.Println(">>> Connecting in AP mode...")
	iapCtx, err := iap.NewContext(uint16(vid), uint16(pid))
	if err != nil {
		return err
	}
	defer iapCtx.Close()

	log.Print(">>> Attempt Ping... ")
	pong, err := iapCtx.Ping(42)
	if err != nil {
		return err
	} else if !pong{
		return errors.New("invalid or no response to ping")
	}
	log.Println("pong")

	log.Println(">>> Get Version:")
	fwv, err := iapCtx.APGetVersion()
	if err != nil {
		return err
	}

	log.Println(fwv)
	fw := cfg.Devices[0].Firmwares[0]
	if !fw.Version.Compatible(fwv) {
		return fmt.Errorf("versions incompatible. Update: %s, Device: %s", fw.Version, fwv)
	}

	if cfg.Exe == nil || len(cfg.Exe.ExtraCRC) == 0 {
		// XXX: This is temporary, this command will get reworked
		return errors.New("iap test requires ExtraCRC")
	}

	log.Println(">>> Reset to IAP mode...")
	iapCtx.Reset(false)

	log.Println(">>> Connecting in IAP mode...")
	vid, pid = dev.Bootloader.VID, dev.Bootloader.PID
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

	iapCtx.SetExtraCRCData(cfg.Exe.ExtraCRC)

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

func enterIAP(cfg *config.Config) (*iap.Context, error) {
	if len(cfg.Devices) != 1 || cfg.Devices[0].Application == nil || cfg.Devices[0].Bootloader == nil {
		// XXX: This is temporary, this command will get reworked.
		return nil, errors.New("require a single device with Application and Bootloader information")
	}

	dev := cfg.Devices[0]

	vid, pid := dev.Bootloader.VID, dev.Bootloader.PID
	iapCtx, err := iap.NewContext(vid, pid)
	if err != nil {
		v, p := dev.Application.VID, dev.Application.PID
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
		fw := cfg.Devices[0].Firmwares[0]
		if !fw.Version.Compatible(fwv) {
			return nil, fmt.Errorf("versions incompatible. Update: %s, Device: %s", fw.Version, fwv)
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
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || len(cfg.Devices[0].Firmwares) != 1 {
		// XXX: This is temporary, this command will go away entirely.
		return errors.New("update requires a single device with a single firmware")
	}

	img, ok := cfg.Devices[0].Firmwares[0].Images[string(config.Internal)]
	if !ok || len(img.Data) == 0 {
		return errors.New("no data for internal image")
	}

	if !img.XferEncoded {
		return errors.New("update image must be XferEncoded")
	}

	iapCtx, err := enterIAP(cfg)
	if err != nil {
		return err
	}
	defer iapCtx.Reset(false)

	if cfg.Exe == nil || len(cfg.Exe.ExtraCRC) == 0 {
		// XXX: This is temporary, this command will get reworked
		return errors.New("iap test requires ExtraCRC")
	}

	iapCtx.SetExtraCRCData(cfg.Exe.ExtraCRC)

	info, err := iapCtx.GetInformation()
	if err != nil {
		return err
	}

	log.Println("Device Info:")
	log.Println(info)

	fw := cfg.Devices[0].Firmwares[0]
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
		if !fw.Version.Compatible(fwv) {
			return fmt.Errorf("versions incompatible. Update: %s, Device: %s", fw.Version, fwv)
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

	data := img.Data
	addr := info.StartAddr()

	log.Println(">>> Erase program...")
	err = iapCtx.ErasePage(addr, len(data))
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
	for start := 0; start < len(data); start += chunkLen {
		end := start + chunkLen
		if end > len(data) {
			end = len(data)
		}

		err = iapCtx.WriteData(addr, data[start:end])
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
	err = iapCtx.WriteVersion(info, *fw.Version)
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
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	// Force a reset to make sure we have a clean slate
	iapCtx, err := enterIAP(cfg)
	if err != nil {
		return err
	}
	iapCtx.Reset(true)

	iapCtx, err = enterIAP(cfg)
	if err != nil {
		return err
	}
	defer iapCtx.Reset(false)

	if cfg.Exe == nil || len(cfg.Exe.ExtraCRC) == 0 {
		// XXX: This is temporary, this command will get reworked
		return errors.New("iap test requires ExtraCRC")
	}

	iapCtx.SetExtraCRCData(cfg.Exe.ExtraCRC)

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
	//     crc = crc16.Update(crc, xor.Decode(data), crc16.MakeTable(crc16.CRC16_XMODEM))
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

func iap2TestAction(ctx *cli.Context) error {
	vid := ctx.Uint("vid")
	pid := ctx.Uint("pid")

	log.Println(">>> Connecting in AP mode...")
	iapCtx, err := iap2.NewContext(uint16(vid), uint16(pid))
	if err != nil {
		return err
	}
	defer iapCtx.Close()

	iap2Cmd := func(cmd []byte) error {
		err := iapCtx.RawSend(cmd)
		if err != nil {
			return err
		}

		_, err = iapCtx.RawReceive()
		if err != nil {
			return err
		}

		return nil
	}

	err = iap2Cmd([]byte{0x10, 0x02})
	if err != nil {
		return err
	}

	err = iap2Cmd([]byte{0x12, 0x00})
	if err != nil {
		return err
	}

	err = iap2Cmd([]byte{0x12, 0x20})
	if err != nil {
		return err
	}

	err = iap2Cmd([]byte{0x12, 0x01})
	if err != nil {
		return err
	}

	err = iap2Cmd([]byte{0x12, 0x22})
	if err != nil {
		return err
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
					Name:     "out",
					Aliases:  []string{"o"},
					Usage:    "Output filename (.toml)",
					Required: false,
				},
			},
		},
		{
			Name:      "decode",
			ArgsUsage: "INPUT_FILE",
			Action:    decodeAction,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "out",
					Aliases:  []string{"o"},
					Usage:    "Output filename (.toml)",
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
		{
			Name: "iap2",
			Subcommands: []*cli.Command{
				{
					Name:      "test",
					Action:    iap2TestAction,
					Flags: []cli.Flag{
						&cli.UintFlag{
							Name:     "vid",
							Usage:    "Vendor ID (VID)",
							Required: false,
							Value:    0x04d9,
						},
						&cli.UintFlag{
							Name:     "pid",
							Aliases:  []string{"p"},
							Usage:    "Product ID (PID)",
							Required: true,
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

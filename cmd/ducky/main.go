// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/iap"
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

func devicesAction(ctx *cli.Context) error {
	var cfg *config.Config
	var err error
	if ctx.Args().Len() == 1 {
		cfg, err = loadUpdateFile(ctx)
		if err != nil {
			return err
		}
	} else {
		vid := uint16(ctx.Uint("vid"))
		pid := uint16(ctx.Uint("pid"))
		cfg = &config.Config{
			Devices: []*config.Device{
				&config.Device{
					Application: &config.Application{
						VID: vid,
						PID: pid,
						// XXX: This shouldn't be hard-coded when we have protocol detection
						Protocol: config.One,
					},
				},
			},
		}
	}

	apps := FindDevices(cfg.Devices)

	if len(apps) == 0 {
		return errors.New("didn't find any devices")
	}

	for _, app := range apps {
		log.Printf(">>> Device VID:PID: 0x%04x:0x%04x\n", app.VID, app.PID)
	}

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

	log.Println(">>> Connecting...")
	iapCtx, err := iap.NewContext(cfg.Devices[0])
	if err != nil {
		return err
	}

	proto, ok := iapCtx.Protocol().(*iap.ProtocolOne)
	if !ok {
		return errors.New("wrong protocol version")
	}

	log.Println(">>> Get Version:")
	fwv, err := proto.APGetVersion()
	if err != nil {
		return err
	}

	log.Println(fwv)

	log.Println(">>> Reset to IAP mode...")
	err = iapCtx.Reset(true)
	if err != nil {
		return err
	}

	proto, ok = iapCtx.Protocol().(*iap.ProtocolOne)
	if !ok {
		return errors.New("wrong protocol version")
	}

	info, err := proto.GetInformation()
	if err != nil {
		return err
	}

	log.Println(">>> Info:")
	log.Println(info.String())

	fwv2, err := proto.GetVersion(info)
	if err != nil {
		return err
	}

	log.Println(">>> Version:", fwv2)
	if !fwv2.Matches(fwv) {
		return fmt.Errorf("version inconsistent. AP: %s, IAP: %s", fwv, fwv2)
	}

	log.Println(">>> Reset back to AP...")
	iapCtx.Reset(false)
	iapCtx.Close()

	return nil
}

func enterIAP(cfg *config.Config) (*iap.ProtocolOne, error) {
	if len(cfg.Devices) != 1 || cfg.Devices[0].Application == nil || cfg.Devices[0].Bootloader == nil {
		// XXX: This is temporary, this command will get reworked.
		return nil, errors.New("require a single device with Application and Bootloader information")
	}

	dev := cfg.Devices[0]

	vid, pid := dev.Bootloader.VID, dev.Bootloader.PID
	proto, err := iap.NewContextWithProtocol(uint16(vid), uint16(pid), "one")
	if err != nil {
		v, p := dev.Application.VID, dev.Application.PID
		proto, err = iap.NewContextWithProtocol(uint16(v), uint16(p), "one")
		if err != nil {
			return nil, err
		}
		iapCtx := proto.(*iap.ProtocolOne)
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
			proto, err = iap.NewContextWithProtocol(uint16(vid), uint16(pid), "one")
			if err == nil {
				iapCtx = proto.(*iap.ProtocolOne)
				return iapCtx, nil
			}
		}
	} else {
		iapCtx := proto.(*iap.ProtocolOne)
		return iapCtx, nil
	}

	return nil, err
}

func updateAction(ctx *cli.Context) error {
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || len(cfg.Devices[0].Firmwares) != 1 {
		// XXX: Need to implement device (and firmware) selection
		return errors.New("update requires a single device with a single firmware")
	}

	iapCtx, err := iap.NewContext(cfg.Devices[0])
	if err != nil {
		return err
	}

	err = iapCtx.Update(cfg.Devices[0].Firmwares[0])
	if err != nil {
		return err
	}

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

	dev := cfg.Devices[0]

	if len(dev.Bootloader.ExtraCRC) == 0 {
		// XXX: This is temporary, this command will get reworked
		return errors.New("iap test requires ExtraCRC")
	}

	iapCtx.SetExtraCRCData(dev.Bootloader.ExtraCRC)

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
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || len(cfg.Devices[0].Firmwares) != 1 {
		// XXX: Need to implement device (and firmware) selection
		return errors.New("update requires a single device with a single firmware")
	}

	iapCtx, err := iap.NewContext(cfg.Devices[0])
	if err != nil {
		return err
	}

	proto, ok := iapCtx.Protocol().(*iap.ProtocolOne2)
	if !ok {
		return errors.New("wrong protocol version")
	}

	blinfo := func() error {
		log.Println("Read Bootloader info...")
		var info []byte
		tmp, err := proto.ReadInfo(0)
		if err != nil {
			return err
		}
		info = append(info, tmp...)

		tmp, err = proto.ReadInfo(1)
		if err != nil {
			return err
		}
		info = append(info, tmp...)

		log.Println(hex.Dump(info))

		return nil
	}

	fwinfo := func() error {
		log.Println("Read Firmware info...")
		var info []byte
		tmp, err := proto.ReadChunk(0)
		if err != nil {
			return err
		}
		info = append(info, tmp...)

		tmp, err = proto.ReadChunk(1)
		if err != nil {
			return err
		}
		info = append(info, tmp...)

		tmp, err = proto.ReadChunk(2)
		if err != nil {
			return err
		}
		info = append(info, tmp...)

		log.Println(hex.Dump(info))

		return nil
	}

	err = blinfo()
	if err != nil {
		return err
	}

	err = fwinfo()
	if err != nil {
		return err
	}

	log.Println("Reset to IAP mode...")
	err = iapCtx.Reset(true)
	if err != nil {
		return err
	}

	proto, ok = iapCtx.Protocol().(*iap.ProtocolOne2)
	if !ok {
		return errors.New("wrong protocol version")
	}

	err = blinfo()
	if err != nil {
		return err
	}

	err = fwinfo()
	if err != nil {
		return err
	}

	log.Println("Reset back to AP...")
	// For some reason, the One2 doesn't properly release on exit
	// so bypass the Context reset, and reset via the Protocol directly
	proto.Reset(false)
	iapCtx.Close()

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
			Name:      "update",
			Usage:     "Flash an update.",
			ArgsUsage: "INPUT_FILE",
			Action:    updateAction,
		},
		{
			Name: "iap",
			Subcommands: []*cli.Command{
				{
					Name:      "test",
					ArgsUsage: "INPUT_FILE",
					Action:    iapTestAction,
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
					ArgsUsage: "INPUT_FILE",
				},
			},
		},
		{
			Name: "devices",
			Usage:     "Try and connect to devices",
			ArgsUsage: "[INPUT_FILE]",
			Action:    devicesAction,
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
					Required: false,
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

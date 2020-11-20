// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/hex"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/iap"
	"github.com/usedbytes/ducky-tools/lib/exe/one"
	"github.com/usedbytes/ducky-tools/lib/exe"
	"github.com/usedbytes/ducky-tools/lib/xor"
	"github.com/usedbytes/log"

	"github.com/sigurn/crc16"
	"github.com/cheggaaa/pb/v3"
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

func iapDumpAction(ctx *cli.Context) error {
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || len(cfg.Devices[0].Firmwares) != 1 {
		// XXX: Need to implement device (and firmware) selection
		return errors.New("update requires a single device with a single firmware")
	}

	dev := cfg.Devices[0]

	// Force a pair of resets to make sure we have a clean slate
	iapCtx, err := iap.NewContext(dev)
	if err != nil {
		return err
	}
	err = iapCtx.Reset(true)
	if err != nil {
		return err
	}

	err = iapCtx.Reset(true)
	if err != nil {
		return err
	}

	// The Context will have already applied this for us, but it must
	// exist!
	if len(dev.Bootloader.ExtraCRC) == 0 {
		return errors.New("dump via CRC requires ExtraCRC")
	}

	proto, ok := iapCtx.Protocol().(*iap.ProtocolOne)
	if !ok {
		return errors.New("wrong protocol version")
	}

	info, err := proto.GetInformation()
	if err != nil {
		return err
	}

	log.Println("Device Info:")
	log.Println(info)

	err = proto.CheckStatus(-1)
	if err != nil {
		return err
	}

	crct := crc16.MakeTable(crc16.CRC16_XMODEM)
	lu := make(map[uint16]byte)
	for i := 0; i < 256; i++ {
		crc := crc16.Checksum([]byte{byte(i)}, crct)
		lu[crc] = byte(i)
	}

	// The CRC we send has to match the expected value, which is updated in
	// two ways:
	// 1) On each invocation of WriteData(..., data):
	//     crc = crc16.Update(crc, xor.Decode(data), crc16.MakeTable(crc16.CRC16_XMODEM))
	// 2) On each invocation of CRCCheck():
	//     crc = crc16.Update(crc, nibbles, crc16.MakeTable(crc16.CRC16_XMODEM))
	// We're running on a clean reset and never call WriteData(), so we just
	// need to update according to the CRCCheck() path.
	//
	// If the check fails, the firmware will be erased!

	// crc is initialised to zero at boot
	crc := uint16(0)

	// nibbles is hard-coded in the IAP code
	nibbles := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

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

		crc = crc16.Update(crc, nibbles, crct)

		xcrc, err := proto.CRCCheck(uint32(addr), 1, crc)
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

	log.Println(">>> Reset back to AP...")
	iapCtx.Reset(false)
	iapCtx.Close()

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

func iap2DumpAction(ctx *cli.Context) error {
	cfg, err := loadUpdateFile(ctx)
	if err != nil {
		return err
	}

	if len(cfg.Devices) != 1 || len(cfg.Devices[0].Firmwares) != 1 {
		// XXX: Need to implement device (and firmware) selection
		return errors.New("dump requires a single device with a single firmware")
	}

	fw := cfg.Devices[0].Firmwares[0]
	img, ok := fw.Images["internal"]
	if !ok || len(img.XferKey) == 0 {
		return errors.New("dump requires an XferKey for the internal image")
	}
	key := img.XferKey

	iapCtx, err := iap.NewContext(cfg.Devices[0])
	if err != nil {
		return err
	}

	err = iapCtx.Reset(false)
	if err != nil {
		return err
	}

	err = iapCtx.Reset(true)
	if err != nil {
		return err
	}

	proto, ok := iapCtx.Protocol().(*iap.ProtocolOne2)
	if !ok {
		return errors.New("wrong protocol version")
	}

	defer proto.Reset(false)

	// The checksum in the firmware applies the XOR key to the data being
	// checksummed, and adds together all the results. Something like:
	//
	// checksum(addr, length) =
	//    mem[addr] ^ key[0] + mem[addr+1] ^ key[1] ... + mem[addr+length-1] ^ key[length-1]
	//
	// For compactness, lets re-write that as:
	//
	//     a ^ k0 + b ^ k1 + c ^ k2 ...
	//
	// We know all the 'k' values, we want to find a, b, c...
	//
	// This is easy assuming we can keep adding extra values to the and of
	// the checksum. e.g.
	// checksum(a..c) is:
	//    a ^ k0 + b ^ k1 + c ^ k2
	// and checksum(a..d) is:
	//    a ^ k0 + b ^ k1 + c ^ k2 + d ^ k3
	// therefore checksum(a..d) - checksum(a..c) is:
	//    (a ^ k0 + b ^ k1 + c ^ k2 + d ^ k3) - (a ^ k0 + b ^ k1 + c ^ k2)
	// which simplifies to just (d ^ k3), and we know k3, so we can find d.
	//    d = (checksum(a..d) - checksum(a..c)) ^ k3
	//
	// This is fine so long as we can keep _extending_ the checksum.
	// However, the firmware imposes some restrictions:
	//   1. addr >= 0x400
	//   2. length >= 0x1000
	//
	// This means the first value we can find by extending the checksum is
	// at address 0x1400, and we can't find any values lower than that via
	// this method. (checksum(a..c) in the analogy above effectively becomes
	// checksum(0x400..0x1400))
	//
	// Unfortunately, extending the checksum "down" is not as
	// straightforward as extending it up.
	//
	// If we had checksum(b..d) and checksum(a..d), we can't simply subtract
	// one from the other to find 'a', because the key always starts from
	// k0 for the lowest address. i.e.:
	// checksum(a..d) is:
	//    a ^ k0 + b ^ k1 + c ^ k2 + d ^ k3
	// and checksum(b..d) is:
	//    b ^ k0 + c ^ k1 + d ^ k2
	// We can't directly simplify this, because in one we have (b ^ k0) and
	// in the other (b ^ k1), so one doesn't simply subtract from the other.
	//
	// Thankfully, we can combine the two approaches.
	//
	// If we take checksum(a..d):
	//    a ^ k0 + b ^ k1 + c ^ k2 + d ^ k3
	// and we have already found b, c and d with the approach above, then
	// we can calculate the part from 'b' onwards for ourselves:
	//    b ^ k1 + c ^ k2 + d ^ k2
	// Subtracting that from checksum(a..d) leaves just (a ^ k0), where
	// we know k0, and we can find 'a'.


	// To start with, we find the data from 0x1400-0x2400 using the
	// extension method. Note that we can apply the XOR decode to all the
	// data at the end, we don't need to decode the values as we read them.
	// However we do pad the start of the buffer with 0x1000 bytes, and
	// start the decode from there, to make sure the right key values are
	// used for the right entries in the buffer.
	// Technically, we don't need the full 0x1000 bytes at the start - only
	// enough to align to the key length (0x3c).

	data := make([]byte, 0x2000)
	baseline := uint32(0)

	log.Println("Read upwards, 0x1400-0x2400...")
	bar := pb.StartNew(0x1000)
	bar.SetMaxWidth(80)

	for i := uint32(0); i <= 0x1000; i += 4 {
		csum, err := proto.Checksum(0x400, 0x1000 + i)
		if err != nil {
			return err
		}

		if i > 0 {
			val := csum - baseline
			binary.LittleEndian.PutUint32(data[0x1000 + (i - 4):], val)
		}
		baseline = csum

		bar.SetCurrent(int64(i))
	}
	bar.Finish()

	decoded := xor.Decode(data, key, false)

	// Now data contains 0x1000 bytes of the XOR key repeating (garbage),
	// followed by 0x1000 bytes of valid decoded data, representing
	// addresses 0x1400-0x2400
	copy(data, decoded)

	// Part 2 is to work downwards from 0x1400 to 0x400, using the second
	// method
	log.Println("Read downwards, 0x1400-0x400...")
	bar = pb.StartNew(0x1000)
	bar.SetMaxWidth(80)

	tmp := []byte{0, 0, 0, 0}
	for start := uint32(0x1400-4); start >= 0x400; start -= 4 {
		// We always checksum 0x1000 bytes, starting at successively
		// lower addresses
		csum, err := proto.Checksum(start, 0x1000)
		if err != nil {
			return err
		}

		// Address 0x400 is offset 0 in our data buffer
		idx := start - 0x400

		// Encode 0x1000 bytes of the data we already found, the same
		// as the bootloader will do.  The first 4 bytes for us are
		// meaningless, but that doesn't matter.
		enc := xor.Decode(data[idx:idx+0x1000], key, false)

		// Then checksum from the 4th byte onwards (i.e. b..d from
		// the analogy), to give us the baseline
		baseline := iap.Checksum(enc[4:])

		// Subtract one from the other, to leave a ^ k0
		val := csum - baseline

		// And this time, we need to XOR with the first 4 bytes of
		// the key (k0) for each value individually.
		binary.LittleEndian.PutUint32(tmp, val)
		copy(data[idx:], xor.Decode(tmp, key, false))

		bar.Add(4)
	}
	bar.Finish()

	// If all went well, we've now got 0x2000 bytes of valid data, for
	// addresses 0x400-0x2400!

	var f *os.File
	fname := ctx.String("outfile")
	if len(fname) != 0 {
		f, err = os.Create(fname)
		if err != nil {
			return err
		}
		defer f.Close()

		n, err := f.Write(data)
		if err != nil {
			return err
		} else if n != len(data) {
			return errors.New("short write to outfile")
		}
	}

	// Now read upwards until checksum fails (presumably the top of flash)
	// We'll work in smaller chunks to hopefully manage to get all data
	pageSize := uint32(256)
	data = data[:0x1000+pageSize]
	for page := 0; page < 256; page++ {
		start := uint32(page * 256 + 0x2400)
		log.Printf("Read upwards, 0x%04x-0x%04x...\n", start, start + pageSize)

		bar := pb.StartNew(int(pageSize))
		bar.SetMaxWidth(80)
		for i := uint32(0); i <= pageSize; i += 4 {
			csum, err := proto.Checksum(start-0x1000, 0x1000 + i)
			if err != nil {
				return err
			}

			if i > 0 {
				val := csum - baseline
				binary.LittleEndian.PutUint32(data[0x1000 + (i - 4):], val)
			}
			baseline = csum

			bar.SetCurrent(int64(i))
		}
		bar.Finish()

		decoded := xor.Decode(data, key, false)
		if f != nil {
			n, err := f.Write(decoded[0x1000:])
			if err != nil {
				return err
			} else if n != len(decoded[0x1000:]) {
				return errors.New("short write to outfile")
			}
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
					Action:    iapDumpAction,
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
				{
					Name:      "dump",
					Action:    iap2DumpAction,
					ArgsUsage: "INPUT_FILE",
					Flags: []cli.Flag{
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

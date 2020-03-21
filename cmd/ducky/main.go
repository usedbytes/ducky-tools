// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/update"
	"github.com/usedbytes/log"
)

func run(ctx *cli.Context) error {
	u := update.NewUpdate(ctx.String("version"))
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

	log.Println(u.GetCRCValue(update.Internal))
	log.Println(hex.Dump(u.GetCRCData(update.Internal)))

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

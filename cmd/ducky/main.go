// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/usedbytes/ducky-tools/lib/update"
	"github.com/usedbytes/log"
)

func run(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		return fmt.Errorf("INPUT_FILE is required")
	}
	fname := ctx.Args().First()

	ver := ctx.String("version")
	// Attempt to automatically get the version, based on Ducky's file
	// naming convention
	if !ctx.IsSet("version") {
		fname := filepath.Base(fname)
		if filepath.Ext(fname) != ".exe" {
			return fmt.Errorf("No version specified and it couldn't be determined")
		}

		toks := strings.SplitAfter(strings.TrimSuffix(fname, ".exe"), "_")
		ver = toks[len(toks)-1]
	}

	u := update.NewUpdate(ver)
	if u == nil {
		return fmt.Errorf("Unrecognised version '%s'", ver)
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

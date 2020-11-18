// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package main

import (
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/iap"
)

func tryApp(app *config.Application) error {
	ctx, err := iap.NewContextWithProtocol(app.VID, app.PID, "one")
	if err == nil {
		// TODO: ctx.Reset() when we have a unified context
		ctx.Close()
	}

	return err
}

func FindDevices(devs []*config.Device) []*config.Application {
	var results []*config.Application

	for _, dev := range devs {
		if dev.Application != nil {
			err := tryApp(dev.Application)
			if err == nil {
				results = append(results, dev.Application)
				continue
			}
		}

		if dev.Bootloader != nil {
			err := tryApp(dev.Bootloader)
			if err == nil {
				results = append(results, dev.Bootloader)
				continue
			}
		}
	}

	return results
}

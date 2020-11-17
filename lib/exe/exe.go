// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package exe

import (
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/exe/one"
	"github.com/usedbytes/log"
)

func Load(filename string) (*config.Config, error) {
	// TODO: Should attempt to detect exe type rather than
	// just trying.

	log.Verboseln("Attempt load as FWUpdate")
	cfg, err := loadFWUpdateExe(filename)
	if err == nil {
		return cfg, nil
	} else {
		log.Verboseln("Failed loading as FWUpdate", err)
	}

	cfg, err = one.Load(filename)
	if err == nil {
		return cfg, nil
	}

	return nil, err
}

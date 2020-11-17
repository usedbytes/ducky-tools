// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package exe

import (
	"github.com/usedbytes/ducky-tools/lib/config"
)

func Load(filename string) (*config.Config, error) {
	// TODO: Should attempt to detect exe type

	cfg, err := loadFWUpdateExe(filename)

	return cfg, err
}

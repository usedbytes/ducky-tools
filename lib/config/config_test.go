// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package config

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestParse(t *testing.T) {
	var tomlData = `
[exe]
name = "FWUpdate.exe"
iap_version = "V1.0.0"
file_key = 0x12345678
extra_crc_data_file = "extracrc.bin"
byte_swapping = true

[[device]]
name = "Ducky RGB 100%"
	[device.application]
	vid = 0x04d9
	pid = 0x0356
	protocol = "one2"

	[device.bootloader]
	vid = 0x04d9
	pid = 0x1356
	protocol = "one2"

	[[device.firmware]]
		name = "EU Layout"
		version = "V1.0.5"
		[firmware.images.internal]
		data_file = "internal.bin"
		check_crc = 0x1234
		[firmware.images.meta]
		data_file = "metadata.bin"
		check_crc = 0x1234
`

	var cfg Config
	_, err := toml.Decode(tomlData, &cfg)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(cfg)

	buf := &bytes.Buffer{}
	enc := toml.NewEncoder(buf)
	err = enc.Encode(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(buf.String())
}

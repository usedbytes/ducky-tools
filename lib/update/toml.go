// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"encoding/binary"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

type tomlBlob struct {
	CheckCRC     uint16 `toml:"check_crc"`
	FileEncoded  bool   `toml:"file_encoded"`
	XferEncoded  bool   `toml:"xfer_encoded"`
	XferKeyFile  string `toml:"xfer_key_file"`
	DataFile     string `toml:"data_file"`
	ExtraCRCFile string `toml:"extra_crc_data_file"`
}

type tomlUpdate struct {
	Name         string              `toml:"name"`
	IAPVerStr    string              `toml:"iap_version"`
	VerStr       string              `toml:"version"`
	FileKey      uint32              `toml:"file_key"`
	ExtraCRCFile string              `toml:"extra_crc_data_file"`
	ApVidPid     []uint16            `toml:"ap_vid_pid"`
	IapVidPid    []uint16            `toml:"iap_vid_pid"`
	Images       map[string]tomlBlob `toml:"images"`
}

func LoadTOMLUpdate(file string) (*Update, error) {
	var tu tomlUpdate
	_, err := toml.DecodeFile(file, &tu)
	if err != nil {
		return nil, err
	}

	u := Update{
		Name:    tu.Name,
		FileKey: tu.FileKey,
		Images:  make(map[ImageNumber]*Image),
	}

	if len(tu.VerStr) == 0 {
		return nil, errors.New("version string is required")
	}
	u.Version, err = ParseFWVersion(tu.VerStr)
	if err != nil {
		return nil, err
	}

	u.IAPVersion, err = ParseIAPVersion(tu.IAPVerStr)
	if err != nil {
		return nil, err
	}

	if len(tu.ApVidPid) != 2 {
		return nil, errors.New("ap_vid_pid must be a list of two integers: [vid, pid]")
	}
	u.APVID, u.APPID = tu.ApVidPid[0], tu.ApVidPid[1]

	if len(tu.IapVidPid) != 2 {
		return nil, errors.New("iap_vid_pid must be a list of two integers: [vid, pid]")
	}
	u.IAPVID, u.IAPPID = tu.IapVidPid[0], tu.IapVidPid[1]

	if len(tu.Images) == 0 {
		return nil, errors.New("no images found")
	}

	for k, v := range tu.Images {
		var i Image
		switch k {
		case "internal":
			u.Images[Internal] = &i
		case "external":
			u.Images[External] = &i
		default:
			return nil, errors.Errorf("unrecognised image name '%s'", k)
		}

		i.CheckCRC = v.CheckCRC

		data, err := ioutil.ReadFile(v.DataFile)
		if err != nil {
			return nil, err
		}
		i.Data = data

		if v.FileEncoded {
			key := [4]byte{}
			binary.LittleEndian.PutUint32(key[:], tu.FileKey)
			i.Data = XORDecode(i.Data, key[:], true)
		}

		if len(v.XferKeyFile) != 0 {
			data, err = ioutil.ReadFile(v.XferKeyFile)
			if err != nil {
				return nil, err
			}

			if len(data) != 52 {
				return nil, errors.New("xfer key expected to be 52 bytes")
			}

			i.XferKey = data
		}

		if !v.XferEncoded {
			if i.XferKey == nil {
				return nil, errors.New("xfer key must be provided if data is not xfer encoded")
			}

			// Image always stores data in "wire format"
			i.Data = XORDecode(i.Data, i.XferKey, false)
		}

		if len(v.ExtraCRCFile) != 0 {
			data, err = ioutil.ReadFile(v.ExtraCRCFile)
			if err != nil {
				return nil, err
			}

			i.ExtraCRC = data
		}
	}

	return &u, nil
}

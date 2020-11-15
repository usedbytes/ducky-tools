// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package one

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/usedbytes/log"
)

type exeVersion struct {
	version       FWVersion
	headerLen     int
	chunkLen      int
	globalCrcData bool
}

var exeVersions map[string]*exeVersion = map[string]*exeVersion{
	"1.01": &exeVersion{
		version: FWVersion{
			hwv:      HWVersionUnknown,
			major:    1,
			minor100: 1,
		},
		headerLen:     0x23c,
		chunkLen:      0x54,
		globalCrcData: false,
	},
	"1.03r": &exeVersion{
		version: FWVersion{
			hwv:      HWVersionUnknown,
			major:    1,
			minor100: 3,
		},
		headerLen:     0x288,
		chunkLen:      0x10,
		globalCrcData: true,
	},
}

type exeUpdate struct {
	version   *exeVersion
	fileHdr   *fileHeader
	imageHdr  [2]*imageHeader
	imageData [2][]byte
}

func (u *exeUpdate) loadFileHeader(f io.ReadSeeker) error {
	_, err := f.Seek(-int64(u.version.headerLen), 2)
	if err != nil {
		return errors.Wrap(err, "Seeking file header")
	}

	rawData := make([]byte, u.version.headerLen)
	n, err := f.Read(rawData)
	if n != len(rawData) || err != nil {
		return errors.Wrap(err, "Reading file header")
	}

	u.fileHdr, err = newFileHeader(rawData)
	if err != nil {
		return errors.Wrap(err, "Parsing file header")
	}

	if !u.fileHdr.fwVersion.Compatible(u.version.version) {
		return fmt.Errorf("Incompatible firmware version %s vs %s", u.version.version, u.fileHdr.fwVersion)
	}

	return nil
}

func (u *exeUpdate) loadImageHeader(f io.ReadSeeker, num ImageNumber) error {
	_, err := f.Seek(-int64(u.version.headerLen+u.version.chunkLen*int(num+1)), 2)
	if err != nil {
		return errors.Wrap(err, "Seeking image header")
	}

	rawData := make([]byte, u.version.chunkLen)
	n, err := f.Read(rawData)
	if n != len(rawData) || err != nil {
		return errors.Wrap(err, "Reading image header")
	}

	hdr, err := newImageHeader(rawData, u.fileHdr.fileKey)
	if err != nil {
		return errors.Wrap(err, "Parsing image header")
	}

	if ImageNumber(hdr.idx) != num {
		return fmt.Errorf("Decoded image number (%d) doesn't match expected (%d)", hdr.idx, num)
	}

	switch num {
	case Internal, External:
		u.imageHdr[num] = hdr
	default:
		return fmt.Errorf("Unrecognised image number")
	}

	return nil
}

func (u *exeUpdate) loadImage(f io.ReadSeeker, num ImageNumber) error {

	offs := int64(len(u.fileHdr.rawData) + len(u.imageHdr[Internal].rawData) + len(u.imageHdr[External].rawData))
	for i := 0; i <= int(num); i++ {
		offs += int64(u.imageHdr[i].size)
	}

	_, err := f.Seek(-offs, 2)
	if err != nil {
		return errors.Wrap(err, "Seeking image blob")
	}

	rawData := make([]byte, u.imageHdr[num].size)
	n, err := f.Read(rawData)
	if n != len(rawData) || err != nil {
		return errors.Wrap(err, "Reading image blob")
	}

	data := XORDecode(rawData, u.fileHdr.fileKey[:], true)

	switch num {
	case Internal, External:
		u.imageData[num] = data
	default:
		return fmt.Errorf("Unrecognised image number")
	}

	return nil
}

func (u *exeUpdate) load(f io.ReadSeeker) error {
	err := u.loadFileHeader(f)
	if err != nil {
		return err
	}

	err = u.loadImageHeader(f, Internal)
	if err != nil {
		return err
	}

	err = u.loadImageHeader(f, External)
	if err != nil {
		return err
	}

	err = u.loadImage(f, Internal)
	if err != nil {
		return err
	}

	err = u.loadImage(f, External)
	if err != nil {
		return err
	}

	log.Println(u.fileHdr)
	log.Verbosef("File Header:\n%s\n", hex.Dump(u.fileHdr.rawData))
	log.Verbosef("Image Header (Internal):\n%s\n", hex.Dump(u.imageHdr[Internal].rawData))
	log.Verbosef("Image Header (External):\n%s\n", hex.Dump(u.imageHdr[External].rawData))

	return nil
}

func ParseExeVersion(fname string) (string, error) {
	fname = filepath.Base(fname)
	if filepath.Ext(fname) != ".exe" {
		return "", fmt.Errorf("couldn't determine version from filename")
	}

	toks := strings.SplitAfter(strings.TrimSuffix(fname, ".exe"), "_")
	ver := toks[len(toks)-1]

	v := exeVersions[ver]
	if v == nil {
		return "", errors.Errorf("unrecognised exe version '%s'", ver)
	}

	return ver, nil
}

func LoadExeUpdate(file string, ver string) (*Update, error) {
	v := exeVersions[ver]
	if v == nil {
		return nil, errors.Errorf("unrecognised exe version '%s'", ver)
	}
	eu := &exeUpdate{
		version: v,
	}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	err = eu.load(f)
	if err != nil {
		return nil, err
	}

	u := Update{
		Name:       eu.fileHdr.name,
		Version:    eu.fileHdr.fwVersion,
		IAPVersion: eu.fileHdr.iapVersion,
		FileKey:    binary.LittleEndian.Uint32(eu.fileHdr.fileKey[:]),
		APVID:      eu.fileHdr.apVID,
		APPID:      eu.fileHdr.apPID,
		IAPVID:     eu.fileHdr.iapVID,
		IAPPID:     eu.fileHdr.iapPID,
		Images:     make(map[ImageNumber]*Image),
	}

	for i := Internal; i <= External; i++ {
		d := eu.getImageData(i)
		if d == nil || len(d) == 0 {
			continue
		}

		u.Images[i] = &Image{
			CheckCRC: eu.getCRCValue(i),
			Data:     d,
			ExtraCRC: append([]byte(nil), eu.getCRCData(i)...),
		}
	}

	return &u, nil
}

func (u *exeUpdate) getCRCValue(img ImageNumber) uint16 {
	if u.version.globalCrcData {
		return u.fileHdr.crcValue()
	} else {
		switch img {
		case Internal, External:
			return u.imageHdr[img].crcValue()
		default:
			return 0
		}
	}
}

func (u *exeUpdate) getCRCData(img ImageNumber) []byte {
	if u.version.globalCrcData {
		return u.fileHdr.crcData()
	} else {
		switch img {
		case Internal, External:
			return u.imageHdr[img].crcData()
		default:
			return []byte{}
		}
	}
}

func (u *exeUpdate) getImageData(img ImageNumber) []byte {
	switch img {
	case Internal, External:
		return u.imageData[img]
	default:
		return nil
	}
}

func (u *exeUpdate) getAPVIDPID() (uint16, uint16) {
	return u.fileHdr.apVID, u.fileHdr.apPID
}

func (u *exeUpdate) getIAPVIDPID() (uint16, uint16) {
	return u.fileHdr.iapVID, u.fileHdr.iapPID
}

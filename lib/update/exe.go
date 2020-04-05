// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"encoding/hex"
	"fmt"
	"io"

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

type ExeUpdate struct {
	version  *exeVersion
	fileHdr  *fileHeader
	imageHdr [2]*imageHeader
	image    [2]*FWBlob
}

func NewExeUpdate(version string) *ExeUpdate {
	v := exeVersions[version]
	if v == nil {
		return nil
	}
	return &ExeUpdate{
		version: v,
	}
}

func (u *ExeUpdate) loadFileHeader(f io.ReadSeeker) error {
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

func (u *ExeUpdate) loadImageHeader(f io.ReadSeeker, num ImageNumber) error {
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

func (u *ExeUpdate) loadImage(f io.ReadSeeker, num ImageNumber) error {

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

	blob, err := newFWBlob(rawData, u.fileHdr.fileKey)
	if err != nil {
		return errors.Wrap(err, "Parsing image blob")
	}

	switch num {
	case Internal, External:
		u.image[num] = blob
	default:
		return fmt.Errorf("Unrecognised image number")
	}

	return nil
}

func (u *ExeUpdate) Load(f io.ReadSeeker) error {
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

func (u *ExeUpdate) GetCRCValue(img ImageNumber) uint16 {
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

func (u *ExeUpdate) GetCRCData(img ImageNumber) []byte {
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

func (u *ExeUpdate) GetFWBlob(img ImageNumber) *FWBlob {
	switch img {
	case Internal, External:
		return u.image[img]
	default:
		return &FWBlob{}
	}
}

func (u *ExeUpdate) GetAPVIDPID() (uint16, uint16) {
	return u.fileHdr.apVID, u.fileHdr.apPID
}

func (u *ExeUpdate) GetIAPVIDPID() (uint16, uint16) {
	return u.fileHdr.iapVID, u.fileHdr.iapPID
}

func (u *ExeUpdate) Compatible(other FWVersion) bool {
	return u.fileHdr.fwVersion.Compatible(other)
}

func (u *ExeUpdate) GetVersion() FWVersion {
	if u.fileHdr != nil {
		return u.fileHdr.fwVersion
	}
	return u.version.version
}
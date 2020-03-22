// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/usedbytes/log"
)

type FWVersion struct {
	major, minor100 int
}

func (fwv FWVersion) Matches(other FWVersion) bool {
	return fwv.major == other.major && fwv.minor100 == other.minor100
}

func (fwv FWVersion) String() string {
	return fmt.Sprintf("v%.2f", float64(fwv.major)+float64(fwv.minor100)/100)
}

type Version struct {
	version       FWVersion
	headerLen     int
	chunkLen      int
	globalCrcData bool
}

var versions map[string]*Version = map[string]*Version{
	"1.01": &Version{
		version: FWVersion{
			major:    1,
			minor100: 1,
		},
		headerLen:     0x23c,
		chunkLen:      0x54,
		globalCrcData: false,
	},
	"1.03r": &Version{
		version: FWVersion{
			major:    1,
			minor100: 3,
		},
		headerLen:     0x288,
		chunkLen:      0x10,
		globalCrcData: true,
	},
}

func hexByteString(a []byte) string {
	var chars []string
	for _, v := range a {
		chars = append(chars, fmt.Sprintf("%2x", v))
	}
	return strings.Join(chars, " ")
}

type Update struct {
	version  *Version
	fileHdr  *fileHeader
	imageHdr [2]*imageHeader
	image    [2]*FWBlob
}

type ImageNumber int

const (
	Internal ImageNumber = iota
	External
)

func NewUpdate(version string) *Update {
	v := versions[version]
	if v == nil {
		return nil
	}
	return &Update{
		version: v,
	}
}

func (u *Update) loadFileHeader(f io.ReadSeeker) error {
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

	if !u.fileHdr.fwVersion.Matches(u.version.version) {
		return fmt.Errorf("Expected firmware version %s but got %s", u.version.version, u.fileHdr.fwVersion)
	}

	return nil
}

func (u *Update) loadImageHeader(f io.ReadSeeker, num ImageNumber) error {
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

func (u *Update) loadImage(f io.ReadSeeker, num ImageNumber) error {

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

func (u *Update) Load(f io.ReadSeeker) error {
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

func (u *Update) GetCRCValue(img ImageNumber) uint16 {
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

func (u *Update) GetCRCData(img ImageNumber) []byte {
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

func (u *Update) GetFWBlob(img ImageNumber) *FWBlob {
	switch img {
	case Internal, External:
		return u.image[img]
	default:
		return &FWBlob{}
	}
}

func (u *Update) GetAPVIDPID() (uint16, uint16) {
	return u.fileHdr.apVID, u.fileHdr.apPID
}

func (u *Update) GetIAPVIDPID() (uint16, uint16) {
	return u.fileHdr.iapVID, u.fileHdr.iapPID
}

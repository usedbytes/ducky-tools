// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/sigurn/crc16"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/log"
)

type ProtocolOne struct {
	*usbContext

	crct     *crc16.Table
	crcExtra []byte
}

func newProtocolOne(ctx *usbContext) (Protocol, error) {
	proto := &ProtocolOne{
		usbContext: ctx,
		crct: crc16.MakeTable(crc16.CRC16_XMODEM),
	}

	return proto, nil
}

func (p *ProtocolOne) SetExtraCRCData(data []byte) {
	p.crcExtra = data
}

func (p *ProtocolOne) sendPacket(packet []byte) ([]byte, error) {
	if len(packet) < 0x40 {
		packet = append(packet, make([]byte, 0x40-len(packet))...)
	}

	crc := crc16.Checksum(packet, p.crct)
	crc = crc16.Update(crc, p.crcExtra, p.crct)

	binary.LittleEndian.PutUint16(packet[2:], crc)

	log.Verbose("Write\n", hex.Dump(packet))

	n, err := p.outEp.Write(packet)
	if err != nil {
		return nil, err
	} else if n != len(packet) {
		return nil, errors.New("Short write")
	}

	return packet, nil
}

func (p *ProtocolOne) readPacket(packet []byte) (int, error) {
	if len(packet) != 0x40 {
		return 0, errors.New("Read transfers must be 64 bytes")
	}

	to, cancel := context.WithTimeout(p.bg, 1*time.Second)
	defer cancel()

	n, err := p.inEp.ReadContext(to, packet)
	if err == nil {
		log.Verbose("Read", n, "\n", hex.Dump(packet))
	}

	return n, err
}

func (p *ProtocolOne) ReadData(start uint32, data []byte) (int, error) {
	if p.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x01, 0x02,
		0x00, 0x00, // CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // End
	}

	if len(data) > 0x40 {
		return 0, errors.New("Too long. Split not implemented")
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], start+uint32(len(data)-1))

	_, err := p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	rxbuf := data
	if len(rxbuf) < 0x40 {
		rxbuf = make([]byte, 64)
	}

	n, err := p.readPacket(rxbuf)
	if len(rxbuf) > len(data) {
		copy(data, rxbuf)
	}

	return n, err
}

func (p *ProtocolOne) WriteData(start uint32, data []byte) error {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x01, 0x01,
		0x00, 0x00, // CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // End
	}

	if len(data) > 0x40-len(packet) {
		return errors.New("Too long. Split not implemented")
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], start+uint32(len(data)-1))

	packet = append(packet, data...)
	_, err := p.sendPacket(packet)
	if err != nil {
		return err
	}

	return err
}

// TODO: I have no idea what this does (if anything) and how to detect
// if it fails.
func (p *ProtocolOne) VerifyData(start uint32, data []byte) error {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x01, 0x00,
		0x00, 0x00, // CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // End
	}

	if len(data) > 0x40-len(packet) {
		return errors.New("Too long. Split not implemented")
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], start+uint32(len(data)-1))

	packet = append(packet, data...)
	_, err := p.sendPacket(packet)
	if err != nil {
		return err
	}

	return err
}

// CRCCheck() WILL ERASE THE FIRMWARE IF THE PASSED-IN 'crc' VALUE IS INCORRECT
//
// The correct 'crc' value is derived from data received and a secret string
// stored in the IAP code. In the case of a firmware update, if the following
// sequence is followed, then the correct 'crc' value is returned by
// (*one.Update).GetCRCValue():
//
//   - Erase version string
//   - Erase firmware region
//   - Write encoded firmware data from (*one.Update).GetFWBlob(...).RawData()
//     in 52-byte chunks, via WriteData()
//   - Call CRCCheck() with 'crc' = (*one.Update).GetCRCValue(...)
//
// As well as performing the CRC check on the written data, CRCCheck() calculates
// (and returns) the XMODEM CRC of 'length' bytes starting at 'start'. This is
// returned in the same GET_REPORT response as used for GetStatus(). As a result,
// this function drains the status buffer in order to retrieve the calculated CRC
// value.
func (p *ProtocolOne) CRCCheck(start, length uint32, crc uint16) (uint16, error) {
	if p.closed {
		return 0, closedErr
	}

	// Dummy ping packet and drain status. Ping is just to prevent timeout
	_, err := p.sendPacket([]byte{0xff, 0x00})
	if err != nil {
		return 0, err
	}

	_, err = p.GetStatus()
	if err != nil {
		return 0, err
	}

	packet := []byte{
		0x02, 0x00,
		0x00, 0x00, // Packet CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // Length
		0x00, 0x00, // Check CRC
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], length)
	binary.LittleEndian.PutUint16(packet[12:], crc)

	_, err = p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	status, err := p.RawControl()
	if err != nil {
		return 0, err
	}

	if status[2] != 'O' {
		return 0, errors.New("expected OK response")
	} else if status[3] != 0 {
		return 0, errors.New("expected 3-byte response")
	}

	crc = binary.LittleEndian.Uint16(status[:2])

	return crc, nil
}

// 'toIAP' is ignored when in AP mode. It always resets to IAP
func (p *ProtocolOne) Reset(toIAP bool) error {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x04, 0x00,
		0x00, 0x00, // CRC
	}

	if toIAP {
		packet[1] = 1
	}

	_, err := p.sendPacket(packet)
	if err != nil {
		return err
	}

	// Device will have gone away, so kill the context
	p.Close()

	return err
}

func (p *ProtocolOne) Ping(val byte) (bool, error) {
	if p.closed {
		return false, closedErr
	}

	packet := []byte{
		0xff, val,
		0x00, 0x00, // CRC
	}

	packet, err := p.sendPacket(packet)
	if err != nil {
		return false, err
	}

	rxbuf := make([]byte, 64)
	n, err := p.readPacket(rxbuf)
	if err != nil {
		return false, err
	} else if n != len(rxbuf) {
		return false, errors.New("short read")
	}

	magic := binary.LittleEndian.Uint16(rxbuf)
	if magic != 0xaaff {
		log.Verboseln("unexpected magic")
		return false, nil
	}

	if bytes.Compare(packet[:4], rxbuf[4:8]) != 0 {
		log.Verboseln("val not matched", packet[:4], rxbuf[4:8])
		return false, nil
	}

	return true, nil
}

type IAPInfo struct {
	// I think the layout is like so:
	// Offset: hex bytes
	//   0000:  16 54 - Chip ID, HT32F{16}{54}
	//   0002:  00 11 - Four 4-bit fields, C.B.A.I
	//                  C, B, A: IAP/ISP version
	//                  D: 0 == ISP, 1 == IAP
	//   0004:  00 40 - Programming start address, uint16
	//   0006:  00 04 - "Option Size" (flash page size), uint16
	//   0008:  30 00 - OB_PP bit count. Number of unprotected? pages, uint16
	//   000a:  30 00 - Number of pages.
	//   000c:  00 3c - Address of FW version string, uint16
	rawData []byte
}

func (i IAPInfo) ChipName() string {
	return fmt.Sprintf("HT32F%02x%02x", i.rawData[1], i.rawData[0])
}

func (i IAPInfo) IAPVersion() string {
	// Version is stored in bytes 2/3 as BCD
	//  2  3
	// cb ai
	// Version: a.b.p
	// i == 1 means IAP, 0 means ISP
	bcd := binary.LittleEndian.Uint16(i.rawData[2:3])

	t := "ISP"
	if (bcd >> 12) > 0 {
		t = "IAP"
	}
	ver := config.NewIAPVersion(int(bcd>>12)&0xf, int(bcd>>8)&0xf, int(bcd)&0xf)

	return fmt.Sprintf("%s %s", t, ver)
}

func (i IAPInfo) OptionSize() uint16 {
	return binary.LittleEndian.Uint16(i.rawData[6:8])
}

func (i IAPInfo) OB_PPBits() uint16 {
	return binary.LittleEndian.Uint16(i.rawData[8:10])
}

func (i IAPInfo) FlashSize() uint32 {
	// TODO
	return uint32(binary.LittleEndian.Uint16(i.rawData[10:12])) * uint32(i.OptionSize())
}

func (i IAPInfo) StartAddr() uint32 {
	return uint32(binary.LittleEndian.Uint16(i.rawData[4:6]))
}

func (i IAPInfo) VersionAddr() uint32 {
	return uint32(binary.LittleEndian.Uint16(i.rawData[12:14]))
}

func (i IAPInfo) String() string {
	s := fmt.Sprintf("Chip:         %s\n", i.ChipName())
	s += fmt.Sprintf("Option Size:  0x%04x (%d)\n", i.OptionSize(), i.OptionSize())
	s += fmt.Sprintf("Flash Size:   0x%08x (%d)\n", i.FlashSize(), i.FlashSize())
	s += fmt.Sprintf("OB_PP Bits:   0x%04x (%d)\n", i.OB_PPBits(), i.OB_PPBits())
	s += fmt.Sprintf("Start Addr:   0x%08x\n", i.StartAddr())
	s += fmt.Sprintf("Version Addr: 0x%08x\n", i.VersionAddr())
	return s
}

func (p *ProtocolOne) GetInformation() (IAPInfo, error) {
	if p.closed {
		return IAPInfo{}, closedErr
	}

	packet := []byte{
		0x03, 0x00,
		0x00, 0x00, // CRC
	}

	_, err := p.sendPacket(packet)
	if err != nil {
		return IAPInfo{}, err
	}

	rxbuf := make([]byte, 64)
	n, err := p.readPacket(rxbuf)
	if err != nil {
		return IAPInfo{}, err
	} else if n != len(rxbuf) {
		return IAPInfo{}, errors.New("short read")
	}

	info := IAPInfo{
		rawData: rxbuf,
	}

	return info, nil
}

var versionErasedErr error = errors.New("version string erased")

func IsVersionErased(e error) bool {
	return e == versionErasedErr
}

func (p *ProtocolOne) readVersion(addr uint32) (string, error) {
	// For whatever reason, we have to request a full 64 bytes or we get nothing
	data := make([]byte, 64)
	_, err := p.ReadData(uint32(addr), data)
	if err != nil {
		return "", err
	}

	length := binary.LittleEndian.Uint32(data[:4])
	if length == 0xffffffff {
		return "", versionErasedErr
	}

	if length > 0x40 {
		return "", errors.New("version string too long")
	}

	_, err = p.ReadData(uint32(addr)+4, data)
	if err != nil {
		return "", err
	}

	return string(data[:length]), nil
}

func (p *ProtocolOne) APGetVersion() (config.FWVersion, error) {
	if p.closed {
		return config.FWVersion{}, closedErr
	}

	// 0x2800 is hardcoded in the v1.03 updater, but it doesn't seem
	// to matter - the AP code doesn't seem to pay attention to the
	// address
	data := make([]byte, 64)
	_, err := p.ReadData(0x2800, data)
	if err != nil {
		return config.FWVersion{}, err
	}

	length := binary.LittleEndian.Uint32(data[:4])
	if length == 0xffffffff {
		return config.FWVersion{}, versionErasedErr
	}

	if length > 0x40 {
		return config.FWVersion{}, errors.New("version string too long")
	}

	fwv, err := config.ParseFWVersion(string(data[4 : 4+length]))
	if err != nil {
		return config.FWVersion{}, err
	}

	return fwv, nil
}

func (p *ProtocolOne) GetVersion(i IAPInfo) (config.FWVersion, error) {
	if p.closed {
		return config.FWVersion{}, closedErr
	}

	addr := i.VersionAddr()
	str, err := p.readVersion(addr)
	if err != nil {
		return config.FWVersion{}, err
	}

	fwv, err := config.ParseFWVersion(str)
	if err != nil {
		return config.FWVersion{}, err
	}

	return fwv, nil
}

func (p *ProtocolOne) EraseVersion(i IAPInfo, force bool) error {
	if p.closed {
		return closedErr
	}

	addr := i.VersionAddr()
	str, err := p.readVersion(addr)
	length := len(str) + 4
	if err != nil {
		if !force || !IsVersionErased(err) {
			return err
		}
		length = 0x80 + 4
	}

	err = p.ErasePage(addr, length)
	if err != nil {
		return err
	}

	return nil
}

func (p *ProtocolOne) WriteVersion(i IAPInfo, v config.FWVersion) error {
	if p.closed {
		return closedErr
	}

	addr := i.VersionAddr()

	verStr := v.String()

	data := make([]byte, len(verStr)+4)
	binary.LittleEndian.PutUint32(data, uint32(len(verStr)))
	copy(data[4:], verStr)

	err := p.WriteData(addr, data)
	if err != nil {
		return err
	}

	return nil
}

type StatusCode int

const (
	StatusOK StatusCode = iota
	StatusFail
	StatusUnknown
)

type Status struct {
	code StatusCode
	val  byte
}

func (s Status) IsOK() bool {
	return s.code == StatusOK
}

func (s Status) IsFail() bool {
	return s.code == StatusFail
}

func (s Status) String() string {
	switch s.code {
	case StatusOK:
		return "OK"
	case StatusFail:
		return "Fail"
	default:
		return "???"
	}
}

func (p *ProtocolOne) GetStatus() ([]Status, error) {
	if p.closed {
		return nil, closedErr
	}

	data := make([]byte, 0x40)
	n, err := p.dev.Control(0xa1, 0x1, 0x100, 1, data)
	if err != nil {
		return nil, err
	} else if n != len(data) {
		return nil, errors.New("short read")
	}

	log.Verbose("Status\n", hex.Dump(data))

	var ret []Status
	for _, v := range data {
		switch v {
		case 'O':
			ret = append(ret, Status{code: StatusOK, val: v})
		case 'F':
			ret = append(ret, Status{code: StatusFail, val: v})
		case 0:
			return ret, nil
		default:
			ret = append(ret, Status{code: StatusUnknown, val: v})
		}
	}

	return nil, nil
}

func (p *ProtocolOne) RawControl() ([]byte, error) {
	if p.closed {
		return nil, closedErr
	}

	data := make([]byte, 0x40)
	n, err := p.dev.Control(0xa1, 0x1, 0x100, 1, data)
	if err != nil {
		return nil, err
	} else if n != len(data) {
		return nil, errors.New("short read")
	}

	return data, nil
}

func (p *ProtocolOne) CheckStatus(expected int) error {
	codes, err := p.GetStatus()
	if err != nil {
		return err
	}

	if expected >= 0 && len(codes) != expected {
		return errors.New("unexpected number of status codes")
	}

	for _, p := range codes {
		if p.IsFail() {
			return errors.New("encountered status Fail")
		} else if !p.IsOK() {
			return fmt.Errorf("encountered unknown status code '%v'", p.val)
		}
	}

	return nil
}

func (p *ProtocolOne) ErasePage(start uint32, length int) error {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x00, 0x08,
		0x00, 0x00, // CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // End
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], start+uint32(length-1))

	_, err := p.sendPacket(packet)
	if err != nil {
		return err
	}

	return nil

}

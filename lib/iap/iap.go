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

	"github.com/google/gousb"
	"github.com/pkg/errors"
	"github.com/sigurn/crc16"
	"github.com/usedbytes/ducky-tools/lib/update"
	"github.com/usedbytes/log"
)

var closedErr error = errors.New("context closed")

type Context struct {
	bg    context.Context
	ctx   *gousb.Context
	dev   *gousb.Device
	cfg   *gousb.Config
	intf  *gousb.Interface
	outEp *gousb.OutEndpoint
	inEp  *gousb.InEndpoint

	crct     *crc16.Table
	crcExtra []byte

	closed bool
}

func NewContext(vid, pid uint16) (*Context, error) {
	ctx := &Context{
		bg:   context.Background(),
		ctx:  gousb.NewContext(),
		crct: crc16.MakeTable(crc16.CRC16_XMODEM),
	}

	log.Verbosef("NewContext %04x:%04x\n", vid, pid)

	var err error
	ctx.dev, err = ctx.ctx.OpenDeviceWithVIDPID(gousb.ID(vid), gousb.ID(pid))
	if err != nil {
		// Now I understand what go2 is trying to improve
		ctx.Close()
		return nil, err
	} else if ctx.dev == nil {
		ctx.Close()
		return nil, errors.New("Couldn't find a matching device")
	}

	err = ctx.dev.SetAutoDetach(true)
	if err != nil {
		ctx.Close()
		return nil, err
	}

	num, err := ctx.dev.ActiveConfigNum()
	if err != nil {
		ctx.Close()
		return nil, err
	}

	ctx.cfg, err = ctx.dev.Config(num)
	if err != nil {
		ctx.Close()
		return nil, err
	}

	ctx.intf, err = ctx.cfg.Interface(1, 0)
	if err != nil {
		ctx.Close()
		return nil, err
	}

	for _, v := range ctx.intf.Setting.Endpoints {
		if v.TransferType != gousb.TransferTypeInterrupt {
			ctx.Close()
			return nil, errors.New("Expected to find interrupt endpoints")
		}

		if v.Direction == gousb.EndpointDirectionIn {
			if ctx.inEp != nil {
				ctx.Close()
				return nil, errors.New("Found multiple In endpoints")
			}
			ctx.inEp, err = ctx.intf.InEndpoint(v.Number)
			if err != nil {
				ctx.Close()
				return nil, err
			}
		}

		if v.Direction == gousb.EndpointDirectionOut {
			if ctx.outEp != nil {
				ctx.Close()
				return nil, errors.New("Found multiple Out endpoints")
			}
			ctx.outEp, err = ctx.intf.OutEndpoint(v.Number)
			if err != nil {
				ctx.Close()
				return nil, err
			}
		}
	}

	log.Verboseln(ctx.intf)
	log.Verboseln(ctx.inEp)
	log.Verboseln(ctx.outEp)

	return ctx, nil
}

func (c *Context) Close() {
	if c.closed {
		return
	}

	if c.intf != nil {
		c.intf.Close()
		c.intf = nil
	}
	if c.cfg != nil {
		c.cfg.Close()
		c.cfg = nil
	}
	if c.dev != nil {
		c.dev.Close()
		c.dev = nil
	}
	if c.ctx != nil {
		c.ctx.Close()
		c.ctx = nil
	}

	c.closed = true
}

func (c *Context) SetExtraCRCData(data []byte) {
	c.crcExtra = data
}

func (c *Context) sendPacket(packet []byte) ([]byte, error) {
	if len(packet) < 0x40 {
		packet = append(packet, make([]byte, 0x40-len(packet))...)
	}

	crc := crc16.Checksum(packet, c.crct)
	crc = crc16.Update(crc, c.crcExtra, c.crct)

	binary.LittleEndian.PutUint16(packet[2:], crc)

	log.Verbose("Write\n", hex.Dump(packet))

	n, err := c.outEp.Write(packet)
	if err != nil {
		return nil, err
	} else if n != len(packet) {
		return nil, errors.New("Short write")
	}

	return packet, nil
}

func (c *Context) readPacket(packet []byte) (int, error) {
	if len(packet) != 0x40 {
		return 0, errors.New("Read transfers must be 64 bytes")
	}

	to, cancel := context.WithTimeout(c.bg, 1*time.Second)
	defer cancel()

	n, err := c.inEp.ReadContext(to, packet)
	if err == nil {
		log.Verbose("Read", n, "\n", hex.Dump(packet))
	}

	return n, err
}

func (c *Context) ReadData(start uint32, data []byte) (int, error) {
	if c.closed {
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

	_, err := c.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	rxbuf := data
	if len(rxbuf) < 0x40 {
		rxbuf = make([]byte, 64)
	}

	n, err := c.readPacket(rxbuf)
	if len(rxbuf) > len(data) {
		copy(data, rxbuf)
	}

	return n, err
}

func (c *Context) WriteData(start uint32, data []byte) error {
	if c.closed {
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
	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	return err
}

// TODO: I have no idea what this does (if anything) and how to detect
// if it fails.
func (c *Context) VerifyData(start uint32, data []byte) error {
	if c.closed {
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
	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	return err
}

func (c *Context) CRCCheck(start, length uint32, crc uint16) error {
	if c.closed {
		return closedErr
	}

	packet := []byte{
		0x02, 0x00,
		0x00, 0x00, // Packet CRC
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // End
		0x00, 0x00, // Check CRC
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], start+uint32(length-1))
	binary.LittleEndian.PutUint16(packet[12:], crc)

	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	return err
}

// 'toIAP' is ignored when in AP mode. It always resets to IAP
func (c *Context) Reset(toIAP bool) error {
	if c.closed {
		return closedErr
	}

	packet := []byte{
		0x04, 0x00,
		0x00, 0x00, // CRC
	}

	if toIAP {
		packet[1] = 1
	}

	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	// Device will have gone away, so kill the context
	c.Close()

	return err
}

func (c *Context) Ping(val byte) (bool, error) {
	if c.closed {
		return false, closedErr
	}

	packet := []byte{
		0xff, val,
		0x00, 0x00, // CRC
	}

	packet, err := c.sendPacket(packet)
	if err != nil {
		return false, err
	}

	rxbuf := make([]byte, 64)
	n, err := c.readPacket(rxbuf)
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
	// Version: a.b.c
	// i == 1 means IAP, 0 means ISP
	bcd := binary.LittleEndian.Uint16(i.rawData[2:3])

	t := "ISP"
	if (bcd >> 12) > 0 {
		t = "IAP"
	}
	ver := update.NewIAPVersion(int(bcd>>12)&0xf, int(bcd>>8)&0xf, int(bcd)&0xf)

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

func (c *Context) GetInformation() (IAPInfo, error) {
	if c.closed {
		return IAPInfo{}, closedErr
	}

	packet := []byte{
		0x03, 0x00,
		0x00, 0x00, // CRC
	}

	_, err := c.sendPacket(packet)
	if err != nil {
		return IAPInfo{}, err
	}

	rxbuf := make([]byte, 64)
	n, err := c.readPacket(rxbuf)
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

func (c *Context) readVersion(addr uint32) (string, error) {
	// For whatever reason, we have to request a full 64 bytes or we get nothing
	data := make([]byte, 64)
	_, err := c.ReadData(uint32(addr), data)
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

	_, err = c.ReadData(uint32(addr)+4, data)
	if err != nil {
		return "", err
	}

	return string(data[:length]), nil
}

func (c *Context) APGetVersion() (update.FWVersion, error) {
	if c.closed {
		return update.FWVersion{}, closedErr
	}

	// 0x2800 is hardcoded in the v1.03 updater, but it doesn't seem
	// to matter - the AP code doesn't seem to pay attention to the
	// address
	data := make([]byte, 64)
	_, err := c.ReadData(0x2800, data)
	if err != nil {
		return update.FWVersion{}, err
	}

	length := binary.LittleEndian.Uint32(data[:4])
	if length == 0xffffffff {
		return update.FWVersion{}, versionErasedErr
	}

	if length > 0x40 {
		return update.FWVersion{}, errors.New("version string too long")
	}

	fwv, err := update.ParseFWVersion(string(data[4 : 4+length]))
	if err != nil {
		return update.FWVersion{}, err
	}

	return fwv, nil
}

func (c *Context) GetVersion(i IAPInfo) (update.FWVersion, error) {
	if c.closed {
		return update.FWVersion{}, closedErr
	}

	addr := i.VersionAddr()
	str, err := c.readVersion(addr)
	if err != nil {
		return update.FWVersion{}, err
	}

	fwv, err := update.ParseFWVersion(str)
	if err != nil {
		return update.FWVersion{}, err
	}

	return fwv, nil
}

func (c *Context) EraseVersion(i IAPInfo, force bool) error {
	if c.closed {
		return closedErr
	}

	addr := i.VersionAddr()
	str, err := c.readVersion(addr)
	length := len(str) + 4
	if err != nil {
		if !force || !IsVersionErased(err) {
			return err
		}
		length = 0x80 + 4
	}

	err = c.ErasePage(addr, length)
	if err != nil {
		return err
	}

	return nil
}

func (c *Context) WriteVersion(i IAPInfo, v update.FWVersion) error {
	if c.closed {
		return closedErr
	}

	addr := i.VersionAddr()

	verStr := v.String()

	data := make([]byte, len(verStr)+4)
	binary.LittleEndian.PutUint32(data, uint32(len(verStr)))
	copy(data[4:], verStr)

	err := c.WriteData(addr, data)
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

func (c *Context) GetStatus() ([]Status, error) {
	if c.closed {
		return nil, closedErr
	}

	data := make([]byte, 0x40)
	n, err := c.dev.Control(0xa1, 0x1, 0x100, 1, data)
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

func (c *Context) CheckStatus(expected int) error {
	codes, err := c.GetStatus()
	if err != nil {
		return err
	}

	if expected >= 0 && len(codes) != expected {
		return errors.New("unexpected number of status codes")
	}

	for _, c := range codes {
		if c.IsFail() {
			return errors.New("encountered status Fail")
		} else if !c.IsOK() {
			return fmt.Errorf("encountered unknown status code '%v'", c.val)
		}
	}

	return nil
}

func (c *Context) ErasePage(start uint32, length int) error {
	if c.closed {
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

	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	return nil

}

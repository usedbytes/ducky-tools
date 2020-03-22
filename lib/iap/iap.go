// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/google/gousb"
	"github.com/pkg/errors"
	"github.com/sigurn/crc16"
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

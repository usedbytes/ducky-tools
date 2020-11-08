// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap2

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/google/gousb"
	"github.com/pkg/errors"
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

	closed bool
}

func NewContext(vid, pid uint16) (*Context, error) {
	ctx := &Context{
		bg:   context.Background(),
		ctx:  gousb.NewContext(),
		//crct: crc16.MakeTable(crc16.CRC16_XMODEM),
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

func (c *Context) sendPacket(packet []byte) ([]byte, error) {
	if len(packet) < 0x40 {
		packet = append(packet, make([]byte, 0x40-len(packet))...)
	}

	/*
	crc := crc16.Checksum(packet, c.crct)
	crc = crc16.Update(crc, c.crcExtra, c.crct)

	binary.LittleEndian.PutUint16(packet[2:], crc)
	*/

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

func (c *Context) RawSend(data []byte) error {
	_, err := c.sendPacket(data)
	return err
}

func (c *Context) RawReceive() ([]byte, error) {
	data := make([]byte, 64)
	_, err := c.readPacket(data)
	return data, err
}

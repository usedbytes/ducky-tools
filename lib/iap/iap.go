// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap

import (
	"context"
	"time"

	"github.com/google/gousb"
	"github.com/pkg/errors"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/log"
)

var closedErr error = errors.New("context closed")

type usbContext struct {
	bg    context.Context
	ctx   *gousb.Context
	dev   *gousb.Device
	cfg   *gousb.Config
	intf  *gousb.Interface
	outEp *gousb.OutEndpoint
	inEp  *gousb.InEndpoint

	closed bool
}

type Protocol interface {
	Close()
	Reset(toIAP bool) error
	Update(fw *config.Firmware) error
}

type CRCProtocol interface {
	Protocol
	SetExtraCRCData([]byte)
}

type Context struct {
	dev *config.Device
	iap bool
	proto Protocol
}

func (c *Context) usbConnect(app *config.Application) (Protocol, error) {
	proto, err := NewContextWithProtocol(app.VID, app.PID, string(app.Protocol))

	if err != nil {
		return nil, err
	}

	if len(app.ExtraCRC) != 0 {
		crcproto, ok := proto.(CRCProtocol)
		if !ok {
			proto.Close()
			return nil, errors.New("ExtraCRC provided, but protocol doesn't support ExtraCRC")
		}
		crcproto.SetExtraCRCData(app.ExtraCRC)
	}

	return proto, nil
}

func (c *Context) Reset(toIap bool) error {
	if c.proto == nil {
		return errors.New("not connected")
	}

	if toIap && c.dev.Bootloader == nil {
		return errors.New("reset to iap requested, but bootloader not defined")
	} else if !toIap && c.dev.Application == nil {
		return errors.New("reset to application requested, but application not defined")
	}

	c.proto.Reset(toIap)
	c.proto.Close()
	c.proto = nil

	var app *config.Application
	if toIap {
		app = c.dev.Bootloader
	} else {
		app = c.dev.Application
	}

	var proto Protocol
	var err error
	log.Printf("Reconnect... ")
	for i := 0; i < 10; i++ {
		time.Sleep(1000 * time.Millisecond)
		log.Printf(".")
		proto, err = c.usbConnect(app)
		if err == nil {
			break
		}
	}
	log.Printf("\n")
	if err != nil {
		return err
	}

	c.proto = proto
	c.iap = toIap

	return nil
}

func (c *Context) Update(fw *config.Firmware) error {
	// We always need to be in IAP to update
	err := c.Reset(true)
	if err != nil {
		return err
	}

	err = c.proto.Update(fw)
	if err != nil {
		return err
	}

	// Note: Not c.Reset() because that re-connects, and we don't want
	// that
	c.proto.Reset(false)
	c.proto.Close()
	c.proto = nil

	return nil
}

func (c *Context) Protocol() Protocol {
	return c.proto
}

func (c *Context) Close() {
	c.proto.Close()
	c.proto = nil
}

func NewContext(dev *config.Device) (*Context, error) {
	ctx := &Context{
		dev: dev,
	}

	var proto Protocol
	var err error
	if dev.Application != nil {
		proto, err = ctx.usbConnect(dev.Application)
	}

	if proto == nil && dev.Bootloader != nil {
		proto, err = ctx.usbConnect(dev.Bootloader)
		if err == nil {
			ctx.iap = true
		}
	}

	if err != nil {
		return nil, err
	}

	ctx.proto = proto
	return ctx, nil
}

func NewContextWithProtocol(vid, pid uint16, protocol string) (Protocol, error) {
	ctx := &usbContext{
		bg:   context.Background(),
		ctx:  gousb.NewContext(),
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

	switch protocol {
	case "one":
		return newProtocolOne(ctx)
	case "one2":
		return newProtocolOne2(ctx)
	default:
		return nil, errors.New("unknown protocol")
	}

	return nil, nil
}

func (c *usbContext) Close() {
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

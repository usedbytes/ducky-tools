// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap2

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/binary"
	"time"

	"github.com/google/gousb"
	"github.com/pkg/errors"
	"github.com/usedbytes/log"
)

// Command set:
// 10 02
//     Unknown. Sent before version query.
//     Request and response are all zeroes
// 10 01 00 00 <arg32>
//     Unknown. No response?
// 10 00
//     Unknown.
// 11 <arg8>
//     Reset. arg8 == 1 to reset back to normal
//     arg8 == 0 to reset to IAP
// 12 01
//     Query.
//     Response:
//     0040   12 01 00 00 04 00 02 00 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
// 12 00
//     Query.
//     Response contains lots.
//     0040   12 00 00 00 04 00 00 00 00 00 00 00 d9 04 56 13   ..............V.
//     0050   00 40 04 03 ff ff ff ff 02 00 00 00 ff ff ff ff   .@..............
//     0060   08 01 00 00 00 04 34 00 00 04 4b 42 30 33 35 36   ......4...KB0356
//     0070   00 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00   ................
// 12 20
//     Response:
//     0040   12 20 00 00 1a 00 00 00 56 00 31 00 2e 00 30 00   . ......V.1...0.
//     0050   30 00 2e 00 30 00 32 00 00 00 00 00 00 00 00 00   0...0.2.........
//     0060   00 00 ff ff ff ff ff ff ff ff ff ff ff ff ff ff   ................
//     0070   ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff   ................
// 12 22
//     Response:
//     0040   12 22 00 00 04 00 80 00 02 00 00 00 32 01 00 00   ."..........2...
//     0050   ff ff ff ef 01 00 00 00 00 00 00 00 d9 04 56 03   ..............V.
//     0060   ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff   ................
//     0070   ff ff ff ff ff ff ff ff ff ff ff ff a5 5a 1c 00   .............Z..
// 1d 00
//     Erase
//     Somehow a 'd0' gets in there, but no idea how
//     Request:
//     0040   1d 00 00 00 00 00 00 00 00 d0 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     Response:
//     0040   1d 00 00 00 00 00 00 00 00 cc 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
// 1d 01 00 00 <startaddr> <length>
//     Checksum
//     Request:
//     0040   1d 01 00 00 00 04 00 00 74 a2 00 00 00 00 00 00   ........t.......
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     Response:
//     0040   1d 01 00 00 4d d4 93 e3 00 00 00 00 00 00 00 00   ....M...........
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
// 1e 01 00 00 <arg1>
//     Set write pointer?
//     Request:
//     0040   1e 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     Response:
//     0040   1e 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
// 1e 00 00 00 <arg1>
//     Get write pointer?
//     Request:
//     0040   1e 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     Response:
//     0040   1e 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
// 1f <len>
//     Write data
//     0040   1f 34 00 00 1b a1 c2 e7 7f 7e 08 79 62 7e d5 53   .4.......~.yb~.S
//     0050   5d ba 1e fc f4 2f e8 48 e1 b5 3c 77 3d 00 48 b7   ]..../.H..<w=.H.
//     0060   19 b9 cb d9 a9 be 8c 2a c7 98 67 09 33 3a 52 d4   .......*..g.3:R.
//     0070   f2 12 c3 d0 aa a4 c0 ea 00 00 00 00 00 00 00 00   ................
//     Response: "Get write pointer"
//     0040   1e 02 00 00 9c 04 00 00 00 00 00 00 00 00 00 00   ................
//     0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//     0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................



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

	to, cancel := context.WithTimeout(c.bg, 5*time.Second)
	defer cancel()

	n, err := c.inEp.ReadContext(to, packet)
	if err == nil {
		log.Verbose("Read", n, "\n", hex.Dump(packet))
	}

	return n, err
}

// 'toIAP' is ignored when in AP mode. It always resets to IAP
func (c *Context) Reset(toIAP bool) error {
	if c.closed {
		return closedErr
	}

	packet := []byte{
		0x11, 0x00,
	}

	if !toIAP {
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

func (c *Context) Checksum(start, length uint32) (uint32, error) {
	if c.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x1d, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // Length
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], length)

	_, err := c.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	csum := binary.LittleEndian.Uint32(response[4:])

	return csum, nil
}

func (c *Context) SetWritePointer(addr uint32) (error) {
	if c.closed {
		return closedErr
	}

	packet := []byte{
		0x1e, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Addr
	}

	binary.LittleEndian.PutUint32(packet[4:], addr)

	_, err := c.sendPacket(packet)
	if err != nil {
		return err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return err
	}

	if bytes.Compare(packet, response[:len(packet)]) != 0 {
		return errors.New("command failed")
	}

	return nil
}

func (c *Context) GetWritePointer() (uint32, error) {
	if c.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x1e, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff,
	}

	_, err := c.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	addr := binary.LittleEndian.Uint32(response[4:])

	return addr, nil
}

func (c *Context) Erase() (uint32, error) {
	if c.closed {
		return 0, closedErr
	}

	// This is the packet sent by the official decoder.
	// I can't tell from the code where the 0xd0 comes from, but it matches
	// with the highest address that a checksum can be requested for, so it
	// seems like it could be the length to erase.
	packet := []byte{
		0x1d, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Start?
		0x00, 0xd0, 0x00, 0x00, // Length?
	}

	_, err := c.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	resp := binary.LittleEndian.Uint32(response[8:])

	return resp, nil
}

func (c *Context) ReadChunk(addr uint32) ([]byte, error) {
	if c.closed {
		return nil, closedErr
	}

	packet := []byte{
		0x12, 0x20, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Chunk
	}

	if addr % 0x3c != 0 {
		return nil, errors.New("addr must be aligned to 0x3c")
	}

	chunk := addr / 0x3c
	binary.LittleEndian.PutUint32(packet[4:], chunk)

	_, err := c.sendPacket(packet)
	if err != nil {
		return nil, err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return nil, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return nil, errors.New("command failed")
	}

	return response[4:], nil
}

func (c *Context) Write(data []byte) (uint32, error) {
	if c.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x1f, 0x00, 0x00, 0x00,
	}

	if len(data) > 0x40-len(packet) {
		return 0, errors.New("Too long. Split not implemented")
	}

	packet[1] = byte(len(data))

	packet = append(packet, data...)
	_, err := c.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = c.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if response[0] != 0x1e || response[1] != 0x02 {
		return 0, errors.New("command failed")
	}

	addr := binary.LittleEndian.Uint32(response[4:])

	return addr, nil
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

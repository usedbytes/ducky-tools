// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package iap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/binary"
	"time"

	"github.com/pkg/errors"
	"github.com/usedbytes/ducky-tools/lib/config"
	"github.com/usedbytes/ducky-tools/lib/xor"
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

type ProtocolOne2 struct {
	*usbContext
}

func newProtocolOne2(ctx *usbContext) (Protocol, error) {
	proto := &ProtocolOne2{
		usbContext: ctx,
	}

	return proto, nil
}

func (p *ProtocolOne2) sendPacket(packet []byte) ([]byte, error) {
	if len(packet) < 0x40 {
		packet = append(packet, make([]byte, 0x40-len(packet))...)
	}

	log.Verbose("Write\n", hex.Dump(packet))

	n, err := p.outEp.Write(packet)
	if err != nil {
		return nil, err
	} else if n != len(packet) {
		return nil, errors.New("Short write")
	}

	return packet, nil
}

func (p *ProtocolOne2) readPacket(packet []byte) (int, error) {
	if len(packet) != 0x40 {
		return 0, errors.New("Read transfers must be 64 bytes")
	}

	to, cancel := context.WithTimeout(p.bg, 5*time.Second)
	defer cancel()

	n, err := p.inEp.ReadContext(to, packet)
	if err == nil {
		log.Verbose("Read", n, "\n", hex.Dump(packet))
	}

	return n, err
}

// 'toIAP' is ignored when in AP mode. It always resets to IAP
func (p *ProtocolOne2) Reset(toIAP bool) error {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x11, 0x00,
	}

	if !toIAP {
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

func (p *ProtocolOne2) Ping(val byte) (bool, error) {
	if p.closed {
		return false, closedErr
	}

	packet := []byte{
		0x10, 0x02,
		val,
	}

	packet, err := p.sendPacket(packet)
	if err != nil {
		return false, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return false, err
	}

	if bytes.Compare(packet, response[:len(packet)]) != 0 {
		return false, errors.New("command failed")
	}

	return true, nil
}

func Checksum(data []byte) uint32 {
	lenWords := (len(data) + 3) / 4
	tmp := make([]byte, lenWords * 4)
	copy(tmp, data)

	var sum uint32
	for i := 0; i < lenWords; i++ {
		sum += binary.LittleEndian.Uint32(tmp[i * 4:(i + 1) * 4])
	}

	return sum
}

func (p *ProtocolOne2) Checksum(start, length uint32) (uint32, error) {
	if p.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x1d, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Start
		0x00, 0x00, 0x00, 0x00, // Length
	}

	binary.LittleEndian.PutUint32(packet[4:], start)
	binary.LittleEndian.PutUint32(packet[8:], length)

	_, err := p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	csum := binary.LittleEndian.Uint32(response[4:])

	return csum, nil
}

func (p *ProtocolOne2) SetWritePointer(addr uint32) (error) {
	if p.closed {
		return closedErr
	}

	packet := []byte{
		0x1e, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Addr
	}

	binary.LittleEndian.PutUint32(packet[4:], addr)

	_, err := p.sendPacket(packet)
	if err != nil {
		return err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return err
	}

	if bytes.Compare(packet, response[:len(packet)]) != 0 {
		return errors.New("command failed")
	}

	return nil
}

func (p *ProtocolOne2) GetWritePointer() (uint32, error) {
	if p.closed {
		return 0, closedErr
	}

	packet := []byte{
		0x1e, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff,
	}

	_, err := p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	addr := binary.LittleEndian.Uint32(response[4:])

	return addr, nil
}

func (p *ProtocolOne2) Erase() (uint32, error) {
	if p.closed {
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

	_, err := p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if bytes.Compare(packet[:4], response[:4]) != 0 {
		return 0, errors.New("command failed")
	}

	resp := binary.LittleEndian.Uint32(response[8:])

	return resp, nil
}

func (p *ProtocolOne2) ReadChunk(chunk byte) ([]byte, error) {
	if p.closed {
		return nil, closedErr
	}

	packet := []byte{
		0x12, 0x20,
	}

	if chunk >= 0x10 {
		return nil, errors.New("addr out of range")
	}

	packet[1] = chunk + 0x20

	_, err := p.sendPacket(packet)
	if err != nil {
		return nil, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return nil, err
	}

	if bytes.Compare(packet[:len(packet)], response[:len(packet)]) != 0 {
		return nil, errors.New("command failed")
	}

	return response[4:], nil
}

func (p *ProtocolOne2) Write(data []byte) (uint32, error) {
	if p.closed {
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
	_, err := p.sendPacket(packet)
	if err != nil {
		return 0, err
	}

	response := [0x40]byte{}
	_, err = p.readPacket(response[:])
	if err != nil {
		return 0, err
	}

	if response[0] != 0x1e || response[1] != 0x02 {
		return 0, errors.New("command failed")
	}

	addr := binary.LittleEndian.Uint32(response[4:])

	return addr, nil
}

func (p *ProtocolOne2) RawSend(data []byte) error {
	_, err := p.sendPacket(data)
	return err
}

func (p *ProtocolOne2) RawReceive() ([]byte, error) {
	data := make([]byte, 64)
	_, err := p.readPacket(data)
	return data, err
}

func (p *ProtocolOne2) Update(fw *config.Firmware) error {
	internal, ok := fw.Images[string(config.Internal)]
	if !ok || len(internal.Data) == 0 {
		return errors.New("no data for internal image")
	}

	meta, ok := fw.Images[string(config.Metadata)]
	if !ok || len(meta.Data) == 0 {
		return errors.New("no data for metadata image")
	}

	if meta.XferEncoded {
		return errors.New("metadata image should not be XferEncoded")
	}

	data := make([]byte, len(internal.Data))
	copy(data, internal.Data)

	if !internal.XferEncoded {
		if len(internal.XferKey) == 0 {
			return errors.New("image must be XferEncoded, or XferKey must be specified")
		}

		xor.Decode(data, internal.XferKey, false)
	}

	expected := Checksum(data)

	// Erase
	log.Println("Erase...")
	val, err := p.Erase()
	if err != nil {
		return err
	}
	log.Verbosef("Erase response: %x\n", val)

	err = p.SetWritePointer(0x0400)
	if err != nil {
		return err
	}

	// Get write pointer, check 0x0400
	val, err = p.GetWritePointer()
	if err != nil {
		return err
	}

	log.Verbosef("Write pointer: %x\n", val)
	if val != 0x0400 {
		return errors.New("unexpected write pointer")
	}

	// Write data, check returned value is addr + len(data)
	log.Println("Write program...")
	cursor := uint32(0x400)
	packetLen := 0x34
	numChunks := (len(data) + (packetLen - 1)) / packetLen
	for i := 0; i < numChunks; i++ {
		start := i * packetLen
		end := (i + 1) * packetLen
		if end > len(data) {
			end = len(data)
		}

		resp, err := p.Write(data[start:end])
		if err != nil {
			return err
		}

		cursor += uint32(end - start)
		if resp != cursor {
			return errors.New("unexpected cursor response")
		}
	}

	// Checksum, check against data.
	log.Println("Validate checksum...")
	csum, err := p.Checksum(0x400, uint32(len(data)))
	if err != nil {
		return err
	}

	log.Verbosef("Checksum: %08x\n", csum)
	if csum != expected {
		return errors.New("checksum mismatch")
	}

	// Set write pointer 0x000
	err = p.SetWritePointer(0x000)
	if err != nil {
		return err
	}

	// Get write pointer, check 0x000
	val, err = p.GetWritePointer()
	if err != nil {
		return err
	}

	log.Verbosef("Write pointer: %x\n", val)
	if val != 0x00 {
		return errors.New("unexpected write pointer")
	}

	// Write header
	log.Println("Write metadata...")
	cursor = uint32(0x0)
	numChunks = (len(meta.Data) + (packetLen - 1)) / packetLen
	for i := 0; i < numChunks; i++ {
		start := i * packetLen
		end := (i + 1) * packetLen
		if end > len(meta.Data) {
			end = len(meta.Data)
		}

		resp, err := p.Write(meta.Data[start:end])
		if err != nil {
			return err
		}

		cursor += uint32(end - start)
		if resp != cursor {
			return errors.New("unexpected cursor response")
		}
	}

	log.Println("Check metadata...")
	var checkMeta []byte

	for i := 0; i < (len(meta.Data) + 0x3c - 1) / 0x3c; i++ {
		tmp, err := p.ReadChunk(byte(i))
		if err != nil {
			return err
		}
		checkMeta = append(checkMeta, tmp...)
	}

	if bytes.Compare(checkMeta, meta.Data) != 0 {
		return errors.New("metadata mistmatch")
	}

	log.Println("Success!")

	return nil
}

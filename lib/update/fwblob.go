// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

type FWBlob struct {
	rawData []byte
}

func newFWBlob(rawData []byte, key [4]byte) (*FWBlob, error) {
	blob := &FWBlob{
		rawData: rawData,
	}

	for i, _ := range blob.rawData {
		blob.rawData[i] = blob.rawData[i] ^ key[i%4] ^ byte(i)
	}

	return blob, nil
}

func (fwb *FWBlob) RawData() []byte {
	return fwb.rawData
}

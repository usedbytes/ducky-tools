// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

func XORDecode(data []byte, key []byte, withIdx bool) []byte {
	res := make([]byte, len(data))
	for i := 0; i < len(data); {
		for j := 0; j < len(key); i, j = i+1, j+1 {
			v := data[i] ^ key[j]
			if withIdx {
				v = v ^ byte(i)
			}
			res[i] = v
		}
	}
	return res
}

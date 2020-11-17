// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package one

type ImageNumber int

const (
	Internal ImageNumber = iota
	External
)

func (i ImageNumber) String() string {
	switch i {
	case Internal:
		return "internal"
	case External:
		return "external"
	}

	return "???"
}

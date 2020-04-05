// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package update

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

// Not totally sure about this
type HWVersion int

const (
	HWVersionUnknown HWVersion = 0
	HWVersionV1      HWVersion = 1 // US
	HWVersionV2                = 2 // EU
)

func (hwv HWVersion) String() string {
	if hwv == HWVersionUnknown {
		return "V?"
	}
	return fmt.Sprintf("V%d", hwv)
}

func (hwv HWVersion) Matches(other HWVersion) bool {
	return hwv == other
}

func (hwv HWVersion) Compatible(other HWVersion) bool {
	return (hwv == HWVersionUnknown) || (other == HWVersionUnknown) || hwv == other
}

var hwvRE *regexp.Regexp = regexp.MustCompile("V([12])\\.")

func ParseHWVersion(str string) (HWVersion, error) {
	matches := hwvRE.FindStringSubmatch(str)
	if len(matches) != 2 {
		return HWVersionUnknown, fmt.Errorf("Can't parse: '%s'", str)
	}

	var val HWVersion
	n, err := fmt.Sscanf(matches[1], "%d", &val)
	if n != 1 || err != nil {
		return HWVersionUnknown, fmt.Errorf("Can't parse: '%s'", str)
	}

	return val, nil
}

type FWVersion struct {
	hwv             HWVersion
	major, minor100 int
}

func ParseFWVersion(str string) (FWVersion, error) {
	hwv, err := ParseHWVersion(str)
	if err != nil {
		return FWVersion{}, err
	}

	var val float64
	n, err := fmt.Sscanf(str[3:], "%f", &val)
	if n != 1 || err != nil {
		return FWVersion{}, fmt.Errorf("Can't parse: '%s'", str[3:])
	}

	major, minor := math.Modf(val)

	return FWVersion{
		hwv:      hwv,
		major:    int(math.Floor(major)),
		minor100: int(math.Floor(minor * 100)),
	}, nil
}

func (fwv FWVersion) Matches(other FWVersion) bool {
	return fwv.hwv.Matches(other.hwv) && fwv.major == other.major && fwv.minor100 == other.minor100
}

// Compatibility for the major/minor isn't clear, so let's be conservative
func (fwv FWVersion) Compatible(other FWVersion) bool {
	return fwv.hwv.Compatible(other.hwv) && fwv.major == other.major
}

func (fwv FWVersion) String() string {
	return fmt.Sprintf("%s.%.2f", fwv.hwv, float64(fwv.major)+float64(fwv.minor100)/100)
}

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

type IAPVersion struct {
	a, b, c int
}

var IAPVersion100 = IAPVersion{a: 1, b: 0, c: 0}

func NewIAPVersion(a, b, c int) IAPVersion {
	return IAPVersion{a: a, b: b, c: c}
}

var iapRE *regexp.Regexp = regexp.MustCompile("V([0-9]+)\\.([0-9]+)\\.([0-9]+)")

func ParseIAPVersion(str string) (IAPVersion, error) {
	matches := iapRE.FindStringSubmatch(str)
	if len(matches) != 4 {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s'", str)
	}
	a, err := strconv.Atoi(matches[1])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s'", str)
	}
	b, err := strconv.Atoi(matches[2])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s'", str)
	}
	c, err := strconv.Atoi(matches[3])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s'", str)
	}

	return NewIAPVersion(a, b, c), nil
}

func (iapv IAPVersion) Matches(other IAPVersion) bool {
	return iapv.a == other.a && iapv.b == other.b && iapv.c == other.c
}

func (iapv IAPVersion) String() string {
	return fmt.Sprintf("V%0d.%0d.%0d", iapv.a, iapv.b, iapv.c)
}

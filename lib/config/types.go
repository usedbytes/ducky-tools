// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package config

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

func (fwv *FWVersion) UnmarshalText(text []byte) error {
	parsed, err := ParseFWVersion(string(text))
	(*fwv) = parsed
	return err
}

func (fwv *FWVersion) MarshalText() ([]byte, error) {
	return []byte(fwv.String()), nil
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

type ImageType string

const (
	Internal ImageType = "internal"
	External           = "external"
	Metadata           = "metadata"
)

func (i *ImageType) String() string {
	return string(*i)
}

func (i *ImageType) UnmarshalText(text []byte) error {
	str := ImageType(text)
	switch str {
	case Internal:
		*i = Internal
	case External:
		*i = External
	case Metadata:
		*i = Metadata
	default:
		return fmt.Errorf("unrecognised image type: %s", str)
	}

	return nil
}

func (i *ImageType) MarshalText() ([]byte, error) {
	return []byte(string(*i)), nil
}

type IAPVersion struct {
	a, b, c int
}

var IAPVersion100 = IAPVersion{a: 1, b: 0, c: 0}

func NewIAPVersion(a, b, c int) IAPVersion {
	return IAPVersion{a: a, b: b, c: c}
}

func (i *IAPVersion) UnmarshalText(text []byte) error {
	parsed, err := ParseIAPVersion(string(text))
	(*i) = parsed
	return err
}

func (i *IAPVersion) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

var iapRE *regexp.Regexp = regexp.MustCompile("V([0-9]+)\\.([0-9]+)\\.([0-9]+)")

func ParseIAPVersion(str string) (IAPVersion, error) {
	matches := iapRE.FindStringSubmatch(str)
	if len(matches) != 4 {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s'. Not 4 matches", str)
	}
	a, err := strconv.Atoi(matches[1])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s' (a)", str)
	}
	b, err := strconv.Atoi(matches[2])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s' (b)", str)
	}
	c, err := strconv.Atoi(matches[3])
	if err != nil {
		return IAPVersion{}, fmt.Errorf("Can't parse: '%s' (c)", str)
	}

	return NewIAPVersion(a, b, c), nil
}

func (iapv IAPVersion) Matches(other IAPVersion) bool {
	return iapv.a == other.a && iapv.b == other.b && iapv.c == other.c
}

func (iapv IAPVersion) String() string {
	return fmt.Sprintf("V%0d.%0d.%0d", iapv.a, iapv.b, iapv.c)
}

type Protocol string

const (
	One  Protocol = "one"
	One2          = "one2"
)

func (p *Protocol) String() string {
	return string(*p)
}

func (p *Protocol) UnmarshalText(text []byte) error {
	str := Protocol(text)
	switch str {
	case One:
		*p = One
	case One2:
		*p = One2
	default:
		return fmt.Errorf("unrecognised protocol type: %s", str)
	}

	return nil
}

func (p *Protocol) MarshalText() ([]byte, error) {
	return []byte(string(*p)), nil
}

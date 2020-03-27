Ducky One firmware tools
========================

This is the result of some time spent reverse-engineering the Ducky One keyboard
firmware updater. It can (in theory) be used to update Ducky One firmware on
platforms other than Windows.

**!!! Use this at your own risk! Everything I've learned indicates that the
keyboard is relatively robust against bricking, but this code is likely to have
bugs, and except for the sample-of-one test on my own Ducky One, it's largely
untested !!!**

## `lib/update`

Contains code for dealing with the updater `.exe` file, extracting version
information and the firmware blob itself.

## `lib/iap`

Contains code for working with the In-Application Programming (IAP) code on the
keyboard, for erasing and flashing.

## `cmd/ducky`

A simple application for testing some IAP basics and flashing firmware

Example usage to flash an update:

```
# ducky iap update One_TKL_EU_L_1.03r.exe
```

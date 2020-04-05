Ducky One firmware tools
========================

This is the result of some time spent reverse-engineering the Ducky One
keyboard firmware updater. It can (in theory) be used to extract and update
Ducky One firmware on platforms other than Windows.

**!!! Use this at your own risk! Everything I've learned indicates that the
keyboard is relatively robust against bricking, but this code is likely to have
bugs, and except for the sample-of-one test on my own Ducky One, it's largely
untested !!!**

## `lib/update`

Contains code for handling "Updates", consisting of firmware blobs and the
metadata related to them.

This can extract Updates from Ducky's `.exe` updater programs, and read/write
`.toml`-based update files created by this tool.

## `lib/iap`

Contains code for working with the In-Application Programming (IAP) code on the
keyboard, for erasing, flashing, retrieving info, etc.

## `cmd/ducky`

Application for accessing the above libraries.

## Installation

First, install `go` - https://golang.org/. At least version 1.11 for `go mod`
support.

This also uses [`gousb`
(https://github.com/google/gousb)](https://github.com/google/gousb), which
itself depends on `libusb-1.0`. This should be an easy dependency to satisfy on
Linux and Mac.  Consult the `gousb` page for more information.

Then:

```
git clone https://github.com/usedbytes/ducky-tools
cd ducky-tools
go build ./cmd/ducky

./ducky help
```

## `ducky extract`

This extracts the information from an update file (`.exe` or `.toml`) and writes
it out to a `.toml`-based description and set of binary files.

Example usage:

```
./ducky extract One_TKL_EU_L_1.03r.exe
```

This will extract the firmware blob and some other data from the `.exe` updater
into files in the current working directory, with a description stored in
`One_TKL_EU_L_1.03r.exe.toml`.

This `.toml` file can be used as an input to `ducky iap update` (see below).

The firmware blob itself will be written to
`One_TKL_EU_L_1.03r.exe.internal.enc.bin`. Note that this data is likely to be
scrambled with a 52-byte XOR key, and so won't look like Arm/Thumb code.

The keyboard expects to receive the scrambled data during the programming
process, and descrambles it with a key which is only stored in the keyboard and
not the updater.

If the XOR key is known, it can be passed as an argument to the `extract`
command, in which case the data will be decoded to `<name>.internal.plain.bin`:

```
./ducky extract --xferkey key.bin One_TKL_EU_L_1.03r.exe
```

The `extractkey` command below attempts to recover the XOR scrambling key from
the encoded firmware by applying some heursitics.

## `ducky extractkey`

This attempts to derive the 52-byte scrambling key from an encoded update. It
can be provided with either an `.exe` or `.toml` input file.

The process is based on finding the most-common byte in each position in the
data, with some fix-ups based on the assumption that the end of the blob is
zeroed.

This process may be unreliable! However, if the input contains a "CheckCRC"
(e.g. it's either a Ducky `.exe` updater, or is derived from one), then errors
in the derivation will be detected.

Example usage:
```
./ducky extractkey --out key.bin One_TKL_EU_L_1.03r.exe
```

## `iap` Commands

Depending on your USB permissions, `iap` subcommands may required elevated
permissions (`sudo`).

### `ducky iap test`

Runs some (theoretically) non-destructive tests to verify the keyboard can enter
IAP mode and acts as expected. An input file (`.exe` or `.toml`) is required for
VID/PID and version information.

Example usage:
```
./ducky iap test One_TKL_EU_L_1.03r.exe
```

### `ducky iap update`

Updates the keyboard with the firmware contained in the provided file (`.exe` or
`.toml`). If the file is not XOR-scrambled (`xfer_encoded = true` in the `.toml` file),
then the 52-byte XOR key must be provided via `xfer_key_file`.

Example usage:
```
./ducky iap test One_TKL_EU_L_1.03r.exe.toml
```

### `ducky iap dump`

This (ab)uses the `IAP_CheckCRC()` functionality to dump an arbitrary region
of the keyboard's flash or memory.

The IAP code in the keyboard conducts a CRC check on the received data, and in
the case of any mismatch, it **will erase the firmware**. This should be
recoverable either using the `update` command or an official Ducky updater.

The code is implemented to provide correct CRC values and so avoid accidental
erasure, but _you have been warned!_

Example usage (dump 16kB from address 0):
```
./ducky iap dump -o out.bin -s 0x0000 -l 0x4000 One_TKL_EU_L_1.03r.exe.toml
```

## `.toml` file description

The `.toml` files used by this tool have the following structure:

```
# Optional. Descriptive name.
name = "One_TKL_EU_L_1.03r"

# Optional. 4-byte XOR key used for scrambling all data in the `.exe`. Not used,
# but would be needed to reconstruct a valid patched `.exe` updater.
file_key = 0x456789ab

# Required. Version of the IAP protocol to be used. Only V1.0.0 is supported.
iap_version = "V1.0.0"

# Required. Version of the firmware. 'V2' seems to mean EU hardware, 'V1' for US.
# This should have the format: 'Vx.y.zz'.
version = "V2.1.03"

# Required. VID and PID for "AP" (Application) and "IAP" (In-Application Programming)
# modes
ap_vid_pid = [0x04D9, 0x0188]
iap_vid_pid = [0x04D9, 0x1188]

# Required. A map of images. Only "internal" is supported
[images.internal]
# Optional if `xfer_key_file` is provided. CheckCRC value for the firmware.
# This will be calculated automatically using `xfer_key_file` if not included
check_crc = 0xebf5

# Optional, defaults to false. Whether the data in `data_file` is scrambled
# with the 4-byte XOR key.
file_encoded = false

# Optional, defaults to false. Whether the data in `data_file` is scrambled
# with the 52-byte XOR key. If 'false' then `xfer_key_file` must be provided.
xfer_encoded = true

# Optional. Filename of a binary file containing the 52-byte XOR key.
# If `xfer_encoded` is true, this is not required. If this is set, then an
# `extract` operation will automatically decode the data.
xfer_key_file = "xferkey.bin"

# Required. Data file containing the firmware data. The data may be stored
# scrambled with the `file_key`, `xfer_key` or both, depending on the fields
# above.
data_file = "internal.enc.bin"

# Required. Extra CRC data which is required to generate correct packet CRCs.
extra_crc_data_file = "extracrc.bin"
```

## Extracting, modifying and re-flashing firmware

The following process allows for flashing of modified firmware:

```
# First, extract the 52-byte XOR key, to allow us to get descrambled firmware
./ducky extractkey -o out.key One_TKL_EU_L_1.03r.exe

# Then extract and descramble the firmware
./ducky extract -o out.toml One_TKL_EU_L_1.03r.exe

# Now modify `out.toml` and remove the `check_crc` line. Modifying the firmware
# will invalidate this, so we must remove it to have it calculated automatically
sed -i '/check_crc/d' out.toml

# Make whatever modifications you want to the firmware (internal.plain.bin file)
#
# Be careful!
#
# If you get it wrong, you might be unable to get back in to IAP mode to
# recover. Entering IAP mode depends on the firmware responding to a command
# over USB.
# Specifically, to enter IAP mode:
#  - the chip needs to be reset with the FMC SBVT1 register (0x40080304) set to
#    0x55AAFAF5, or
#  - the "version page" needs to be erased in flash, or
#  - the FW stack pointer and/or reset vector need to be invalid in flash.

# Re-flash the modified firmware
./ducky iap update out.toml
```

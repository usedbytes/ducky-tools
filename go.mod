module github.com/usedbytes/ducky-tools

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/cheggaaa/pb/v3 v3.0.5
	github.com/google/gousb v0.0.0-20190812193832-18f4c1d8a750
	github.com/pkg/errors v0.9.1
	github.com/sigurn/crc16 v0.0.0-20160107003519-da416fad5162
	github.com/sigurn/utils v0.0.0-20190728110027-e1fefb11a144 // indirect
	github.com/urfave/cli/v2 v2.2.0
	github.com/usedbytes/log v0.0.0-20200327231049-dcca836ed393
)

replace github.com/BurntSushi/toml => github.com/usedbytes/toml v0.3.2-0.20200404115030-940371987070

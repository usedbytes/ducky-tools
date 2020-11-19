package config

import (
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

func replaceFilenameChars(in string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' {
			return '_'
		}

		if strings.ContainsRune("\t\n\f\r%<>/'\"\\`:{}()$+*?|@!", r) {
			return -1
		}

		return r
	}, in)
}

func (fw *Firmware) GenerateFilenames() {
	var parts []string

	parts = append(parts, "image")

	if len(fw.DeviceName) != 0 {
		parts = append(parts, fw.DeviceName)
	}
	if len(fw.Name) != 0 {
		parts = append(parts, fw.Name)
	}
	if fw.Version != nil {
		parts = append(parts, fw.Version.String())
	}

	base := strings.Join(parts, "_")
	for k, v := range fw.Images {
		if len(v.Data) == 0 {
			continue
		}

		hash := crc32.Checksum(v.Data, crc32.IEEETable)

		fname := fmt.Sprintf("%s.%08x.%s.bin", base, hash, k)

		v.DataFile = replaceFilenameChars(fname)

		if len(v.XferKey) != 0 {
			parts[0] = "xferkey"
			base := strings.Join(parts, "_")
			hash := crc32.Checksum(v.XferKey, crc32.IEEETable)
			fname := fmt.Sprintf("%s.%08x.%s.bin", base, hash, k)

			v.XferKeyFile = replaceFilenameChars(fname)
		}
	}
}

func (app *Application) GenerateFilenames(name string) {
	if len(app.ExtraCRC) == 0 {
		return
	}

	parts := []string{}
	if len(name) == 0 {
		parts = append(parts, name)
	}

	parts = append(parts, fmt.Sprintf("%04x_%04x", app.VID, app.PID))
	parts = append(parts, "extracrc")
	parts = append(parts, fmt.Sprintf("%08x", crc32.Checksum(app.ExtraCRC, crc32.IEEETable)))

	fname := strings.Join(parts, "_") + ".bin"
	app.ExtraCRCFile = replaceFilenameChars(fname)
}

func (dev *Device) GenerateFilenames() {
	if dev.Application != nil {
		dev.Application.GenerateFilenames(dev.Name)
	}

	if dev.Bootloader != nil {
		dev.Bootloader.GenerateFilenames(dev.Name)
	}

	for _, fw := range dev.Firmwares {
		fw.GenerateFilenames()
	}
}

func (app *Application) LoadData() error {
	if len(app.ExtraCRCFile) != 0 {
		f, err := os.Open(app.ExtraCRCFile)
		if err != nil {
			return err
		}
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		app.ExtraCRC = data
	}

	return nil
}

func (app *Application) WriteData() error {
	if len(app.ExtraCRC) != 0 {
		if len(app.ExtraCRCFile) == 0 {
			return errors.New("can't write ExtraCRC - no filename")
		}

		f, err := os.Create(app.ExtraCRCFile)
		if err != nil {
			return err
		}

		n, err := f.Write(app.ExtraCRC)
		if n != len(app.ExtraCRC) {
			f.Close()
			return errors.New("short write for ExtraCRC")
		} else if err != nil {
			f.Close()
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (img *Image) LoadData() error {
	if len(img.DataFile) != 0 {
		f, err := os.Open(img.DataFile)
		if err != nil {
			return err
		}
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		img.Data = data
	}

	if len(img.XferKeyFile) != 0 {
		f, err := os.Open(img.XferKeyFile)
		if err != nil {
			return err
		}
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		img.XferKey = data
	}

	return nil
}

func (img *Image) WriteData() error {
	if len(img.Data) != 0 {
		if len(img.DataFile) == 0 {
			return errors.New("can't write Data - no filename")
		}

		f, err := os.Create(img.DataFile)
		if err != nil {
			return err
		}

		n, err := f.Write(img.Data)
		if n != len(img.Data) {
			f.Close()
			return errors.New("short write for Data")
		} else if err != nil {
			f.Close()
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}
	}

	if len(img.XferKey) != 0 {
		if len(img.XferKeyFile) == 0 {
			return errors.New("can't write XferKey - no filename")
		}

		f, err := os.Create(img.XferKeyFile)
		if err != nil {
			return err
		}

		n, err := f.Write(img.XferKey)
		if n != len(img.XferKey) {
			f.Close()
			return errors.New("short write for XferKey")
		} else if err != nil {
			f.Close()
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) LoadData() error {
	var err error

	for _, dev := range c.Devices {
		if dev.Application != nil {
			err = dev.Application.LoadData()
			if err != nil {
				return err
			}
		}
		if dev.Bootloader != nil {
			err = dev.Bootloader.LoadData()
			if err != nil {
				return err
			}
		}
		for _, fw := range dev.Firmwares {
			for _, img := range fw.Images {
				err := img.LoadData()
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Config) WriteData() error {
	var err error

	for _, dev := range c.Devices {
		if dev.Application != nil {
			err = dev.Application.WriteData()
			if err != nil {
				return err
			}
		}
		if dev.Bootloader != nil {
			err = dev.Bootloader.WriteData()
			if err != nil {
				return err
			}
		}
		for _, fw := range dev.Firmwares {
			for _, img := range fw.Images {
				err := img.WriteData()
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Config) WriteTOML(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	enc := toml.NewEncoder(f)
	err = enc.Encode(c)
	if err != nil {
		f.Close()
		return err
	}

	err = f.Close()
	return err
}

func (c *Config) Write(filename string) error {
	err := c.WriteData()
	if err != nil {
		return err
	}

	return c.WriteTOML(filename)
}

func LoadConfig(filename string) (*Config, error) {
	var cfg = &Config{}
	_, err := toml.DecodeFile(filename, cfg)
	if err != nil {
		return nil, err
	}

	err = cfg.LoadData()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

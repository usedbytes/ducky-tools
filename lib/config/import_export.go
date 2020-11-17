package config

import (
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

func (exe *Exe) LoadData() error {
	if len(exe.ExtraCRCFile) != 0 {
		f, err := os.Open(exe.ExtraCRCFile)
		if err != nil {
			return err
		}
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		exe.ExtraCRC = data
	}

	return nil
}

func (exe *Exe) WriteData() error {
	if len(exe.ExtraCRC) != 0 {
		if len(exe.ExtraCRCFile) == 0 {
			return errors.New("can't write ExtraCRC - no filename")
		}

		f, err := os.Create(exe.ExtraCRCFile)
		if err != nil {
			return err
		}

		n, err := f.Write(exe.ExtraCRC)
		if n != len(exe.ExtraCRC) {
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

	return nil
}

func (c *Config) LoadData() error {
	if c.Exe != nil {
		err := c.Exe.LoadData()
		if err != nil {
			return err
		}
	}

	for _, fw := range c.Firmwares {
		for _, img := range fw.Images {
			err := img.LoadData()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Config) WriteData() error {
	if c.Exe != nil {
		err := c.Exe.WriteData()
		if err != nil {
			return err
		}
	}

	for _, fw := range c.Firmwares {
		for _, img := range fw.Images {
			err := img.WriteData()
			if err != nil {
				return err
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
	var cfg *Config
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

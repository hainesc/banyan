package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/ghodss/yaml"
)

// Config is the config format for the main application.
type BanyanConf struct {
	Store     string     `json:"store"`
}

// NotFoundError when the directory and file not found.
type NotFoundError struct {
	Dir  string
	Name string
}

// Error prints out the error message for NotFoundError
func (e NotFoundError) Error() string {
	return fmt.Sprintf(`no configuration with name "%s" in %s`, e.Name, e.Dir)
}

// NoConfigsFoundError when no config files found in dir
type NoConfigsFoundError struct {
	Dir string
}

// Error print out the error message for NoConfigFoundError
func (e NoConfigsFoundError) Error() string {
	return fmt.Sprintf(`no configurations found in %s`, e.Dir)
}

// LoadConf loads config for Monkey
func LoadConf(dir, name string) (*BanyanConf, error) {
	files, err := ConfFiles(dir, []string{".conf", ".yaml"})
	switch {
	case err != nil:
		return nil, err
	case len(files) == 0:
		return nil, NoConfigsFoundError{Dir: dir}
	}
	sort.Strings(files)

	for _, confFile := range files {
		conf, err := ConfFromFile(confFile)
		if err != nil {
			return nil, err
		}
		return conf, nil

	}
	return nil, NotFoundError{dir, name}

}

// ConfFromFile reads config from file
func ConfFromFile(filename string) (*BanyanConf, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", filename, err)
	}
	return ConfFromBytes(bytes)
}

// ConfFromBytes reads config from byte array
func ConfFromBytes(bytes []byte) (*BanyanConf, error) {
	conf := &BanyanConf{}
	if err := yaml.Unmarshal(bytes, &conf); err != nil {
		return nil, fmt.Errorf("error parsing configuration: %s", err)
	}
	return conf, nil
}

// ConfFiles returns config file list in the dir which has specail extensions
func ConfFiles(dir string, extensions []string) ([]string, error) {
	files, err := ioutil.ReadDir(dir)
	switch {
	case err == nil: // break
	case os.IsNotExist(err):
		return nil, nil
	default:
		return nil, err
	}

	confFiles := []string{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fileExt := filepath.Ext(f.Name())
		for _, ext := range extensions {
			if fileExt == ext {
				confFiles = append(confFiles, filepath.Join(dir, f.Name()))
			}
		}
	}
	return confFiles, nil
}


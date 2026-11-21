package debrepo

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"go.vitalvas.com/gokit/xconfig"
)

type repoConfig struct {
	Origin      string                 `yaml:"origin"`
	Label       string                 `yaml:"label"`
	Description string                 `yaml:"description"`
	Suites      map[string]suiteConfig `yaml:"suites"`
}

type suiteConfig struct {
	Suite   string `yaml:"suite"`
	Version string `yaml:"version"`
}

func loadRepoConfig(path string) (repoConfig, error) {
	var cfg repoConfig

	err := xconfig.Load(&cfg, xconfig.WithFiles(path), xconfig.WithStrict(true))
	if err != nil && !errors.Is(err, io.EOF) {
		return repoConfig{}, fmt.Errorf("load %s: %w", path, err)
	}

	err = cfg.validate()
	if err != nil {
		return repoConfig{}, fmt.Errorf("validate %s: %w", path, err)
	}

	return cfg, nil
}

func (c repoConfig) suiteName(codename string) string {
	return cmp.Or(c.Suites[codename].Suite, codename)
}

type configField struct {
	name  string
	value string
}

func (c repoConfig) validate() error {
	fields := make([]configField, 0, 3+2*len(c.Suites))
	fields = append(fields,
		configField{"origin", c.Origin},
		configField{"label", c.Label},
		configField{"description", c.Description},
	)

	for _, name := range slices.Sorted(maps.Keys(c.Suites)) {
		fields = append(fields,
			configField{fmt.Sprintf("suites.%s.suite", name), c.Suites[name].Suite},
			configField{fmt.Sprintf("suites.%s.version", name), c.Suites[name].Version},
		)
	}

	for _, f := range fields {
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("field %s contains a line break", f.name)
		}
	}

	return nil
}

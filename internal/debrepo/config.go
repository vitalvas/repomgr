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

	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/repofs"
)

type repoConfig struct {
	Origin      string                 `yaml:"origin"`
	Label       string                 `yaml:"label"`
	Description string                 `yaml:"description"`
	Suites      map[string]suiteConfig `yaml:"suites"`
}

type suiteConfig struct {
	Suite         string   `yaml:"suite"`
	Version       string   `yaml:"version"`
	Components    []string `yaml:"components"`
	Architectures []string `yaml:"architectures"`
}

// seedIndexes publishes every component and architecture of a suite that
// declares either, combining the declared ones with those from pool packages,
// so the indexes exist even without packages.
func (c repoConfig) seedIndexes(indexes map[indexKey][]indexEntry) {
	for suite, s := range c.Suites {
		if len(s.Components) == 0 && len(s.Architectures) == 0 {
			continue
		}

		components := slices.Clone(s.Components)
		archs := slices.Clone(s.Architectures)

		for key := range indexes {
			if key.suite == suite {
				components = append(components, key.component)
				archs = append(archs, key.arch)
			}
		}

		for _, component := range components {
			for _, arch := range archs {
				key := indexKey{suite: suite, component: component, arch: arch}

				_, ok := indexes[key]
				if !ok {
					indexes[key] = nil
				}
			}
		}
	}
}

func validateDeclared(name string, s suiteConfig) error {
	if len(s.Components) == 0 && len(s.Architectures) == 0 {
		return nil
	}

	err := repofs.CheckName("suite", name)
	if err != nil {
		return fmt.Errorf("suites.%s: %w", name, err)
	}

	for _, component := range s.Components {
		err = repofs.CheckName("component", component)
		if err != nil {
			return fmt.Errorf("suites.%s.components: %w", name, err)
		}
	}

	for _, arch := range s.Architectures {
		if !slices.Contains(debfile.Architectures, arch) {
			return fmt.Errorf("suites.%s.architectures: unsupported architecture %q", name, arch)
		}
	}

	return nil
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

	for _, name := range slices.Sorted(maps.Keys(c.Suites)) {
		err := validateDeclared(name, c.Suites[name])
		if err != nil {
			return err
		}
	}

	return nil
}

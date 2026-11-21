package debrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const specRepoYAML string = `origin: Example
label: Example Repo
description: Example packages
suites:
  bookworm:
    suite: stable
    version: "12.0"
  unused:
    version: "1"
`

func writeRepoYAML(t *testing.T, workdir, content string) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(workdir, "config", "repo.yaml"), []byte(content), 0o644))
}

func TestBuildRepoConfig(t *testing.T) {
	t.Run("release header from repo.yaml", func(t *testing.T) {
		workdir := newWorkdir(t)
		writeRepoYAML(t, workdir, specRepoYAML)
		addPkg(t, workdir, "bookworm", "main", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "trixie", "main", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		bookworm := readPublic(t, workdir, "dists", "bookworm", "Release")
		assert.True(t, strings.HasPrefix(bookworm, "Origin: Example\nLabel: Example Repo\nSuite: stable\nVersion: 12.0\nCodename: bookworm\nDate: "))
		assert.Contains(t, bookworm, "Components: main\nDescription: Example packages\nMD5Sum:\n")

		trixie := readPublic(t, workdir, "dists", "trixie", "Release")
		assert.True(t, strings.HasPrefix(trixie, "Origin: Example\nLabel: Example Repo\nSuite: trixie\nCodename: trixie\n"))
		assert.NotContains(t, trixie, "Version:")
	})

	t.Run("empty file is an empty config", func(t *testing.T) {
		workdir := newWorkdir(t)
		writeRepoYAML(t, workdir, "")
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(readPublic(t, workdir, "dists", "s", "Release"), "Suite: s\nCodename: s\nDate: "))
	})

	t.Run("unknown key fails", func(t *testing.T) {
		workdir := newWorkdir(t)
		writeRepoYAML(t, workdir, "orign: x\n")

		_, err := Build(t.Context(), workdir, buildTime)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repo.yaml")
	})

	t.Run("line break fails before writing", func(t *testing.T) {
		cases := map[string]struct {
			yaml  string
			field string
		}{
			"label":       {"label: \"a\\nb\"\n", "label"},
			"origin":      {"origin: \"a\\rb\"\n", "origin"},
			"description": {"description: \"a\\nb\"\n", "description"},
			"version":     {"suites:\n  s:\n    version: \"1\\n2\"\n", "suites.s.version"},
			"suite":       {"suites:\n  s:\n    suite: \"x\\ny\"\n", "suites.s.suite"},
		}

		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				workdir := newWorkdir(t)
				writeRepoYAML(t, workdir, tc.yaml)
				addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

				_, err := Build(t.Context(), workdir, buildTime)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.field)
				assert.NoDirExists(t, filepath.Join(workdir, "public", "dists"))
			})
		}
	})

	t.Run("sorted validation is deterministic", func(t *testing.T) {
		cfg := repoConfig{Suites: map[string]suiteConfig{
			"e": {Version: "x\ny"},
			"b": {Version: "x\ny"},
			"d": {Version: "x\ny"},
			"a": {Version: "x\ny"},
			"c": {Version: "x\ny"},
			"f": {Version: "x\ny"},
		}}

		err := cfg.validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suites.a.version")
	})

	t.Run("empty suite name falls back to codename", func(t *testing.T) {
		workdir := newWorkdir(t)
		writeRepoYAML(t, workdir, "suites:\n  s:\n    version: \"1.0\"\n")
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(readPublic(t, workdir, "dists", "s", "Release"), "Suite: s\nVersion: 1.0\nCodename: s\n"))
	})
}

func BenchmarkLoadRepoConfig(b *testing.B) {
	path := filepath.Join(b.TempDir(), "repo.yaml")
	require.NoError(b, os.WriteFile(path, []byte(specRepoYAML), 0o644))

	b.ReportAllocs()

	for b.Loop() {
		_, err := loadRepoConfig(path)
		require.NoError(b, err)
	}
}

func FuzzRepoConfigValidate(f *testing.F) {
	f.Add("a", "b", "c")
	f.Add("a\nb", "", "")

	f.Fuzz(func(t *testing.T, origin, label, version string) {
		cfg := repoConfig{Origin: origin, Label: label, Suites: map[string]suiteConfig{"s": {Version: version}}}
		err := cfg.validate()

		hasBreak := strings.ContainsAny(origin+label+version, "\r\n")
		assert.Equal(t, hasBreak, err != nil)
	})
}

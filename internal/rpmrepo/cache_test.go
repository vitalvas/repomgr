package rpmrepo

import (
	"bytes"
	"encoding/gob"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/rpmfile"
)

// captureLogs sends the default logger to the returned buffer until the test ends.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &logs
}

// editPackage decodes the package of e, applies edit and stores it again.
func editPackage(t *testing.T, e *cacheEntry, edit func(p *rpmfile.Package)) {
	t.Helper()

	var pkg rpmfile.Package

	require.NoError(t, gob.NewDecoder(bytes.NewReader(e.Package)).Decode(&pkg))

	edit(&pkg)

	var buf bytes.Buffer

	require.NoError(t, gob.NewEncoder(&buf).Encode(pkg))

	e.Package = buf.Bytes()
}

// mismatches lists edits that make a valid cache entry stop matching its file.
var mismatches = []struct {
	name string
	edit func(t *testing.T, e *cacheEntry)
}{
	{"version", func(_ *testing.T, e *cacheEntry) { e.Version = 1 }},
	{"size", func(_ *testing.T, e *cacheEntry) { e.Size++ }},
	{"mtime", func(_ *testing.T, e *cacheEntry) { e.MTime++ }},
	{"short sha256", func(t *testing.T, e *cacheEntry) {
		editPackage(t, e, func(p *rpmfile.Package) { p.SHA256 = p.SHA256[:63] })
	}},
	{"non-hex sha256", func(t *testing.T, e *cacheEntry) {
		editPackage(t, e, func(p *rpmfile.Package) { p.SHA256 = strings.Repeat("g", 64) })
	}},
	{"package size", func(t *testing.T, e *cacheEntry) {
		editPackage(t, e, func(p *rpmfile.Package) { p.Size++ })
	}},
	{"invalid package", func(t *testing.T, e *cacheEntry) {
		editPackage(t, e, func(p *rpmfile.Package) { p.Name = "-bad" })
	}},
	{"corrupt gob", func(_ *testing.T, e *cacheEntry) { e.Package = []byte("not gob") }},
	{"empty package", func(_ *testing.T, e *cacheEntry) { e.Package = nil }},
}

func TestCacheEntryMatches(t *testing.T) {
	file := addPkg(t, initWorkdir(t), "9/main", basePkg())

	info, err := os.Stat(file)
	require.NoError(t, err)

	want := parseFile(t, file)

	entry, err := newCacheEntry(info, want)
	require.NoError(t, err)
	assert.Equal(t, cacheVersion, entry.Version)
	assert.Equal(t, 2, cacheVersion)

	got, ok := entry.matches(info)
	assert.True(t, ok)
	assert.Equal(t, want, got)

	for _, tt := range mismatches {
		t.Run(tt.name, func(t *testing.T) {
			e := entry
			tt.edit(t, &e)

			_, ok := e.matches(info)
			assert.False(t, ok)
		})
	}
}

func TestCacheEntryKeepsBytes(t *testing.T) {
	file := addPkg(t, initWorkdir(t), "9/main", basePkg())

	info, err := os.Stat(file)
	require.NoError(t, err)

	pkg := parseFile(t, file)
	pkg.Summary = "caf\xe9"

	entry, err := newCacheEntry(info, pkg)
	require.NoError(t, err)

	got, ok := entry.matches(info)
	require.True(t, ok)
	assert.Equal(t, "caf\xe9", got.Summary)
}

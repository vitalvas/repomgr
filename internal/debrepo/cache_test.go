package debrepo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/debfile"
)

func cachePath(workdir string) string {
	return filepath.Join(workdir, "cache", "index.json")
}

func readCache(t *testing.T, workdir string) map[string]cacheEntry {
	t.Helper()

	data, err := os.ReadFile(cachePath(workdir))
	require.NoError(t, err)

	var entries map[string]cacheEntry
	require.NoError(t, json.Unmarshal(data, &entries))

	return entries
}

func packagesPath(workdir string) string {
	return filepath.Join(workdir, "public", "dists", "stable", "main", "binary-amd64", "Packages")
}

func TestCache(t *testing.T) {
	t.Run("add writes entry and repeat add keeps cache", func(t *testing.T) {
		workdir := newWorkdir(t)
		src := writeDeb(t, ctl("foo", "1.0", ""))

		res, err := Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)
		require.True(t, res.Added)

		target := filepath.Join(workdir, "public", filepath.FromSlash(res.Path))
		pkg, err := debfile.Open(target)
		require.NoError(t, err)

		info, err := os.Stat(target)
		require.NoError(t, err)

		assert.Equal(t, map[string]cacheEntry{res.Path: {
			Version: cacheVersion,
			Size:    pkg.Size,
			MTime:   info.ModTime().UnixNano(),
			Control: pkg.Control.Raw,
			Fields:  pkg.Control.Fields,
			MD5:     pkg.MD5,
			SHA1:    pkg.SHA1,
			SHA256:  pkg.SHA256,
		}}, readCache(t, workdir))

		before, err := os.ReadFile(cachePath(workdir))
		require.NoError(t, err)

		res, err = Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)
		assert.False(t, res.Added)

		after, err := os.ReadFile(cachePath(workdir))
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})

	t.Run("build reuses unchanged entries and refreshes changed ones", func(t *testing.T) {
		workdir := newWorkdir(t)
		res := addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		entries := readCache(t, workdir)
		require.Len(t, entries, 1)

		orig := entries[res.Path]
		fake := orig
		fake.SHA256 = "fake"
		entries[res.Path] = fake
		require.NoError(t, saveCache(workdir, entries))

		logs := captureLogs(t)
		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Contains(t, logs.String(), "msg=parsed ")
		assert.Equal(t, orig, readCache(t, workdir)[res.Path])

		logs.Reset()
		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NotContains(t, logs.String(), "msg=parsed ")

		target := filepath.Join(workdir, "public", filepath.FromSlash(res.Path))
		require.NoError(t, os.Chtimes(target, time.Time{}, time.Now().Add(time.Hour)))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		pkgs, err := os.ReadFile(packagesPath(workdir))
		require.NoError(t, err)
		assert.Contains(t, string(pkgs), fmt.Sprintf("SHA256: %s\n", orig.SHA256))
		assert.Equal(t, orig.SHA256, readCache(t, workdir)[res.Path].SHA256)
	})

	t.Run("build drops entries for missing files", func(t *testing.T) {
		workdir := newWorkdir(t)
		keep := addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))
		gone := addPkg(t, workdir, "stable", "main", ctl("bar", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		require.Len(t, readCache(t, workdir), 2)

		require.NoError(t, os.Remove(filepath.Join(workdir, "public", filepath.FromSlash(gone.Path))))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		entries := readCache(t, workdir)
		assert.Len(t, entries, 1)
		assert.Contains(t, entries, keep.Path)
	})

	t.Run("bad or missing cache gives identical output", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		warm, err := os.ReadFile(packagesPath(workdir))
		require.NoError(t, err)

		for name, setup := range map[string]func(){
			"deleted": func() { require.NoError(t, os.RemoveAll(filepath.Dir(cachePath(workdir)))) },
			"garbage": func() { require.NoError(t, os.WriteFile(cachePath(workdir), []byte("not json{"), 0o644)) },
			"null":    func() { require.NoError(t, os.WriteFile(cachePath(workdir), []byte("null"), 0o644)) },
		} {
			setup()

			_, err = Build(t.Context(), workdir, buildTime)
			require.NoError(t, err, name)

			got, err := os.ReadFile(packagesPath(workdir))
			require.NoError(t, err, name)
			assert.Equal(t, warm, got, name)
			assert.Len(t, readCache(t, workdir), 1, name)
		}
	})

	t.Run("unreadable cache is an error", func(t *testing.T) {
		workdir := newWorkdir(t)
		require.NoError(t, os.MkdirAll(cachePath(workdir), 0o755))

		_, err := Build(t.Context(), workdir, buildTime)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "index.json")

		_, err = Add(t.Context(), workdir, "stable", "main", writeDeb(t, ctl("foo", "1.0", "")))
		require.Error(t, err)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "pool"))
	})
}

func BenchmarkLoadCache(b *testing.B) {
	workdir := b.TempDir()
	entries := map[string]cacheEntry{"pool/a.deb": {Size: 1, Fields: map[string]string{"Package": "a"}}}

	require.NoError(b, saveCache(workdir, entries))

	b.ReportAllocs()

	for b.Loop() {
		_, err := loadCache(workdir)
		require.NoError(b, err)
	}
}

func FuzzLoadCache(f *testing.F) {
	f.Add([]byte(`{"pool/a.deb":{"size":1}}`))
	f.Add([]byte("garbage"))
	f.Add([]byte("null"))

	f.Fuzz(func(t *testing.T, data []byte) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Dir(cachePath(workdir)), 0o755))
		require.NoError(t, os.WriteFile(cachePath(workdir), data, 0o644))

		entries, err := loadCache(workdir)
		require.NoError(t, err)
		assert.NotNil(t, entries)
	})
}

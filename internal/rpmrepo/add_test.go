package rpmrepo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/repofs"
	"go.vitalvas.com/repomgr/internal/rpmfile"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

func initWorkdir(t *testing.T) string {
	t.Helper()

	workdir := t.TempDir()
	require.NoError(t, Init(context.Background(), workdir, "Test", ""))

	return workdir
}

func writeRPM(t *testing.T, p rpmtest.Package) string {
	t.Helper()

	data, err := rpmtest.Build(p)
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "in.rpm")
	require.NoError(t, os.WriteFile(file, data, 0o644))

	return file
}

func basePkg() rpmtest.Package {
	return rpmtest.Package{
		Name:    "pdns",
		Version: "5.1.0",
		Release: "1.el9",
		Arch:    "x86_64",
	}
}

func TestAdd(t *testing.T) {
	t.Run("pool path", func(t *testing.T) {
		epoch := uint32(3)

		tests := []struct {
			name string
			edit func(p *rpmtest.Package)
			want string
		}{
			{"x86_64", func(_ *rpmtest.Package) {}, "pool/9/main/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm"},
			{"aarch64", func(p *rpmtest.Package) { p.Arch = "aarch64" }, "pool/9/main/p/pdns/aarch64/pdns-5.1.0-1.el9.aarch64.rpm"},
			{"noarch", func(p *rpmtest.Package) { p.Arch = "noarch" }, "pool/9/main/p/pdns/noarch/pdns-5.1.0-1.el9.noarch.rpm"},
			{"lib prefix", func(p *rpmtest.Package) { p.Name = "libfoo" }, "pool/9/main/libf/libfoo/x86_64/libfoo-5.1.0-1.el9.x86_64.rpm"},
			{"lib alone", func(p *rpmtest.Package) { p.Name = "lib" }, "pool/9/main/l/lib/x86_64/lib-5.1.0-1.el9.x86_64.rpm"},
			{"uppercase", func(p *rpmtest.Package) { p.Name = "NetworkManager" }, "pool/9/main/n/NetworkManager/x86_64/NetworkManager-5.1.0-1.el9.x86_64.rpm"},
			{"epoch not in name", func(p *rpmtest.Package) { p.Epoch = &epoch }, "pool/9/main/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				workdir := initWorkdir(t)
				p := basePkg()
				tt.edit(&p)

				res, err := Add(workdir, "9", "main", writeRPM(t, p))
				require.NoError(t, err)
				assert.True(t, res.Added)
				assert.Equal(t, tt.want, res.Path)
				assert.FileExists(t, filepath.Join(workdir, "public", filepath.FromSlash(tt.want)))
			})
		}
	})

	t.Run("same bytes unchanged", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := writeRPM(t, basePkg())

		first, err := Add(workdir, "9", "main", file)
		require.NoError(t, err)
		require.True(t, first.Added)

		second, err := Add(workdir, "9", "main", file)
		require.NoError(t, err)
		assert.False(t, second.Added)
		assert.Equal(t, first.Path, second.Path)
	})

	t.Run("writes cache entry", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := writeRPM(t, basePkg())

		res, err := Add(workdir, "9", "main", file)
		require.NoError(t, err)

		target := filepath.Join(workdir, "public", filepath.FromSlash(res.Path))

		info, err := os.Stat(target)
		require.NoError(t, err)

		want, err := newCacheEntry(info, parseFile(t, target))
		require.NoError(t, err)

		cache, err := repofs.LoadCache[cacheEntry](workdir)
		require.NoError(t, err)
		assert.Equal(t, map[string]cacheEntry{res.Path: want}, cache)

		require.NoError(t, os.Remove(filepath.Join(workdir, "cache", "index.json")))

		again, err := Add(workdir, "9", "main", file)
		require.NoError(t, err)
		require.False(t, again.Added)

		cache, err = repofs.LoadCache[cacheEntry](workdir)
		require.NoError(t, err)
		assert.Equal(t, map[string]cacheEntry{res.Path: want}, cache)
	})

	t.Run("different bytes conflict", func(t *testing.T) {
		workdir := initWorkdir(t)

		_, err := Add(workdir, "9", "main", writeRPM(t, basePkg()))
		require.NoError(t, err)

		other := basePkg()
		other.Payload = []byte("other")
		file := writeRPM(t, other)

		for _, target := range [][2]string{{"9", "main"}, {"10", "extras"}} {
			_, err = Add(workdir, target[0], target[1], file)
			require.ErrorIs(t, err, repofs.ErrConflict, target)
		}
	})

	t.Run("release rule", func(t *testing.T) {
		for _, bad := range []string{"7", "08", "abc", "99999999999999999999", "", "-9"} {
			_, err := Add(initWorkdir(t), bad, "main", writeRPM(t, basePkg()))
			require.ErrorIs(t, err, repofs.ErrInvalidName, bad)
			assert.Contains(t, err.Error(), "release")
			assert.Contains(t, err.Error(), bad)
		}

		for _, good := range []string{"8", "10"} {
			_, err := Add(initWorkdir(t), good, "main", writeRPM(t, basePkg()))
			assert.NoError(t, err, good)
		}
	})

	t.Run("bad component", func(t *testing.T) {
		_, err := Add(initWorkdir(t), "9", "Bad/Comp", writeRPM(t, basePkg()))
		require.ErrorIs(t, err, repofs.ErrInvalidName)
		assert.Contains(t, err.Error(), "component")
		assert.Contains(t, err.Error(), "Bad/Comp")
	})

	t.Run("not initialized", func(t *testing.T) {
		_, err := Add(t.TempDir(), "9", "main", writeRPM(t, basePkg()))
		assert.ErrorIs(t, err, repofs.ErrNotInitialized)
	})

	t.Run("deb workdir refused", func(t *testing.T) {
		for _, marker := range []string{"dists", "key.gpg"} {
			workdir := initWorkdir(t)
			require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", marker), nil, 0o644))

			_, err := Add(workdir, "9", "main", writeRPM(t, basePkg()))
			require.ErrorIs(t, err, ErrDebWorkdir, marker)
		}
	})

	t.Run("unparseable file writes nothing", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := filepath.Join(t.TempDir(), "bad.rpm")
		require.NoError(t, os.WriteFile(file, []byte("not an rpm"), 0o644))

		_, err := Add(workdir, "9", "main", file)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("add %s", file))
		assert.NoDirExists(t, filepath.Join(workdir, "public", "pool"))
	})

	t.Run("bad text refused before copying", func(t *testing.T) {
		for _, summary := range []string{"a\x01b", "\xed\xa0\x80", "\xe9\x01"} {
			workdir := initWorkdir(t)
			p := basePkg()
			p.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: summary}}

			_, err := Add(workdir, "9", "main", writeRPM(t, p))
			require.ErrorIs(t, err, rpmfile.ErrInvalidField)
			assert.Contains(t, err.Error(), "SUMMARY")
			assert.NoDirExists(t, filepath.Join(workdir, "public", "pool"))
			assert.NoFileExists(t, filepath.Join(workdir, "cache", "index.json"))
		}
	})

	t.Run("bad text refused before the pool check", func(t *testing.T) {
		workdir := initWorkdir(t)

		_, err := Add(workdir, "9", "main", writeRPM(t, basePkg()))
		require.NoError(t, err)

		pool := filepath.Join(workdir, "public", "pool", "9", "main", "p", "pdns", "x86_64")
		want, err := os.ReadDir(pool)
		require.NoError(t, err)
		require.Len(t, want, 1)

		p := basePkg()
		p.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: "a\x01b"}}

		_, err = Add(workdir, "9", "main", writeRPM(t, p))
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		assert.NotErrorIs(t, err, repofs.ErrConflict)

		got, err := os.ReadDir(pool)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, want[0].Name(), got[0].Name())

		wantInfo, err := want[0].Info()
		require.NoError(t, err)

		gotInfo, err := got[0].Info()
		require.NoError(t, err)
		assert.Equal(t, wantInfo.Size(), gotInfo.Size())
		assert.Equal(t, wantInfo.ModTime(), gotInfo.ModTime())
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := Add(initWorkdir(t), "9", "main", filepath.Join(t.TempDir(), "none.rpm"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestInitKeyGPGRefused(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "key.gpg"), nil, 0o644))

	require.ErrorIs(t, Init(context.Background(), workdir, "Test", ""), ErrDebWorkdir)
	assert.NoFileExists(t, filepath.Join(workdir, "config", "signing.asc"))
}

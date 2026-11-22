package debrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/debtest"
)

var buildTime = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func addPkg(t *testing.T, workdir, suite, component, control string) AddResult {
	t.Helper()

	res, err := Add(t.Context(), workdir, suite, component, writeDeb(t, control))
	require.NoError(t, err)

	return res
}

func readPublic(t *testing.T, workdir string, parts ...string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(append([]string{workdir, "public"}, parts...)...))
	require.NoError(t, err)

	return string(data)
}

func TestBuild(t *testing.T) {
	t.Run("splits architectures and writes release", func(t *testing.T) {
		workdir := newWorkdir(t)
		amd := addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", "Description: Foo\n multi\n line\n"))
		all := addPkg(t, workdir, "stable", "main", "Package: bar\nVersion: 2.0\nArchitecture: all\n")

		sums, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, []SuiteSummary{{Suite: "stable", Packages: 2, Architectures: []string{"all", "amd64"}}}, sums)

		pkg, err := debfile.Open(filepath.Join(workdir, "public", filepath.FromSlash(amd.Path)))
		require.NoError(t, err)

		wantAmd := fmt.Sprintf(`Package: foo
Version: 1.0
Architecture: amd64
Description: Foo
 multi
 line
Filename: %s
Size: %d
MD5sum: %s
SHA1: %s
SHA256: %s
`, amd.Path, pkg.Size, pkg.MD5, pkg.SHA1, pkg.SHA256)
		amdIndex := readPublic(t, workdir, "dists", "stable", "main", "binary-amd64", "Packages")
		assert.Equal(t, wantAmd, amdIndex)

		allIndex := readPublic(t, workdir, "dists", "stable", "main", "binary-all", "Packages")
		assert.Contains(t, allIndex, fmt.Sprintf("Filename: %s\n", all.Path))
		assert.NotContains(t, allIndex, "foo")

		var want strings.Builder

		want.WriteString("Suite: stable\nCodename: stable\nDate: Sat, 21 Nov 2026 12:00:00 UTC\nAcquire-By-Hash: yes\nArchitectures: all amd64\nComponents: main\n")

		hashes := []struct {
			name string
			sum  func([]byte) string
		}{
			{"MD5Sum", func(b []byte) string { h := md5.Sum(b); return hex.EncodeToString(h[:]) }},
			{"SHA1", func(b []byte) string { h := sha1.Sum(b); return hex.EncodeToString(h[:]) }},
			{"SHA256", func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }},
		}

		for _, h := range hashes {
			fmt.Fprintf(&want, "%s:\n", h.name)

			for _, arch := range []string{"all", "amd64"} {
				for _, name := range []string{"Packages", "Packages.gz", "Packages.zst", "Release"} {
					rel := fmt.Sprintf("main/binary-%s/%s", arch, name)
					data := []byte(readPublic(t, workdir, "dists", "stable", filepath.FromSlash(rel)))
					fmt.Fprintf(&want, " %s %d %s\n", h.sum(data), len(data), rel)
				}
			}
		}

		assert.Equal(t, want.String(), readPublic(t, workdir, "dists", "stable", "Release"))
	})

	t.Run("per-directory Release", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "bookworm", "main", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "bookworm", "main", "Package: bar\nVersion: 2.0\nArchitecture: all\n")

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, "Archive: bookworm\nAcquire-By-Hash: yes\nComponent: main\nArchitecture: amd64\n",
			readPublic(t, workdir, "dists", "bookworm", "main", "binary-amd64", "Release"))

		cfg := "origin: O\nlabel: L\nsuites:\n  bookworm:\n    suite: stable\n"
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "config", "repo.yaml"), []byte(cfg), 0o644))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, "Archive: stable\nOrigin: O\nLabel: L\nAcquire-By-Hash: yes\nComponent: main\nArchitecture: all\n",
			readPublic(t, workdir, "dists", "bookworm", "main", "binary-all", "Release"))
	})

	t.Run("compressed indexes match Packages and are deterministic", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		plain := readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages")
		gz := readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages.gz")
		zs := readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages.zst")

		zr, err := gzip.NewReader(strings.NewReader(gz))
		require.NoError(t, err)

		unzipped, err := io.ReadAll(zr)
		require.NoError(t, err)
		assert.Equal(t, plain, string(unzipped))
		assert.Empty(t, zr.Name)
		assert.True(t, zr.ModTime.IsZero())

		dec, err := zstd.NewReader(nil)
		require.NoError(t, err)

		defer dec.Close()

		unzstd, err := dec.DecodeAll([]byte(zs), nil)
		require.NoError(t, err)
		assert.Equal(t, plain, string(unzstd))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, gz, readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages.gz"))
		assert.Equal(t, zs, readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages.zst"))
	})

	t.Run("moves Package line first", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", "Version: 1.0\nPackage: foo\nArchitecture: amd64\n")

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages"),
			"Package: foo\nVersion: 1.0\nArchitecture: amd64\nFilename: "))
	})

	t.Run("sorts and separates stanzas", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("zed", "1.0", ""))
		addPkg(t, workdir, "s", "c", ctl("foo", "2.0", ""))
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		index := readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages")
		stanzas := strings.Split(strings.TrimSuffix(index, "\n"), "\n\n")
		require.Len(t, stanzas, 3)
		assert.Contains(t, stanzas[0], "Version: 1.0")
		assert.Contains(t, stanzas[1], "Version: 2.0")
		assert.Contains(t, stanzas[2], "Package: zed")
		assert.True(t, strings.HasSuffix(index, "\n"))
		assert.False(t, strings.HasSuffix(index, "\n\n"))
	})

	t.Run("two suites", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "testing", "main", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "stable", "contrib", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))

		sums, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, []SuiteSummary{
			{Suite: "stable", Packages: 2, Architectures: []string{"amd64"}},
			{Suite: "testing", Packages: 1, Architectures: []string{"amd64"}},
		}, sums)
		assert.Contains(t, readPublic(t, workdir, "dists", "stable", "Release"), "Components: contrib main\n")
		assert.Contains(t, readPublic(t, workdir, "dists", "testing", "Release"), "Suite: testing\n")
	})

	t.Run("deterministic", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		first := readPublic(t, workdir, "dists", "s", "Release") + readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages")

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		second := readPublic(t, workdir, "dists", "s", "Release") + readPublic(t, workdir, "dists", "s", "c", "binary-amd64", "Packages")
		assert.Equal(t, first, second)
	})

	t.Run("not initialized", func(t *testing.T) {
		_, err := Build(t.Context(), t.TempDir(), buildTime)
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("missing signing key", func(t *testing.T) {
		workdir := newWorkdir(t)
		require.NoError(t, os.Remove(filepath.Join(workdir, "config", "signing.asc")))

		_, err := Build(t.Context(), workdir, buildTime)
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("unreadable signing key", func(t *testing.T) {
		workdir := newWorkdir(t)
		keyPath := filepath.Join(workdir, "config", "signing.asc")
		require.NoError(t, os.Remove(keyPath))
		require.NoError(t, os.Mkdir(keyPath, 0o755))

		_, err := Build(t.Context(), workdir, buildTime)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotInitialized)
		assert.Contains(t, err.Error(), keyPath)
	})

	t.Run("corrupt signing key leaves dists untouched", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "config", "signing.asc"), []byte("garbage"), 0o600))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorContains(t, err, "sign release for suite s")
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists"))
	})

	t.Run("signed metadata verifies", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "testing", "main", ctl("foo", "2.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		pubData, err := os.ReadFile(filepath.Join(workdir, "public", "key.gpg"))
		require.NoError(t, err)

		ring, err := openpgp.ReadKeyRing(bytes.NewReader(pubData))
		require.NoError(t, err)

		for _, suite := range []string{"stable", "testing"} {
			release := readPublic(t, workdir, "dists", suite, "Release")

			block, _ := clearsign.Decode([]byte(readPublic(t, workdir, "dists", suite, "InRelease")))
			require.NotNil(t, block)

			_, err = block.VerifySignature(ring, nil)
			require.NoError(t, err)
			assert.Equal(t, release, string(block.Plaintext))

			_, err = openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(release),
				strings.NewReader(readPublic(t, workdir, "dists", suite, "Release.gpg")), nil)
			require.NoError(t, err)

			for _, name := range []string{"Release", "Release.gpg", "InRelease"} {
				info, err := os.Stat(filepath.Join(workdir, "public", "dists", suite, name))
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), name)
			}
		}
	})

	t.Run("empty and missing pool", func(t *testing.T) {
		workdir := newWorkdir(t)

		sums, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Empty(t, sums)

		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public", "pool"), 0o755))

		sums, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Empty(t, sums)
	})

	t.Run("ignores non deb files", func(t *testing.T) {
		workdir := newWorkdir(t)
		res := addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))
		dir := filepath.Dir(filepath.Join(workdir, "public", filepath.FromSlash(res.Path)))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".build-123"), []byte("junk"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "pool", "stray.txt"), []byte("junk"), 0o644))

		sums, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, 1, sums[0].Packages)
	})

	t.Run("invalid deb fails with path", func(t *testing.T) {
		workdir := newWorkdir(t)
		bad := filepath.Join(workdir, "public", "pool", "s", "c", "f", "foo", "foo_1.0_amd64.deb")
		require.NoError(t, os.MkdirAll(filepath.Dir(bad), 0o755))
		require.NoError(t, os.WriteFile(bad, []byte("not a deb"), 0o644))

		_, err := Build(t.Context(), workdir, buildTime)
		require.Error(t, err)
		assert.Contains(t, err.Error(), bad)
	})

	t.Run("unwritable dists fails", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "dists"), nil, 0o644))

		_, err := Build(t.Context(), workdir, buildTime)
		assert.Error(t, err)
		assert.False(t, errors.Is(err, ErrNotInitialized))
	})
}

func TestBuildByHash(t *testing.T) {
	sums := map[string]func([]byte) string{
		"MD5Sum": func(b []byte) string { h := md5.Sum(b); return hex.EncodeToString(h[:]) },
		"SHA1":   func(b []byte) string { h := sha1.Sum(b); return hex.EncodeToString(h[:]) },
		"SHA256": func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) },
	}

	check := func(t *testing.T, workdir string, perDir int) {
		t.Helper()

		dir := filepath.Join(workdir, "public", "dists", "s", "c", "binary-amd64")
		release := readPublic(t, workdir, "dists", "s", "Release")

		for name, sum := range sums {
			entries, err := os.ReadDir(filepath.Join(dir, "by-hash", name))
			require.NoError(t, err)
			require.Len(t, entries, perDir, name)

			for _, e := range entries {
				data, err := os.ReadFile(filepath.Join(dir, "by-hash", name, e.Name()))
				require.NoError(t, err)
				assert.Equal(t, e.Name(), sum(data))
			}

			for _, file := range []string{"Packages", "Packages.gz", "Packages.zst"} {
				data, err := os.ReadFile(filepath.Join(dir, file))
				require.NoError(t, err)

				got, err := os.ReadFile(filepath.Join(dir, "by-hash", name, sum(data)))
				require.NoError(t, err)
				assert.Equal(t, data, got)
				assert.Contains(t, release, fmt.Sprintf(" %s %d c/binary-amd64/%s\n", sum(data), len(data), file))
			}
		}
	}

	workdir := newWorkdir(t)
	addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

	_, err := Build(t.Context(), workdir, buildTime)
	require.NoError(t, err)
	check(t, workdir, 3)

	old := filepath.Join(workdir, "public", "dists", "s", "c", "binary-amd64", "by-hash", "SHA256")
	entries, err := os.ReadDir(old)
	require.NoError(t, err)

	marker := filepath.Join(old, entries[0].Name())
	require.NoError(t, os.WriteFile(marker, []byte("kept"), 0o644))

	_, err = Build(t.Context(), workdir, buildTime)
	require.NoError(t, err)

	check(t, workdir, 3)
	require.NoError(t, os.Remove(marker))

	_, err = Build(t.Context(), workdir, buildTime)
	require.NoError(t, err)
	check(t, workdir, 3)

	addPkg(t, workdir, "s", "c", ctl("bar", "1.0", ""))

	_, err = Build(t.Context(), workdir, buildTime)
	require.NoError(t, err)
	check(t, workdir, 6)
}

func TestBuildRetention(t *testing.T) {
	hashDir := func(workdir string) string {
		return filepath.Join(workdir, "public", "dists", "s", "c", "binary-amd64", "by-hash", "SHA256")
	}

	current := func(t *testing.T, workdir string) []string {
		t.Helper()

		out := make([]string, 0, 3)

		for _, file := range []string{"Packages", "Packages.gz", "Packages.zst"} {
			data := readPublic(t, workdir, "dists", "s", "c", "binary-amd64", file)
			sum := sha256.Sum256([]byte(data))
			out = append(out, hex.EncodeToString(sum[:]))
		}

		return out
	}

	names := func(t *testing.T, dir string) []string {
		t.Helper()

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)

		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Name())
		}

		return out
	}

	run := func(t *testing.T, dropCache bool) {
		workdir := newWorkdir(t)
		logs := captureLogs(t)

		versions := make([][]string, 0, 5)

		for i := range 5 {
			addPkg(t, workdir, "s", "c", ctl(fmt.Sprintf("pkg%d", i), "1.0", ""))

			if dropCache {
				require.NoError(t, os.RemoveAll(filepath.Join(workdir, "cache")))
			}

			_, err := Build(t.Context(), workdir, buildTime.Add(time.Duration(i)*time.Hour))
			require.NoError(t, err)

			versions = append(versions, current(t, workdir))

			var want []string
			for _, v := range versions[max(0, i-2):] {
				want = append(want, v...)
			}

			assert.ElementsMatch(t, want, names(t, hashDir(workdir)), "build %d", i)

			for _, name := range []string{"MD5Sum", "SHA1"} {
				assert.Len(t, names(t, filepath.Join(hashDir(workdir), "..", name)), len(want), name)
			}
		}

		assert.Contains(t, logs.String(), "msg=\"removed by-hash\" path=public/dists/s/c/binary-amd64/by-hash/")
	}

	t.Run("keeps two previous versions", func(t *testing.T) { run(t, false) })
	t.Run("without cache", func(t *testing.T) { run(t, true) })

	t.Run("unchanged rebuild refreshes mtime", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		later := buildTime.Add(time.Hour)

		_, err = Build(t.Context(), workdir, later)
		require.NoError(t, err)

		entries, err := os.ReadDir(hashDir(workdir))
		require.NoError(t, err)
		require.Len(t, entries, 3)

		for _, e := range entries {
			info, err := e.Info()
			require.NoError(t, err)
			assert.True(t, info.ModTime().Equal(later), e.Name())
		}
	})

	t.Run("ignores dot files and directories", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		dir := hashDir(workdir)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))

		for i := range 8 {
			oldFile := filepath.Join(dir, fmt.Sprintf("old%d", i))
			require.NoError(t, os.WriteFile(oldFile, []byte("x"), 0o644))

			mtime := buildTime.Add(-time.Duration(i+1) * time.Hour)
			require.NoError(t, os.Chtimes(oldFile, mtime, mtime))
		}

		require.NoError(t, os.WriteFile(filepath.Join(dir, ".build-x"), []byte("x"), 0o644))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(dir, ".build-x"))
		assert.DirExists(t, filepath.Join(dir, "sub"))

		for i := range 8 {
			file := filepath.Join(dir, fmt.Sprintf("old%d", i))

			if i < 6 {
				assert.FileExists(t, file)
			} else {
				assert.NoFileExists(t, file)
			}
		}

		assert.Len(t, names(t, dir), 3+6+2)
	})
}

func TestBuildStale(t *testing.T) {
	removePkg := func(t *testing.T, workdir string, res AddResult) {
		t.Helper()
		require.NoError(t, os.Remove(filepath.Join(workdir, "public", filepath.FromSlash(res.Path))))
	}

	t.Run("suite", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "a", "main", ctl("foo", "1.0", ""))
		b := addPkg(t, workdir, "b", "main", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		removePkg(t, workdir, b)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists", "b"))
		assert.FileExists(t, filepath.Join(workdir, "public", "dists", "a", "InRelease"))
		assert.DirExists(t, filepath.Join(workdir, "public", "dists", "a", "main", "binary-amd64", "by-hash"))
	})

	t.Run("component", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "main", ctl("foo", "1.0", ""))
		c := addPkg(t, workdir, "s", "contrib", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		removePkg(t, workdir, c)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists", "s", "contrib"))
		assert.DirExists(t, filepath.Join(workdir, "public", "dists", "s", "main"))
		assert.NotContains(t, readPublic(t, workdir, "dists", "s", "Release"), "contrib")
	})

	t.Run("architecture", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "main", ctl("foo", "1.0", ""))
		arm := addPkg(t, workdir, "s", "main", "Package: bar\nVersion: 1.0\nArchitecture: arm64\n")

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		removePkg(t, workdir, arm)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists", "s", "main", "binary-arm64"))
		assert.DirExists(t, filepath.Join(workdir, "public", "dists", "s", "main", "binary-amd64"))
		assert.NotContains(t, readPublic(t, workdir, "dists", "s", "Release"), "arm64")
	})

	t.Run("keeps non-binary directories in a component", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "main", ctl("foo", "1.0", ""))
		arm := addPkg(t, workdir, "s", "main", "Package: bar\nVersion: 1.0\nArchitecture: arm64\n")

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		i18n := filepath.Join(workdir, "public", "dists", "s", "main", "i18n")
		require.NoError(t, os.Mkdir(i18n, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(i18n, "Translation-en"), []byte("x"), 0o644))

		removePkg(t, workdir, arm)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(i18n, "Translation-en"))
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists", "s", "main", "binary-arm64"))
	})

	t.Run("empty pool removes all suites", func(t *testing.T) {
		workdir := newWorkdir(t)
		res := addPkg(t, workdir, "s", "main", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		removePkg(t, workdir, res)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists", "s"))
	})
}

func TestBuildPoolChecks(t *testing.T) {
	poolFile := func(t *testing.T, workdir, control string, parts ...string) {
		t.Helper()

		data, err := debtest.Build(control)
		require.NoError(t, err)

		target := filepath.Join(append([]string{workdir, "public", "pool"}, parts...)...)
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
		require.NoError(t, os.WriteFile(target, data, 0o644))
	}

	misplaced := []struct {
		name  string
		parts []string
		want  string
	}{
		{"wrong file name", []string{"s", "c", "f", "foo", "other_1.0_amd64.deb"}, "pool/s/c/f/foo/other_1.0_amd64.deb: package not at its pool path, want pool/s/c/f/foo/foo_1.0_amd64.deb"},
		{"wrong name dir", []string{"s", "c", "f", "bar", "foo_1.0_amd64.deb"}, ""},
		{"depth 3", []string{"s", "c", "x.deb"}, ""},
		{"bad suite", []string{"Bad", "c", "f", "foo", "foo_1.0_amd64.deb"}, ""},
	}

	for _, tc := range misplaced {
		t.Run(tc.name, func(t *testing.T) {
			workdir := newWorkdir(t)
			poolFile(t, workdir, ctl("foo", "1.0", ""), tc.parts...)

			_, err := Build(t.Context(), workdir, buildTime)
			require.ErrorIs(t, err, ErrMisplaced)

			if tc.want != "" {
				assert.Contains(t, err.Error(), tc.want)
			}

			assert.NoDirExists(t, filepath.Join(workdir, "public", "dists"))
		})
	}

	t.Run("corrupt deb under bad suite is misplaced", func(t *testing.T) {
		workdir := newWorkdir(t)
		bad := filepath.Join(workdir, "public", "pool", "Bad", "c", "f", "foo", "foo_1.0_amd64.deb")
		require.NoError(t, os.MkdirAll(filepath.Dir(bad), 0o755))
		require.NoError(t, os.WriteFile(bad, []byte("not a deb"), 0o644))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrMisplaced)
		require.ErrorIs(t, err, ErrInvalidName)
	})

	const rel = "f/foo/foo_1.0_amd64.deb"

	t.Run("same name different bytes", func(t *testing.T) {
		workdir := newWorkdir(t)
		poolFile(t, workdir, ctl("foo", "1.0", ""), "a", "main", rel)
		poolFile(t, workdir, ctl("foo", "1.0", "Description: x\n"), "b", "main", rel)

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrConflict)
		assert.NoDirExists(t, filepath.Join(workdir, "public", "dists"))
	})

	t.Run("same file name through epoch only", func(t *testing.T) {
		workdir := newWorkdir(t)
		poolFile(t, workdir, ctl("foo", "1:2.0", ""), "a", "main", "f/foo/foo_2.0_amd64.deb")
		poolFile(t, workdir, ctl("foo", "2.0", ""), "b", "main", "f/foo/foo_2.0_amd64.deb")

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrConflict)
	})

	t.Run("identical copies", func(t *testing.T) {
		workdir := newWorkdir(t)
		poolFile(t, workdir, ctl("foo", "1.0", ""), "a", "main", rel)
		poolFile(t, workdir, ctl("foo", "1.0", ""), "b", "main", rel)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
	})
}

func TestStanza(t *testing.T) {
	pkg := debfile.Package{Size: 7, MD5: "m", SHA1: "s1", SHA256: "s256"}

	got := stanza("Version: 1\npAcKaGe: foo\nFilename: old\n obsolete\nsIzE: 99\nSHA256: old\nDescription: foo\n more", "pool/x.deb", pkg)
	assert.Equal(t, "pAcKaGe: foo\nVersion: 1\nDescription: foo\n more\nFilename: pool/x.deb\nSize: 7\nMD5sum: m\nSHA1: s1\nSHA256: s256", got)
}

func TestBuildBadPoolKeepsPublishedSuite(t *testing.T) {
	workdir := newWorkdir(t)
	addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", ""))

	_, err := Build(t.Context(), workdir, buildTime)
	require.NoError(t, err)
	original := readPublic(t, workdir, "dists", "stable", "InRelease")

	pool := filepath.Join(workdir, "public", "pool")
	require.NoError(t, os.Rename(pool, filepath.Join(workdir, "old-pool")))
	require.NoError(t, os.WriteFile(pool, nil, 0o644))

	_, err = Build(t.Context(), workdir, buildTime)
	require.ErrorContains(t, err, "is not a directory")
	assert.Equal(t, original, readPublic(t, workdir, "dists", "stable", "InRelease"))
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer

	prev := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &buf
}

func TestBuildLogs(t *testing.T) {
	t.Run("first build logs by-hash and updated", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		out := logs.String()
		assert.NotContains(t, out, "parsed", "add primes the cache")
		assert.Equal(t, 9, strings.Count(out, `msg="added by-hash"`))
		assert.Contains(t, out, "msg=updated path=public/dists/s/c/binary-amd64/Packages\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/c/binary-amd64/Packages.gz\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/c/binary-amd64/Packages.zst\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/c/binary-amd64/Release\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/Release\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/Release.gpg\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/InRelease\n")
	})

	t.Run("parsed without cache", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))
		addPkg(t, workdir, "s", "c", ctl("bar", "1.0", ""))
		require.NoError(t, os.RemoveAll(filepath.Join(workdir, "cache")))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		out := logs.String()
		assert.Contains(t, out, "msg=parsed path=public/pool/s/c/b/bar/bar_1.0_amd64.deb\n")
		assert.Contains(t, out, "msg=parsed path=public/pool/s/c/f/foo/foo_1.0_amd64.deb\n")
		assert.Less(t, strings.Index(out, "bar_1.0"), strings.Index(out, "foo_1.0"))
	})

	t.Run("unchanged rebuild only rewrites signed release files", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "s", "c", ctl("foo", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		packages := filepath.Join(workdir, "public", "dists", "s", "c", "binary-amd64", "Packages")
		past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, os.Chtimes(packages, past, past))

		logs := captureLogs(t)

		_, err = Build(t.Context(), workdir, buildTime.Add(time.Hour))
		require.NoError(t, err)

		out := logs.String()
		assert.NotContains(t, out, "parsed")
		assert.NotContains(t, out, "added by-hash")
		assert.Equal(t, 3, strings.Count(out, "msg=updated"), out)
		assert.Contains(t, out, "msg=updated path=public/dists/s/Release\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/Release.gpg\n")
		assert.Contains(t, out, "msg=updated path=public/dists/s/InRelease\n")

		info, err := os.Stat(packages)
		require.NoError(t, err)
		assert.True(t, info.ModTime().Equal(past))
	})

	t.Run("deleted pool file drops cache entry and stale suite", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "a", "c", ctl("foo", "1.0", ""))
		gone := addPkg(t, workdir, "b", "c", ctl("bar", "1.0", ""))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(workdir, "public", filepath.FromSlash(gone.Path))))

		logs := captureLogs(t)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		out := logs.String()
		assert.Contains(t, out, fmt.Sprintf("msg=\"cache dropped\" path=public/%s\n", gone.Path))
		assert.Contains(t, out, "msg=\"removed stale\" path=public/dists/b\n")
	})
}

func BenchmarkBuild(b *testing.B) {
	workdir := b.TempDir()
	require.NoError(b, Init(b.Context(), workdir, "Repo Signer", "repo@example.com"))

	src := filepath.Join(b.TempDir(), "a.deb")
	data, err := debtest.Build(ctl("foo", "1.0", ""))
	require.NoError(b, err)
	require.NoError(b, os.WriteFile(src, data, 0o600))
	_, err = Add(b.Context(), workdir, "s", "c", src)
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		_, err := Build(b.Context(), workdir, buildTime)
		require.NoError(b, err)
	}
}

func FuzzStanza(f *testing.F) {
	f.Add("Package: foo\nVersion: 1", "pool/a.deb")
	f.Add("Version: 1\nPackage: foo", "pool/a.deb")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, raw, filename string) {
		got := stanza(raw, filename, debfile.Package{})

		assert.Contains(t, got, fmt.Sprintf("\nFilename: %s\nSize: 0\n", filename))

		control, err := debfile.ParseControl(raw)
		if err == nil && control.Validate() == nil {
			name, _, _ := strings.Cut(got, ":")
			assert.True(t, strings.EqualFold(name, "Package"))
		}
	})
}

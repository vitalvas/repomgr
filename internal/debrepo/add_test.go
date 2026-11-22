package debrepo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/debtest"
)

func newWorkdir(t *testing.T) string {
	t.Helper()

	workdir := t.TempDir()
	require.NoError(t, Init(t.Context(), workdir, "Repo Signer", "repo@example.com"))

	return workdir
}

func writeDeb(t *testing.T, control string) string {
	t.Helper()

	data, err := debtest.Build(control)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "test.deb")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

func ctl(pkg, version, extra string) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\n%s", pkg, version, extra)
}

func TestAdd(t *testing.T) {
	t.Run("copies into pool", func(t *testing.T) {
		workdir := newWorkdir(t)
		src := writeDeb(t, ctl("ikev2-hub", "0.12.0", ""))

		res, err := Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)

		want := "pool/stable/main/i/ikev2-hub/ikev2-hub_0.12.0_amd64.deb"
		assert.Equal(t, AddResult{Path: want, Added: true}, res)

		target := filepath.Join(workdir, "public", want)
		got, err := os.ReadFile(target)
		require.NoError(t, err)
		orig, err := os.ReadFile(src)
		require.NoError(t, err)
		assert.Equal(t, orig, got)

		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	})

	paths := []struct {
		name    string
		control string
		want    string
	}{
		{"epoch stripped", ctl("foo", "1:2.0-1", ""), "pool/s/c/f/foo/foo_2.0-1_amd64.deb"},
		{"source with version", ctl("zabbix-release", "1.0", "Source: zabbix (1.0)\n"), "pool/s/c/z/zabbix/zabbix-release_1.0_amd64.deb"},
		{"source without version", ctl("zabbix-release", "1.0", "Source: zabbix \n"), "pool/s/c/z/zabbix/zabbix-release_1.0_amd64.deb"},
		{"lib prefix", ctl("libfoo1", "1.0", ""), "pool/s/c/libf/libfoo1/libfoo1_1.0_amd64.deb"},
		{"short lib name", ctl("lib", "1.0", ""), "pool/s/c/l/lib/lib_1.0_amd64.deb"},
	}

	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Add(t.Context(), newWorkdir(t), "s", "c", writeDeb(t, tc.control))
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.Path)
		})
	}

	t.Run("same bytes twice is unchanged", func(t *testing.T) {
		workdir := newWorkdir(t)
		src := writeDeb(t, ctl("foo", "1.0", ""))

		first, err := Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)

		target := filepath.Join(workdir, "public", first.Path)
		old := time.Now().Add(-time.Hour).Truncate(time.Second)
		require.NoError(t, os.Chtimes(target, old, old))

		second, err := Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)
		assert.Equal(t, AddResult{Path: first.Path, Added: false}, second)

		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.True(t, info.ModTime().Equal(old))
	})

	t.Run("different bytes conflict", func(t *testing.T) {
		workdir := newWorkdir(t)
		first := writeDeb(t, ctl("foo", "1.0", ""))
		other := writeDeb(t, ctl("foo", "1.0", "Description: different\n"))

		res, err := Add(t.Context(), workdir, "stable", "main", first)
		require.NoError(t, err)

		_, err = Add(t.Context(), workdir, "stable", "main", other)
		require.ErrorIs(t, err, ErrConflict)

		target := filepath.Join(workdir, "public", res.Path)
		got, err := os.ReadFile(target)
		require.NoError(t, err)
		orig, err := os.ReadFile(first)
		require.NoError(t, err)
		assert.Equal(t, orig, got)
		assertNoTemp(t, filepath.Dir(target), 1)
	})

	t.Run("not initialized", func(t *testing.T) {
		_, err := Add(t.Context(), t.TempDir(), "stable", "main", writeDeb(t, ctl("foo", "1.0", "")))
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("invalid names", func(t *testing.T) {
		src := writeDeb(t, ctl("foo", "1.0", ""))

		for _, bad := range []string{"Stable", "../x", "", "-a", "a/b"} {
			_, err := Add(t.Context(), newWorkdir(t), bad, "main", src)
			assert.ErrorIs(t, err, ErrInvalidName, "suite %q", bad)

			_, err = Add(t.Context(), newWorkdir(t), "stable", bad, src)
			assert.ErrorIs(t, err, ErrInvalidName, "component %q", bad)
		}
	})

	t.Run("invalid names are checked before parsing the package", func(t *testing.T) {
		notDeb := filepath.Join(t.TempDir(), "x.deb")
		require.NoError(t, os.WriteFile(notDeb, []byte("not a deb"), 0o600))

		_, err := Add(t.Context(), newWorkdir(t), "Bad", "main", notDeb)
		assert.ErrorIs(t, err, ErrInvalidName)
	})

	t.Run("invalid source", func(t *testing.T) {
		for _, source := range []string{"../evil", "Upper", "a"} {
			_, err := Add(t.Context(), newWorkdir(t), "s", "c", writeDeb(t, ctl("foo", "1.0", fmt.Sprintf("Source: %s\n", source))))
			assert.ErrorIs(t, err, debfile.ErrInvalidField, source)
		}
	})

	t.Run("invalid package", func(t *testing.T) {
		_, err := Add(t.Context(), newWorkdir(t), "s", "c", writeDeb(t, ctl("Foo", "1.0", "")))
		assert.ErrorIs(t, err, debfile.ErrInvalidField)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := Add(t.Context(), newWorkdir(t), "s", "c", filepath.Join(t.TempDir(), "none.deb"))
		assert.Error(t, err)
	})

	t.Run("pool blocked by file", func(t *testing.T) {
		workdir := newWorkdir(t)
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "pool"), nil, 0o644))

		_, err := Add(t.Context(), workdir, "s", "c", writeDeb(t, ctl("foo", "1.0", "")))
		assert.Error(t, err)
	})

	t.Run("target is a directory", func(t *testing.T) {
		workdir := newWorkdir(t)
		dir := filepath.Join(workdir, "public", "pool", "s", "c", "f", "foo", "foo_1.0_amd64.deb")
		require.NoError(t, os.MkdirAll(dir, 0o755))

		_, err := Add(t.Context(), workdir, "s", "c", writeDeb(t, ctl("foo", "1.0", "")))
		assert.Error(t, err)
	})

	t.Run("read-only target dir leaves no temp", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks do not apply to root")
		}

		workdir := newWorkdir(t)
		dir := filepath.Join(workdir, "public", "pool", "s", "c", "f", "foo")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		_, err := Add(t.Context(), workdir, "s", "c", writeDeb(t, ctl("foo", "1.0", "")))
		require.Error(t, err)
		assertNoTemp(t, dir, 0)
	})

	t.Run("no temp after success", func(t *testing.T) {
		workdir := newWorkdir(t)

		res, err := Add(t.Context(), workdir, "s", "c", writeDeb(t, ctl("foo", "1.0", "")))
		require.NoError(t, err)
		assertNoTemp(t, filepath.Dir(filepath.Join(workdir, "public", res.Path)), 1)
	})
}

func TestAddCrossPool(t *testing.T) {
	t.Run("same bytes in two suites", func(t *testing.T) {
		workdir := newWorkdir(t)
		src := writeDeb(t, ctl("foo", "1.0", ""))

		_, err := Add(t.Context(), workdir, "a", "main", src)
		require.NoError(t, err)

		res, err := Add(t.Context(), workdir, "b", "main", src)
		require.NoError(t, err)
		assert.True(t, res.Added)
	})

	conflicts := []struct {
		name    string
		version string
		suite   string
		comp    string
	}{
		{"other suite", "1.0", "b", "main"},
		{"other component", "1.0", "a", "extra"},
		{"epoch only", "1:1.0", "b", "main"},
	}

	for _, tc := range conflicts {
		t.Run(tc.name, func(t *testing.T) {
			workdir := newWorkdir(t)

			_, err := Add(t.Context(), workdir, "a", "main", writeDeb(t, ctl("foo", "1.0", "")))
			require.NoError(t, err)

			_, err = Add(t.Context(), workdir, tc.suite, tc.comp, writeDeb(t, ctl("foo", tc.version, "Description: x\n")))
			require.ErrorIs(t, err, ErrConflict)
			assert.NoDirExists(t, filepath.Join(workdir, "public", "pool", tc.suite, tc.comp, "f"))
		})
	}
}

func TestAddRejectsConflictAcrossSources(t *testing.T) {
	workdir := newWorkdir(t)
	addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", "Source: first\n"))

	_, err := Add(t.Context(), workdir, "testing", "main", writeDeb(t, ctl("foo", "1.0", "Source: second\n")))
	require.ErrorIs(t, err, ErrConflict)
	assert.NoDirExists(t, filepath.Join(workdir, "public", "pool", "testing"))
}

func TestAddGlobMetaWorkdir(t *testing.T) {
	workdir := filepath.Join(t.TempDir(), "w[1]")
	require.NoError(t, os.MkdirAll(workdir, 0o755))
	require.NoError(t, Init(t.Context(), workdir, "Repo Signer", "repo@example.com"))

	_, err := Add(t.Context(), workdir, "a", "main", writeDeb(t, ctl("foo", "1.0", "")))
	require.NoError(t, err)

	_, err = Add(t.Context(), workdir, "b", "main", writeDeb(t, ctl("foo", "1.0", "Description: x\n")))
	require.ErrorIs(t, err, ErrConflict)
}

func TestCopyVerified(t *testing.T) {
	src := writeDeb(t, ctl("foo", "1.0", ""))

	data, err := os.ReadFile(src)
	require.NoError(t, err)

	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	t.Run("matching hash is written", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "a", "foo.deb")

		require.NoError(t, copyVerified(src, target, want))

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})

	t.Run("changed input is not renamed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "foo.deb")

		err := copyVerified(src, target, "deadbeef")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "changed during the add")
		assert.NoFileExists(t, target)
		assertNoTemp(t, dir, 0)
	})

	t.Run("missing source", func(t *testing.T) {
		err := copyVerified(filepath.Join(t.TempDir(), "none.deb"), filepath.Join(t.TempDir(), "foo.deb"), want)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func assertNoTemp(t *testing.T, dir string, wantFiles int) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, wantFiles)
}

func BenchmarkAdd(b *testing.B) {
	workdir := b.TempDir()
	require.NoError(b, os.MkdirAll(filepath.Join(workdir, "config"), 0o755))
	require.NoError(b, os.WriteFile(filepath.Join(workdir, "config", "repo.yaml"), nil, 0o644))

	data, err := debtest.Build(ctl("foo", "1.0", ""))
	require.NoError(b, err)

	src := filepath.Join(b.TempDir(), "test.deb")
	require.NoError(b, os.WriteFile(src, data, 0o600))

	for b.Loop() {
		_, err := Add(b.Context(), workdir, "s", "c", src)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzAdd(f *testing.F) {
	f.Add("foo", "1.0", "")
	f.Add("foo", "1:2.0-1", "zabbix (1.0)")
	f.Add("libfoo", "1.0", "../evil")

	f.Fuzz(func(t *testing.T, pkg, version, source string) {
		control := ctl(pkg, version, "")
		if source != "" {
			control = ctl(pkg, version, fmt.Sprintf("Source: %s\n", source))
		}

		data, err := debtest.Build(control)
		if err != nil {
			t.Skip()
		}

		src := filepath.Join(t.TempDir(), "test.deb")
		require.NoError(t, os.WriteFile(src, data, 0o600))

		workdir := newWorkdir(t)

		res, err := Add(t.Context(), workdir, "s", "c", src)
		if err != nil {
			return
		}

		rel, err := filepath.Rel(filepath.Join(workdir, "public", "pool", "s", "c"), filepath.Join(workdir, "public", res.Path))
		require.NoError(t, err)
		assert.True(t, filepath.IsLocal(rel), rel)
	})
}

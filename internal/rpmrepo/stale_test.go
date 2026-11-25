package rpmrepo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveStale(t *testing.T) {
	build := func(t *testing.T, workdir string) {
		t.Helper()

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
	}

	exists := func(workdir string, parts ...string) bool {
		_, err := os.Lstat(filepath.Join(append([]string{workdir, "public"}, parts...)...))

		return err == nil
	}

	t.Run("last component removes release", func(t *testing.T) {
		workdir := initWorkdir(t)
		pool := addPkg(t, workdir, "9/main", basePkg())
		build(t, workdir)

		require.NoError(t, os.Remove(pool))

		logs := captureLogs(t)

		build(t, workdir)
		assert.Contains(t, logs.String(), "msg=\"removed stale\" path=public/x86_64/9\n")
		assert.False(t, exists(workdir, "x86_64", "9"))
		assert.True(t, exists(workdir, "x86_64"))
	})

	t.Run("other component stays", func(t *testing.T) {
		workdir := initWorkdir(t)
		pool := addPkg(t, workdir, "9/main", basePkg())
		addPkg(t, workdir, "9/extra", basePkg())
		build(t, workdir)

		require.NoError(t, os.Remove(pool))

		logs := captureLogs(t)

		build(t, workdir)
		assert.Contains(t, logs.String(), "msg=\"removed stale\" path=public/x86_64/9/main\n")
		assert.False(t, exists(workdir, "x86_64", "9", "main"))
		assert.True(t, exists(workdir, "x86_64", "9", "extra", "repodata", "repomd.xml"))
	})

	t.Run("files and no-op", func(t *testing.T) {
		workdir := initWorkdir(t)
		addPkg(t, workdir, "9/main", basePkg())
		build(t, workdir)

		outside := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "rpmtest.repo"), []byte("x"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "x86_64", "README"), []byte("x"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "x86_64", "9", "note"), []byte("x"), 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(workdir, "public", "x86_64", "link")))

		logs := captureLogs(t)

		build(t, workdir)
		assert.Empty(t, logs.String())

		for _, f := range [][]string{{"rpmtest.repo"}, {"key.asc"}, {"x86_64", "README"}, {"x86_64", "9", "note"}, {"x86_64", "link"}} {
			assert.True(t, exists(workdir, f...), f)
		}

		assert.FileExists(t, filepath.Join(outside, "keep"))
	})

	t.Run("x86_64 only leaves empty arch dir", func(t *testing.T) {
		workdir := initWorkdir(t)
		pool := addPkg(t, workdir, "9/main", basePkg())
		build(t, workdir)

		require.NoError(t, os.Remove(pool))
		build(t, workdir)

		entries, err := os.ReadDir(filepath.Join(workdir, "public", "x86_64"))
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("missing arch dirs", func(t *testing.T) {
		require.NoError(t, removeStale(t.Context(), t.TempDir(), map[string]bool{}))
	})
}

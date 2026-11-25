package repofs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sumOf(data string) string {
	sum := sha256.Sum256([]byte(data))

	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, file, data string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte(data), 0o644))
}

func TestCheckInitialized(t *testing.T) {
	t.Run("missing key", func(t *testing.T) {
		err := CheckInitialized(t.TempDir(), "add")
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Contains(t, err.Error(), "add to ")
	})

	t.Run("key present", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "config", "signing.asc"), "k")
		assert.NoError(t, CheckInitialized(dir, "add"))
	})

	t.Run("stat failure", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "config"), "not a dir")

		err := CheckInitialized(dir, "add")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotInitialized)
	})
}

func TestCheckName(t *testing.T) {
	for _, good := range []string{"a", "main", "el9", "a_b-c", "0x"} {
		assert.NoError(t, CheckName("component", good), good)
	}

	for _, bad := range []string{"", "-a", "_a", "A", "a b", "a/b", "a.b"} {
		err := CheckName("component", bad)
		require.ErrorIs(t, err, ErrInvalidName, bad)
		assert.Contains(t, err.Error(), fmt.Sprintf("component %q", bad))
	}
}

func TestWalkPool(t *testing.T) {
	collect := func(pool string) ([]string, error) {
		var names []string

		err := WalkPool(pool, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				names = append(names, d.Name())
			}

			return err
		})

		return names, err
	}

	t.Run("missing pool is empty", func(t *testing.T) {
		names, err := collect(filepath.Join(t.TempDir(), "pool"))
		require.NoError(t, err)
		assert.Empty(t, names)
	})

	t.Run("visits files", func(t *testing.T) {
		pool := t.TempDir()
		writeFile(t, filepath.Join(pool, "a", "x.rpm"), "x")

		names, err := collect(pool)
		require.NoError(t, err)
		assert.Equal(t, []string{"x.rpm"}, names)
	})

	t.Run("pool is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "pool")
		writeFile(t, file, "x")

		_, err := collect(file)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a directory")
	})
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	writeFile(t, file, "hello")

	sum, size, err := FileSHA256(file)
	require.NoError(t, err)
	assert.Equal(t, sumOf("hello"), sum)
	assert.Equal(t, int64(5), size)

	_, _, err = FileSHA256(filepath.Join(dir, "none"))
	assert.ErrorIs(t, err, os.ErrNotExist)

	_, _, err = FileSHA256(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

func TestCheckPoolConflicts(t *testing.T) {
	pool := t.TempDir()
	existing := filepath.Join(pool, "a", "x.rpm")
	writeFile(t, existing, "one")

	t.Run("same bytes", func(t *testing.T) {
		assert.NoError(t, CheckPoolConflicts(pool, "x.rpm", sumOf("one"), ""))
	})

	t.Run("other name is ignored", func(t *testing.T) {
		assert.NoError(t, CheckPoolConflicts(pool, "y.rpm", sumOf("two"), ""))
	})

	t.Run("different bytes", func(t *testing.T) {
		assert.ErrorIs(t, CheckPoolConflicts(pool, "x.rpm", sumOf("two"), ""), ErrConflict)
	})

	t.Run("skipped path", func(t *testing.T) {
		assert.NoError(t, CheckPoolConflicts(pool, "x.rpm", sumOf("two"), existing))
	})

	t.Run("not a regular file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o755))
		require.NoError(t, os.Symlink(existing, filepath.Join(dir, "a", "x.rpm")))

		err := CheckPoolConflicts(dir, "x.rpm", sumOf("one"), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})
}

func TestCopyVerified(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src.rpm")
	writeFile(t, src, "payload")

	t.Run("matching hash is written", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "a", "x.rpm")
		require.NoError(t, CopyVerified(src, target, sumOf("payload")))

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, "payload", string(got))
	})

	t.Run("changed input is not renamed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "x.rpm")

		err := CopyVerified(src, target, "deadbeef")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "changed during the add")
		assert.NoFileExists(t, target)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("missing source", func(t *testing.T) {
		err := CopyVerified(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "x.rpm"), sumOf("payload"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

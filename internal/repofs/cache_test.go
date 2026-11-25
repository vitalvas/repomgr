package repofs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEntry struct {
	Size int64  `json:"size"`
	Name string `json:"name"`
}

func TestCache(t *testing.T) {
	index := func(workdir string) string {
		return filepath.Join(workdir, "cache", "index.json")
	}

	t.Run("missing file gives empty map", func(t *testing.T) {
		entries, err := LoadCache[testEntry](t.TempDir())
		require.NoError(t, err)
		assert.NotNil(t, entries)
		assert.Empty(t, entries)
	})

	t.Run("unreadable file is an error", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(index(workdir), 0o755))

		entries, err := LoadCache[testEntry](workdir)
		require.Error(t, err)
		assert.Nil(t, entries)
		assert.Contains(t, err.Error(), "read ")
		assert.Contains(t, err.Error(), "index.json")
	})

	for name, content := range map[string]string{"invalid json": "not json{", "null": "null"} {
		t.Run(fmt.Sprintf("%s gives empty map", name), func(t *testing.T) {
			workdir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Dir(index(workdir)), 0o755))
			require.NoError(t, os.WriteFile(index(workdir), []byte(content), 0o644))

			entries, err := LoadCache[testEntry](workdir)
			require.NoError(t, err)
			assert.NotNil(t, entries)
			assert.Empty(t, entries)
		})
	}

	t.Run("round trip", func(t *testing.T) {
		workdir := t.TempDir()
		want := map[string]testEntry{"pool/a": {Size: 1, Name: "a"}, "pool/b": {Size: 2, Name: "b"}}

		require.NoError(t, SaveCache(workdir, want))

		info, err := os.Stat(index(workdir))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

		got, err := LoadCache[testEntry](workdir)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

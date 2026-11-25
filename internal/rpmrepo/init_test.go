package rpmrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/repofs"
)

func TestInit(t *testing.T) {
	ctx := context.Background()

	t.Run("creates key files", func(t *testing.T) {
		workdir := t.TempDir()

		require.NoError(t, Init(ctx, workdir, "Test", "test@example.com"))

		info, err := os.Stat(filepath.Join(workdir, "config", "signing.asc"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		info, err = os.Stat(filepath.Join(workdir, "public", "key.asc"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

		entries, err := os.ReadDir(filepath.Join(workdir, "public"))
		require.NoError(t, err)
		require.Len(t, entries, 3)
		assert.Equal(t, "aarch64", entries[0].Name())
		assert.Equal(t, "key.asc", entries[1].Name())
		assert.Equal(t, "x86_64", entries[2].Name())

		for _, arch := range []string{"x86_64", "aarch64"} {
			info, err = os.Stat(filepath.Join(workdir, "public", arch))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
		}

		assert.DirExists(t, filepath.Join(workdir, "cache"))
	})

	t.Run("second init fails", func(t *testing.T) {
		workdir := t.TempDir()

		require.NoError(t, Init(ctx, workdir, "Test", ""))
		require.ErrorIs(t, Init(ctx, workdir, "Test", ""), repofs.ErrAlreadyInitialized)
	})

	t.Run("deb workdir refused", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public", "dists"), 0o755))

		require.ErrorIs(t, Init(ctx, workdir, "Test", ""), ErrDebWorkdir)
		assert.NoFileExists(t, filepath.Join(workdir, "config", "signing.asc"))
	})

	t.Run("stat error is returned", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public"), nil, 0o644))

		err := Init(ctx, workdir, "Test", "")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrDebWorkdir)
	})
}

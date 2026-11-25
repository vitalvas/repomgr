package repofs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAtomic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "sub", "f")

		require.NoError(t, WriteAtomic(target, strings.NewReader("data"), 0o640, nil))

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, "data", string(got))

		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	})

	t.Run("verify failure keeps target and removes temp", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "f")
		require.NoError(t, os.WriteFile(target, []byte("old"), 0o644))

		errVerify := errors.New("bad")
		err := WriteAtomic(target, strings.NewReader("new"), 0o644, func() error { return errVerify })
		require.ErrorIs(t, err, errVerify)

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, "old", string(got))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	})
}

func TestLogPath(t *testing.T) {
	assert.Equal(t, "a/b", LogPath("/w", "/w/a/b"))
	assert.Equal(t, "rel", LogPath("/w", "rel"))
}

func TestInitKey(t *testing.T) {
	ctx := context.Background()

	t.Run("second call fails", func(t *testing.T) {
		workdir := t.TempDir()
		var got []byte
		publish := func(_ context.Context, public []byte) error {
			got = public
			return nil
		}

		in := KeyInit{Workdir: workdir, Name: "Test", Publish: publish}

		require.NoError(t, InitKey(ctx, in))
		assert.NotEmpty(t, got)

		err := InitKey(ctx, in)
		require.ErrorIs(t, err, ErrAlreadyInitialized)

		for _, d := range []string{"config", "cache", "public"} {
			assert.DirExists(t, filepath.Join(workdir, d))
		}
	})

	t.Run("publish error leaves no signing.asc", func(t *testing.T) {
		workdir := t.TempDir()
		errPublish := errors.New("publish")

		err := InitKey(ctx, KeyInit{
			Workdir: workdir,
			Name:    "Test",
			Publish: func(context.Context, []byte) error { return errPublish },
		})
		require.ErrorIs(t, err, errPublish)
		assert.NoFileExists(t, filepath.Join(workdir, "config", "signing.asc"))
	})
}

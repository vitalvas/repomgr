package repofs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefuseMarkers(t *testing.T) {
	kind := errors.New("other repository")
	markers := []string{"dists", "key.gpg"}

	t.Run("no marker", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public"), 0o755))

		require.NoError(t, RefuseMarkers(workdir, "add", markers, kind))
	})

	t.Run("each marker", func(t *testing.T) {
		for _, marker := range markers {
			workdir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public", marker), 0o755))

			err := RefuseMarkers(workdir, "add", markers, kind)
			require.ErrorIs(t, err, kind)
			assert.Contains(t, err.Error(), workdir)
		}
	})

	t.Run("marker is a file", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public", "key.gpg"), nil, 0o644))

		require.ErrorIs(t, RefuseMarkers(workdir, "build", markers, kind), kind)
	})

	t.Run("stat error", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "public"), nil, 0o644))

		err := RefuseMarkers(workdir, "init", markers, kind)
		require.Error(t, err)
		assert.NotErrorIs(t, err, kind)
		assert.Contains(t, err.Error(), "stat ")
	})
}

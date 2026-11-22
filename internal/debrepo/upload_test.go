package debrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/debtest"
)

func uploadDeb(t *testing.T, workdir, rel string, data []byte) string {
	t.Helper()

	file := filepath.Join(workdir, "upload", filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, data, 0o600))

	return file
}

func debBytes(t *testing.T, control string) []byte {
	t.Helper()

	data, err := debtest.Build(control)
	require.NoError(t, err)

	return data
}

func TestBuildUploads(t *testing.T) {
	t.Run("moves upload into pool and indexes it", func(t *testing.T) {
		workdir := newWorkdir(t)
		file := uploadDeb(t, workdir, "stable/main/anything.deb", debBytes(t, ctl("foo", "1.0", "")))
		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		assert.NoFileExists(t, file)
		target := filepath.Join(workdir, "public", "pool", "stable", "main", "f", "foo", "amd64", "foo_1.0_amd64.deb")
		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

		assert.Contains(t, readPublic(t, workdir, "dists", "stable", "main", "binary-amd64", "Packages"), "Package: foo\n")
		assert.Contains(t, logs.String(), "msg=moved path=upload/stable/main/anything.deb target=public/pool/stable/main/f/foo/amd64/foo_1.0_amd64.deb")
		assert.DirExists(t, filepath.Join(workdir, "upload", "stable", "main"))
	})

	t.Run("duplicate upload is removed", func(t *testing.T) {
		workdir := newWorkdir(t)
		data := debBytes(t, ctl("foo", "1.0", ""))
		src := filepath.Join(t.TempDir(), "foo.deb")
		require.NoError(t, os.WriteFile(src, data, 0o600))
		_, err := Add(t.Context(), workdir, "stable", "main", src)
		require.NoError(t, err)

		file := uploadDeb(t, workdir, "stable/main/foo.deb", data)
		logs := captureLogs(t)

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.NoFileExists(t, file)
		assert.Contains(t, logs.String(), "msg=\"removed duplicate\" path=upload/stable/main/foo.deb")
	})

	t.Run("conflict stays in upload and fails after publishing", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "stable", "main", ctl("foo", "1.0", "Description: first\n"))
		file := uploadDeb(t, workdir, "testing/main/foo.deb", debBytes(t, ctl("foo", "1.0", "Description: second\n")))
		logs := captureLogs(t)

		summaries, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrUploadRejected)
		assert.ErrorContains(t, err, "1 upload rejected")
		assert.FileExists(t, file)
		assert.Len(t, summaries, 1)
		assert.FileExists(t, filepath.Join(workdir, "public", "dists", "stable", "InRelease"))
		assert.Contains(t, logs.String(), "msg=\"upload rejected\" path=upload/testing/main/foo.deb")
	})

	t.Run("second of two conflicting uploads is rejected", func(t *testing.T) {
		workdir := newWorkdir(t)
		first := uploadDeb(t, workdir, "stable/main/a.deb", debBytes(t, ctl("foo", "1.0", "Description: first\n")))
		second := uploadDeb(t, workdir, "stable/main/b.deb", debBytes(t, ctl("foo", "1.0", "Description: second\n")))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrUploadRejected)
		assert.NoFileExists(t, first)
		assert.FileExists(t, second)
		assert.Contains(t, readPublic(t, workdir, "dists", "stable", "main", "binary-amd64", "Packages"), "Description: first\n")
	})

	t.Run("invalid uploads stay and are counted", func(t *testing.T) {
		workdir := newWorkdir(t)
		data := debBytes(t, ctl("foo", "1.0", ""))
		rejected := []string{
			uploadDeb(t, workdir, "foo.deb", data),
			uploadDeb(t, workdir, "stable/foo.deb", data),
			uploadDeb(t, workdir, "stable/main/extra/foo.deb", data),
			uploadDeb(t, workdir, "Bad/main/foo.deb", data),
			uploadDeb(t, workdir, "stable/main/broken.deb", []byte("not a deb")),
		}

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrUploadRejected)
		assert.ErrorContains(t, err, "5 uploads rejected")

		for _, file := range rejected {
			assert.FileExists(t, file)
		}

		assert.NoDirExists(t, filepath.Join(workdir, "public", "pool"))
	})

	t.Run("dot files and other names are ignored", func(t *testing.T) {
		workdir := newWorkdir(t)
		data := debBytes(t, ctl("foo", "1.0", ""))
		ignored := []string{
			uploadDeb(t, workdir, "stable/main/.foo.deb", data),
			uploadDeb(t, workdir, "stable/main/foo.deb.part", data),
			uploadDeb(t, workdir, ".partial/main/foo.deb", data),
		}
		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		for _, file := range ignored {
			assert.FileExists(t, file)
		}

		assert.False(t, strings.Contains(logs.String(), "upload"))
	})

	t.Run("upload path that is a file fails the build", func(t *testing.T) {
		workdir := newWorkdir(t)
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "upload"), nil, 0o644))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorContains(t, err, "is not a directory")
		assert.NotErrorIs(t, err, ErrUploadRejected)
	})
}

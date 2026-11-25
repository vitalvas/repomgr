package rpmrepo

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/repofs"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

type uploadFixture struct {
	workdir string
	logs    *bytes.Buffer
}

func newUploadFixture(t *testing.T) uploadFixture {
	t.Helper()

	var logs bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return uploadFixture{workdir: initWorkdir(t), logs: &logs}
}

func (f uploadFixture) put(t *testing.T, rel string, data []byte) string {
	t.Helper()

	file := filepath.Join(f.workdir, "upload", filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, data, 0o644))

	return file
}

func rpmBytes(t *testing.T, p rpmtest.Package) []byte {
	t.Helper()

	data, err := rpmtest.Build(p)
	require.NoError(t, err)

	return data
}

func TestBuildUpload(t *testing.T) {
	t.Run("moves into the pool and indexes", func(t *testing.T) {
		f := newUploadFixture(t)
		src := f.put(t, "8/main/x.rpm", rpmBytes(t, basePkg()))

		summaries, err := Build(context.Background(), f.workdir, buildTime)
		require.NoError(t, err)

		assert.Equal(t, []Summary{{Release: "8", Component: "main", Packages: 1, Arches: []string{"x86_64"}}}, summaries)
		assert.NoFileExists(t, src)
		assert.FileExists(t, filepath.Join(f.workdir, "public", "pool", "8", "main", "p", "pdns", "x86_64", "pdns-5.1.0-1.el9.x86_64.rpm"))
		assert.FileExists(t, filepath.Join(f.workdir, "public", "x86_64", "8", "main", "repodata", "repomd.xml"))
		assert.Contains(t, f.logs.String(), "msg=moved path=upload/8/main/x.rpm")
	})

	t.Run("duplicate of a pool file is removed", func(t *testing.T) {
		f := newUploadFixture(t)
		addPkg(t, f.workdir, "8/main", basePkg())

		src := f.put(t, "8/main/x.rpm", rpmBytes(t, basePkg()))

		_, err := Build(context.Background(), f.workdir, buildTime)
		require.NoError(t, err)

		assert.NoFileExists(t, src)
		assert.Contains(t, f.logs.String(), "msg=\"removed duplicate\" path=upload/8/main/x.rpm")
	})

	t.Run("rejected files stay and the build still publishes", func(t *testing.T) {
		f := newUploadFixture(t)

		good := basePkg()
		good.Name = "good"

		ctrl := basePkg()
		ctrl.Name = "ctrl"
		ctrl.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: "a\x01b"}}

		rejected := []string{
			f.put(t, "7/main/x.rpm", rpmBytes(t, basePkg())),
			f.put(t, "8/x.rpm", rpmBytes(t, basePkg())),
			f.put(t, "8/main/sub/x.rpm", rpmBytes(t, basePkg())),
			f.put(t, "8/main/ctrl.rpm", rpmBytes(t, ctrl)),
			f.put(t, "8/main/junk.rpm", []byte("not an rpm")),
		}

		goodFile := f.put(t, "8/main/good.rpm", rpmBytes(t, good))

		summaries, err := Build(context.Background(), f.workdir, buildTime)
		require.ErrorIs(t, err, repofs.ErrUploadRejected)
		assert.ErrorContains(t, err, "5 uploads rejected")

		assert.Equal(t, []Summary{{Release: "8", Component: "main", Packages: 1, Arches: []string{"x86_64"}}}, summaries)
		assert.NoFileExists(t, goodFile)
		assert.FileExists(t, filepath.Join(f.workdir, "public", "x86_64", "8", "main", "repodata", "repomd.xml"))

		for _, file := range rejected {
			assert.FileExists(t, file)
		}
	})

	t.Run("one rejection uses the singular", func(t *testing.T) {
		f := newUploadFixture(t)
		f.put(t, "8/main/junk.rpm", []byte("not an rpm"))

		_, err := Build(context.Background(), f.workdir, buildTime)
		require.ErrorIs(t, err, repofs.ErrUploadRejected)
		assert.ErrorContains(t, err, "1 upload rejected")
	})

	t.Run("dot files and part names are skipped", func(t *testing.T) {
		f := newUploadFixture(t)
		data := rpmBytes(t, basePkg())

		skipped := []string{
			f.put(t, "8/main/.x.rpm", data),
			f.put(t, "8/main/x.rpm.part", data),
			f.put(t, "8/.hidden/x.rpm", data),
		}

		_, err := Build(context.Background(), f.workdir, buildTime)
		require.NoError(t, err)

		for _, file := range skipped {
			assert.FileExists(t, file)
		}
	})
}

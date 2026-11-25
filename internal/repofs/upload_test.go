package repofs

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubAdd struct {
	calls  []string
	result UploadResult
	err    error
}

func (s *stubAdd) upload() Upload {
	return Upload{
		Ext:    ".pkg",
		Layout: "upload/<group>/<component>/<file>.pkg",
		Add: func(group, component, file string) (UploadResult, error) {
			data, err := os.ReadFile(file)
			if err != nil {
				return UploadResult{}, err
			}

			s.calls = append(s.calls, fmt.Sprintf("%s/%s %s", group, component, data))

			return s.result, s.err
		},
	}
}

func captureUploadLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &logs
}

func putUpload(t *testing.T, workdir, rel string) string {
	t.Helper()

	file := filepath.Join(workdir, "upload", filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte("payload"), 0o600))

	return file
}

type swapCase struct {
	workdir string
	file    string
	entry   os.DirEntry
}

func newSwapCase(t *testing.T) swapCase {
	t.Helper()

	workdir := t.TempDir()
	file := putUpload(t, workdir, "g/c/x.pkg")

	entries, err := os.ReadDir(filepath.Dir(file))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	return swapCase{workdir: workdir, file: file, entry: entries[0]}
}

func (c swapCase) move(t *testing.T, stub *stubAdd) error {
	t.Helper()

	root, err := os.OpenRoot(filepath.Join(c.workdir, "upload"))
	require.NoError(t, err)
	t.Cleanup(func() { root.Close() })

	return moveUpload(t.Context(), stub.upload(), uploadFile{workdir: c.workdir, root: root, file: c.file, entry: c.entry})
}

func TestProcessUploads(t *testing.T) {
	t.Run("missing upload dir is not an error", func(t *testing.T) {
		stub := &stubAdd{}

		rejected, err := ProcessUploads(t.Context(), t.TempDir(), stub.upload())
		require.NoError(t, err)
		assert.Zero(t, rejected)
		assert.Empty(t, stub.calls)
	})

	t.Run("upload path that is a file fails", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "upload"), nil, 0o644))

		_, err := ProcessUploads(t.Context(), workdir, (&stubAdd{}).upload())
		require.ErrorContains(t, err, "is not a directory")
		assert.NotErrorIs(t, err, ErrUploadRejected)
	})

	t.Run("added upload is removed and logged as moved", func(t *testing.T) {
		workdir := t.TempDir()
		file := putUpload(t, workdir, "g/c/a.pkg")
		logs := captureUploadLogs(t)
		stub := &stubAdd{result: UploadResult{Path: "pool/a.pkg", Added: true}}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Zero(t, rejected)
		assert.Equal(t, []string{"g/c payload"}, stub.calls)
		assert.NoFileExists(t, file)
		assert.DirExists(t, filepath.Dir(file))
		assert.Contains(t, logs.String(), "msg=moved path=upload/g/c/a.pkg target=public/pool/a.pkg")
		assert.NotContains(t, logs.String(), "removed duplicate")
	})

	t.Run("duplicate upload is removed and logged", func(t *testing.T) {
		workdir := t.TempDir()
		file := putUpload(t, workdir, "g/c/a.pkg")
		logs := captureUploadLogs(t)
		stub := &stubAdd{result: UploadResult{Path: "pool/a.pkg"}}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Zero(t, rejected)
		assert.NoFileExists(t, file)
		assert.Contains(t, logs.String(), "msg=\"removed duplicate\" path=upload/g/c/a.pkg target=public/pool/a.pkg")
		assert.NotContains(t, logs.String(), "msg=moved")
	})

	t.Run("failed add keeps the upload and counts it", func(t *testing.T) {
		workdir := t.TempDir()
		file := putUpload(t, workdir, "g/c/a.pkg")
		logs := captureUploadLogs(t)
		stub := &stubAdd{err: errors.New("boom")}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Equal(t, 1, rejected)
		assert.FileExists(t, file)
		assert.Contains(t, logs.String(), "msg=\"upload rejected\" path=upload/g/c/a.pkg error=boom")

		left, err := filepath.Glob(filepath.Join(workdir, "cache", ".upload-*.pkg"))
		require.NoError(t, err)
		assert.Empty(t, left)
	})

	t.Run("wrong depth is rejected with the layout", func(t *testing.T) {
		workdir := t.TempDir()
		files := []string{
			putUpload(t, workdir, "a.pkg"),
			putUpload(t, workdir, "g/a.pkg"),
			putUpload(t, workdir, "g/c/extra/a.pkg"),
		}
		logs := captureUploadLogs(t)
		stub := &stubAdd{}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Equal(t, 3, rejected)
		assert.Empty(t, stub.calls)

		for _, file := range files {
			assert.FileExists(t, file)
		}

		assert.Contains(t, logs.String(), "not at upload/<group>/<component>/<file>.pkg")
	})

	t.Run("dot entries and other extensions are skipped", func(t *testing.T) {
		workdir := t.TempDir()
		skipped := []string{
			putUpload(t, workdir, "g/c/.a.pkg"),
			putUpload(t, workdir, "g/c/a.pkg.part"),
			putUpload(t, workdir, "g/c/a.deb"),
			putUpload(t, workdir, ".partial/c/a.pkg"),
		}
		logs := captureUploadLogs(t)
		stub := &stubAdd{}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Zero(t, rejected)
		assert.Empty(t, stub.calls)

		for _, file := range skipped {
			assert.FileExists(t, file)
		}

		assert.Empty(t, logs.String())
	})

	t.Run("symlink is rejected and its target untouched", func(t *testing.T) {
		workdir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.pkg")
		require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))

		link := filepath.Join(workdir, "upload", "g", "c", "x.pkg")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
		require.NoError(t, os.Symlink(outside, link))

		stub := &stubAdd{}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Equal(t, 1, rejected)
		assert.Empty(t, stub.calls)

		_, err = os.Lstat(link)
		require.NoError(t, err)

		after, err := os.ReadFile(outside)
		require.NoError(t, err)
		assert.Equal(t, []byte("secret"), after)
	})

	t.Run("FIFO is rejected without blocking", func(t *testing.T) {
		workdir := t.TempDir()
		fifo := filepath.Join(workdir, "upload", "g", "c", "x.pkg")
		require.NoError(t, os.MkdirAll(filepath.Dir(fifo), 0o755))
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))

		stub := &stubAdd{}

		rejected, err := ProcessUploads(t.Context(), workdir, stub.upload())
		require.NoError(t, err)
		assert.Equal(t, 1, rejected)
		assert.Empty(t, stub.calls)

		_, err = os.Lstat(fifo)
		require.NoError(t, err)
	})
}

func TestMoveUploadSwappedForSymlink(t *testing.T) {
	c := newSwapCase(t)
	outside := filepath.Join(t.TempDir(), "outside.pkg")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	require.NoError(t, os.Remove(c.file))
	require.NoError(t, os.Symlink(outside, c.file))

	stub := &stubAdd{}

	require.Error(t, c.move(t, stub))
	assert.Empty(t, stub.calls)

	after, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), after)

	link, err := os.Lstat(c.file)
	require.NoError(t, err)
	assert.NotZero(t, link.Mode()&os.ModeSymlink)
}

func TestMoveUploadParentSwappedForSymlink(t *testing.T) {
	c := newSwapCase(t)
	componentDir := filepath.Dir(c.file)
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "x.pkg")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	require.NoError(t, os.RemoveAll(componentDir))
	require.NoError(t, os.Symlink(outsideDir, componentDir))

	stub := &stubAdd{}

	require.Error(t, c.move(t, stub))
	assert.Empty(t, stub.calls)

	after, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), after)
}

func TestMoveUploadSwappedForFIFO(t *testing.T) {
	c := newSwapCase(t)
	require.NoError(t, os.Remove(c.file))
	require.NoError(t, syscall.Mkfifo(c.file, 0o600))

	stub := &stubAdd{}

	require.ErrorContains(t, c.move(t, stub), "not a regular file")
	assert.Empty(t, stub.calls)

	_, err := os.Lstat(c.file)
	require.NoError(t, err)
}

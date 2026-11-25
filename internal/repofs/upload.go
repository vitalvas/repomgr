package repofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrUploadRejected = errors.New("rejected files stay in upload/")

// Upload describes one repository kind: the file extension to pick up, the
// layout text used in rejection messages, and the function that adds a file
// from upload/<group>/<component>/ to the repository.
type Upload struct {
	Ext    string
	Layout string
	Add    func(group, component, file string) (UploadResult, error)
}

// UploadResult is what Add reports: the public-relative path and whether the
// file was new (false means an identical file was already there).
type UploadResult struct {
	Path  string
	Added bool
}

type uploadFile struct {
	workdir string
	root    *os.Root
	file    string
	entry   fs.DirEntry
}

// ProcessUploads moves upload/<group>/<component>/*<u.Ext> into the pool. A
// file that fails any check stays in upload/ and is counted as rejected. Dot
// files and dot directories are skipped so uploaders can write under a
// temporary name and rename when the file is complete.
func ProcessUploads(ctx context.Context, workdir string, u Upload) (int, error) {
	uploadDir := filepath.Join(workdir, "upload")

	info, err := os.Lstat(uploadDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", uploadDir, err)
	}

	if !info.IsDir() {
		return 0, fmt.Errorf("upload %s is not a directory", uploadDir)
	}

	root, err := os.OpenRoot(uploadDir)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", uploadDir, err)
	}
	defer root.Close()

	rejected := 0

	err = filepath.WalkDir(uploadDir, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if strings.HasPrefix(d.Name(), ".") && file != uploadDir {
			if d.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if d.IsDir() || !strings.HasSuffix(d.Name(), u.Ext) {
			return nil
		}

		err = moveUpload(ctx, u, uploadFile{workdir: workdir, root: root, file: file, entry: d})
		if err != nil {
			rejected++
			slog.ErrorContext(ctx, "upload rejected", "path", LogPath(workdir, file), "error", err)
		}

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("walk %s: %w", uploadDir, err)
	}

	return rejected, nil
}

// moveUpload copies the upload through one handle opened inside root into a
// private temp file and adds that copy. A file or parent directory swapped for
// a symlink after the walk can't make it read or remove anything outside
// upload/, and a file swapped for a FIFO can't block the open.
func moveUpload(ctx context.Context, u Upload, f uploadFile) error {
	// Cheap skip of what the walk already saw as non-regular.
	if !f.entry.Type().IsRegular() {
		return errors.New("not a regular file")
	}

	rel, err := filepath.Rel(f.root.Name(), f.file)
	if err != nil {
		return err
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 {
		return fmt.Errorf("not at %s", u.Layout)
	}

	src, err := f.root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}

	cacheDir := filepath.Join(f.workdir, "cache")

	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", cacheDir, err)
	}

	tmp, err := os.CreateTemp(cacheDir, fmt.Sprintf(".upload-*%s", u.Ext))
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	_, err = io.Copy(tmp, src)
	if err != nil {
		return fmt.Errorf("copy upload: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	res, err := u.Add(parts[0], parts[1], tmp.Name())
	if err != nil {
		return err
	}

	current, err := f.root.Lstat(rel)
	if err != nil {
		return fmt.Errorf("stat upload before removal: %w", err)
	}

	if !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return errors.New("upload changed while processing")
	}

	err = f.root.Remove(rel)
	if err != nil {
		return fmt.Errorf("remove upload: %w", err)
	}

	target := path.Join("public", res.Path)

	if !res.Added {
		slog.InfoContext(ctx, "removed duplicate", "path", LogPath(f.workdir, f.file), "target", target)

		return nil
	}

	slog.InfoContext(ctx, "moved", "path", LogPath(f.workdir, f.file), "target", target)

	return nil
}

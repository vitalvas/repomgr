package debrepo

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

// processUploads moves upload/<suite>/<component>/*.deb into the pool. A file
// that fails any check stays in upload/ and is counted as rejected. Dot files
// and dot directories are skipped so uploaders can write under a temporary
// name and rename to *.deb when the file is complete.
func processUploads(ctx context.Context, workdir string) (int, error) {
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

		if d.IsDir() || !strings.HasSuffix(d.Name(), ".deb") {
			return nil
		}

		err = moveUpload(ctx, workdir, root, file, d)
		if err != nil {
			rejected++
			slog.ErrorContext(ctx, "upload rejected", "path", logPath(workdir, file), "error", err)
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
func moveUpload(ctx context.Context, workdir string, root *os.Root, file string, d fs.DirEntry) error {
	// Cheap skip of what the walk already saw as non-regular.
	if !d.Type().IsRegular() {
		return errors.New("not a regular file")
	}

	rel, err := filepath.Rel(root.Name(), file)
	if err != nil {
		return err
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 {
		return errors.New("not at upload/<suite>/<component>/<file>.deb")
	}

	src, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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

	cacheDir := filepath.Join(workdir, "cache")

	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", cacheDir, err)
	}

	tmp, err := os.CreateTemp(cacheDir, ".upload-*.deb")
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

	res, err := Add(workdir, parts[0], parts[1], tmp.Name(), false)
	if err != nil {
		return err
	}

	err = root.Remove(rel)
	if err != nil {
		return fmt.Errorf("remove upload: %w", err)
	}

	target := path.Join("public", res.Path)

	if !res.Added {
		slog.InfoContext(ctx, "removed duplicate", "path", logPath(workdir, file), "target", target)

		return nil
	}

	slog.InfoContext(ctx, "moved", "path", logPath(workdir, file), "target", target)

	return nil
}

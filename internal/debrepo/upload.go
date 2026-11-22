package debrepo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

		err = moveUpload(ctx, workdir, uploadDir, file, d)
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

func moveUpload(ctx context.Context, workdir, uploadDir, file string, d fs.DirEntry) error {
	if !d.Type().IsRegular() {
		return errors.New("not a regular file")
	}

	rel, err := filepath.Rel(uploadDir, file)
	if err != nil {
		return err
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 {
		return errors.New("not at upload/<suite>/<component>/<file>.deb")
	}

	p, err := placePackage(workdir, parts[0], parts[1], file, false)
	if err != nil {
		return err
	}

	if p.exists {
		err = os.Remove(file)
		if err != nil {
			return fmt.Errorf("remove duplicate: %w", err)
		}

		slog.InfoContext(ctx, "removed duplicate", "path", logPath(workdir, file), "target", logPath(workdir, p.target))

		return nil
	}

	err = os.MkdirAll(filepath.Dir(p.target), 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(p.target), err)
	}

	// Pool files are served to clients, so they get the same mode add gives them.
	err = os.Chmod(file, 0o644)
	if err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// upload/ and public/ share a filesystem, so this is one atomic rename. The
	// pool scan that follows re-reads the file, so the indexes describe the
	// bytes that landed even if the upload changed after placePackage hashed it.
	err = os.Rename(file, p.target)
	if err != nil {
		return fmt.Errorf("move: %w", err)
	}

	slog.InfoContext(ctx, "moved", "path", logPath(workdir, file), "target", logPath(workdir, p.target))

	return nil
}

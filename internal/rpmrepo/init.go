package rpmrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
)

var (
	ErrDebWorkdir = errors.New("workdir holds a deb repository")

	debMarkers = []string{"dists", "key.gpg"}
)

// makeArchDirs creates the missing public/<arch>/ directories that mark an rpm
// workdir. An existing one must be a real directory: a symlink would let the
// stale-directory removal reach outside the workdir.
func makeArchDirs(workdir string) error {
	for _, arch := range baseArches {
		dir := filepath.Join(workdir, "public", arch)

		info, err := os.Lstat(dir)

		switch {
		case err == nil && !info.IsDir():
			return fmt.Errorf("%s is not a directory", dir)
		case err == nil:
			continue
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("stat %s: %w", dir, err)
		}

		err = os.MkdirAll(dir, 0o755)
		if err != nil {
			return fmt.Errorf("create %s directory: %w", arch, err)
		}
	}

	return nil
}

func Init(ctx context.Context, workdir, name, email string) error {
	err := repofs.RefuseMarkers(workdir, "init", debMarkers, ErrDebWorkdir)
	if err != nil {
		return err
	}

	return repofs.InitKey(ctx, repofs.KeyInit{
		Workdir: workdir,
		Name:    name,
		Email:   email,
		Publish: func(ctx context.Context, public []byte) error {
			armored, err := pgpsign.ArmorPublicKey(public)
			if err != nil {
				return err
			}

			keyPath := filepath.Join(workdir, "public", "key.asc")

			err = repofs.WriteAtomic(keyPath, bytes.NewReader(armored), 0o644, nil)
			if err != nil {
				return err
			}

			slog.InfoContext(ctx, "created", "path", repofs.LogPath(workdir, keyPath))

			return makeArchDirs(workdir)
		},
	})
}

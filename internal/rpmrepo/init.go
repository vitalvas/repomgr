package rpmrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
		err := checkDirs(workdir, filepath.Join("public", arch))
		if err != nil {
			return err
		}

		err = os.MkdirAll(filepath.Join(workdir, "public", arch), 0o755)
		if err != nil {
			return fmt.Errorf("create %s directory: %w", arch, err)
		}
	}

	return nil
}

// checkDirs checks each existing directory below root, without following links.
func checkDirs(root, rel string) error {
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		root = filepath.Join(root, part)
		info, err := os.Lstat(root)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("stat %s: %w", root, err)
		case !info.IsDir():
			return fmt.Errorf("%s is not a directory", root)
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
			if err := makeArchDirs(workdir); err != nil {
				return err
			}

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

			return nil
		},
	})
}

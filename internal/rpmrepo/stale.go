package rpmrepo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/repofs"
)

const (
	releaseDepth   int = 0
	componentDepth int = 1
)

type sweepScope struct {
	workdir string
	keep    map[string]bool
}

// removeStale deletes release and component directories under each base
// architecture directory that have no repository in this build. keep holds
// the public/<arch>/<release> and public/<arch>/<release>/<component> paths.
func removeStale(ctx context.Context, workdir string, keep map[string]bool) error {
	scope := sweepScope{workdir: workdir, keep: keep}

	for _, arch := range baseArches {
		err := scope.sweep(ctx, filepath.Join(workdir, "public", arch), releaseDepth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s sweepScope) sweep(ctx context.Context, dir string, depth int) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		sub := filepath.Join(dir, e.Name())

		if !s.keep[sub] {
			err = os.RemoveAll(sub)
			if err != nil {
				return fmt.Errorf("remove %s: %w", sub, err)
			}

			slog.InfoContext(ctx, "removed stale", "path", repofs.LogPath(s.workdir, sub))

			continue
		}

		if depth == releaseDepth {
			err = s.sweep(ctx, sub, componentDepth)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

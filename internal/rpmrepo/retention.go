package rpmrepo

import (
	"cmp"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.vitalvas.com/repomgr/internal/repofs"
)

// keepPrevious is how many unreferenced files of each metadata type stay.
const keepPrevious int = 2

var metadataName = regexp.MustCompile(`^[0-9a-f]{64}-(primary|filelists|other)\.xml\.gz$`)

// pruneTarget is one repository directory and the repomd in effect for it.
type pruneTarget struct {
	workdir    string
	repoDir    string
	referenced repomd
}

// readRepomd parses the repomd.xml published in repoDir.
func readRepomd(repoDir string) (repomd, error) {
	file := filepath.Join(repoDir, "repodata", "repomd.xml")

	data, err := os.ReadFile(file)
	if err != nil {
		return repomd{}, fmt.Errorf("read %s: %w", file, err)
	}

	var md repomd

	err = xml.Unmarshal(data, &md)
	if err != nil {
		return repomd{}, fmt.Errorf("parse %s: %w", file, err)
	}

	return md, nil
}

type candidate struct {
	name  string
	mtime time.Time
}

// pruneRepodata keeps the files t.referenced points at plus the two newest
// unreferenced files of each metadata type, and removes the rest. Retention
// ranks files by mtime, so a referenced file older than the newest
// unreferenced one (content reverted to an earlier generation) is touched to
// rank first again. Referenced files are not touched otherwise, so mtime-based
// syncs skip them.
func pruneRepodata(ctx context.Context, t pruneTarget, now time.Time) error {
	dir := filepath.Join(t.repoDir, "repodata")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	referenced := make(map[string]bool, len(t.referenced.Data))
	refByType := make(map[string]string, len(t.referenced.Data))

	for _, d := range t.referenced.Data {
		name := path.Base(d.Location.Href)
		referenced[name] = true
		refByType[d.Type] = name
	}

	byType := make(map[string][]candidate)

	for _, e := range entries {
		match := metadataName.FindStringSubmatch(e.Name())
		if match == nil || !e.Type().IsRegular() || referenced[e.Name()] {
			continue
		}

		info, err := e.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", filepath.Join(dir, e.Name()), err)
		}

		byType[match[1]] = append(byType[match[1]], candidate{name: e.Name(), mtime: info.ModTime()})
	}

	for _, typ := range []string{"primary", "filelists", "other"} {
		files := byType[typ]

		slices.SortFunc(files, func(a, b candidate) int {
			return cmp.Or(b.mtime.Compare(a.mtime), strings.Compare(a.name, b.name))
		})

		err = touchReferenced(filepath.Join(dir, refByType[typ]), files, now)
		if err != nil {
			return err
		}

		for _, c := range files[min(len(files), keepPrevious):] {
			file := filepath.Join(dir, c.name)

			err = os.Remove(file)
			if err != nil {
				return fmt.Errorf("remove %s: %w", file, err)
			}

			slog.InfoContext(ctx, "removed", "path", repofs.LogPath(t.workdir, file))
		}
	}

	return nil
}

// touchReferenced sets the mtime of file to now when it is older than the
// newest of files (sorted newest first).
func touchReferenced(file string, files []candidate, now time.Time) error {
	if len(files) == 0 {
		return nil
	}

	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("stat %s: %w", file, err)
	}

	if !files[0].mtime.After(info.ModTime()) {
		return nil
	}

	err = os.Chtimes(file, now, now)
	if err != nil {
		return fmt.Errorf("touch %s: %w", file, err)
	}

	return nil
}

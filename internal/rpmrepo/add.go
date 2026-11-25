package rpmrepo

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.vitalvas.com/repomgr/internal/repofs"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

const minRelease int = 8

var releaseRe = regexp.MustCompile(`^[1-9][0-9]*$`)

type AddResult struct {
	Path  string
	Added bool
}

func checkRelease(release string) error {
	n, err := strconv.Atoi(release)
	if !releaseRe.MatchString(release) || err != nil || n < minRelease {
		return fmt.Errorf("%w: release %q", repofs.ErrInvalidName, release)
	}

	return nil
}

func poolPath(release, component string, pkg rpmfile.Package) string {
	source := pkg.SourceName()
	lower := strings.ToLower(source)

	prefix := lower[:1]
	if strings.HasPrefix(lower, "lib") && len(lower) > 3 {
		prefix = lower[:4]
	}

	return path.Join("pool", release, component, prefix, source, pkg.Arch, pkg.FileName())
}

func Add(workdir, release, component, rpmPath string) (AddResult, error) {
	err := repofs.CheckInitialized(workdir, "add")
	if err != nil {
		return AddResult{}, err
	}

	err = repofs.RefuseMarkers(workdir, "add", debMarkers, ErrDebWorkdir)
	if err != nil {
		return AddResult{}, err
	}

	err = checkRelease(release)
	if err != nil {
		return AddResult{}, err
	}

	err = repofs.CheckName("component", component)
	if err != nil {
		return AddResult{}, err
	}

	f, err := os.Open(rpmPath)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", rpmPath, err)
	}
	defer f.Close()

	pkg, err := rpmfile.Parse(f)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", rpmPath, err)
	}

	err = checkText(pkg)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", rpmPath, err)
	}

	rel := poolPath(release, component, pkg)
	dst := filepath.Join("public", filepath.FromSlash(rel))
	target := filepath.Join(workdir, dst)

	err = checkDirs(workdir, filepath.Dir(dst))
	if err != nil {
		return AddResult{}, err
	}

	err = repofs.CheckPoolConflicts(filepath.Join(workdir, "public", "pool"), pkg.FileName(), pkg.SHA256, "")
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", rpmPath, err)
	}

	existing, _, err := repofs.FileSHA256(target)
	if err == nil {
		if existing != pkg.SHA256 {
			return AddResult{}, fmt.Errorf("add %s: %w", target, repofs.ErrConflict)
		}

		return AddResult{Path: rel}, saveCacheEntry(workdir, rel, pkg)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return AddResult{}, fmt.Errorf("hash %s: %w", target, err)
	}

	err = repofs.CopyVerified(rpmPath, target, pkg.SHA256)
	if err != nil {
		return AddResult{}, err
	}

	return AddResult{Path: rel, Added: true}, saveCacheEntry(workdir, rel, pkg)
}

// saveCacheEntry records the pool file at rel, which holds pkg, in the cache.
func saveCacheEntry(workdir, rel string, pkg rpmfile.Package) error {
	target := filepath.Join(workdir, "public", filepath.FromSlash(rel))

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %s: %w", target, err)
	}

	cache, err := repofs.LoadCache[cacheEntry](workdir)
	if err != nil {
		return err
	}

	entry, err := newCacheEntry(info, pkg)
	if err != nil {
		return fmt.Errorf("cache %s: %w", rel, err)
	}

	if cache[rel].equal(entry) {
		return nil
	}

	cache[rel] = entry

	return repofs.SaveCache(workdir, cache)
}

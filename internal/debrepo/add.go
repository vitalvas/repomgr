package debrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"go.vitalvas.com/repomgr/internal/debfile"
)

var (
	ErrNotInitialized = errors.New("workdir not initialized")
	ErrInvalidName    = errors.New("invalid name")
	ErrConflict       = errors.New("conflicting package already exists")
	ErrMisplaced      = errors.New("package not at its pool path")

	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	sourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
)

type AddResult struct {
	Path  string
	Added bool
}

func Add(_ context.Context, workdir, suite, component, debPath string) (AddResult, error) {
	keyPath := filepath.Join(workdir, "config", "signing.asc")

	_, err := os.Stat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return AddResult{}, fmt.Errorf("add to %s: %w", workdir, ErrNotInitialized)
	}

	if err != nil {
		return AddResult{}, fmt.Errorf("stat %s: %w", keyPath, err)
	}

	p, err := placePackage(workdir, suite, component, debPath)
	if err != nil {
		return AddResult{}, err
	}

	if p.exists {
		return AddResult{Path: p.rel, Added: false}, nil
	}

	cache, err := loadCache(workdir)
	if err != nil {
		return AddResult{}, err
	}

	err = copyVerified(debPath, p.target, p.pkg.SHA256)
	if err != nil {
		return AddResult{}, err
	}

	err = cacheAddedPackage(workdir, p.target, p.rel, p.pkg, cache)
	if err != nil {
		if rollbackErr := os.Remove(p.target); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("remove %s after cache failure: %w", p.target, rollbackErr))
		}

		return AddResult{}, err
	}

	return AddResult{Path: p.rel, Added: true}, nil
}

type placement struct {
	rel    string
	target string
	pkg    debfile.Package
	exists bool
}

// placePackage validates and parses debPath and finds its pool path. exists
// reports that the pool already holds the same bytes there.
func placePackage(workdir, suite, component, debPath string) (placement, error) {
	err := checkNames(suite, component)
	if err != nil {
		return placement{}, err
	}

	pkg, err := debfile.Open(debPath)
	if err != nil {
		return placement{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	rel, err := poolPath(suite, component, pkg.Control.Fields)
	if err != nil {
		return placement{}, err
	}

	poolDir := filepath.Join(workdir, "public", "pool")
	err = checkPoolConflicts(poolDir, path.Base(rel), pkg.SHA256)
	if err != nil {
		return placement{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	p := placement{rel: rel, target: filepath.Join(workdir, "public", filepath.FromSlash(rel)), pkg: pkg}

	existing, err := fileSHA256(p.target)
	if err == nil {
		if existing != pkg.SHA256 {
			return placement{}, fmt.Errorf("add %s: %w", p.target, ErrConflict)
		}

		p.exists = true

		return p, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return placement{}, fmt.Errorf("hash %s: %w", p.target, err)
	}

	return p, nil
}

func checkPoolConflicts(poolDir, filename, wantSHA256 string) error {
	return walkPool(poolDir, func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() != filename {
			return err
		}

		if !entry.Type().IsRegular() {
			return fmt.Errorf("package %s is not a regular file", file)
		}

		sum, err := fileSHA256(file)
		if err != nil {
			return fmt.Errorf("hash %s: %w", file, err)
		}

		if sum != wantSHA256 {
			return fmt.Errorf("different content at %s: %w", file, ErrConflict)
		}

		return nil
	})
}

func cacheAddedPackage(workdir, target, rel string, pkg debfile.Package, cache map[string]cacheEntry) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %s: %w", target, err)
	}

	cache[rel] = newCacheEntry(info, pkg)

	return saveCache(workdir, cache)
}

func checkNames(suite, component string) error {
	if !nameRe.MatchString(suite) {
		return fmt.Errorf("%w: suite %q", ErrInvalidName, suite)
	}

	if !nameRe.MatchString(component) {
		return fmt.Errorf("%w: component %q", ErrInvalidName, component)
	}

	return nil
}

func poolPath(suite, component string, fields map[string]string) (string, error) {
	err := checkNames(suite, component)
	if err != nil {
		return "", err
	}

	name := fields["Package"]
	if source, ok := fields["Source"]; ok {
		name, _, _ = strings.Cut(source, "(")
		name = strings.TrimSpace(name)
	}

	if !sourceRe.MatchString(name) {
		return "", fmt.Errorf("%w: Source %q", debfile.ErrInvalidField, name)
	}

	prefix := name[:1]
	if strings.HasPrefix(name, "lib") && len(name) > 3 {
		prefix = name[:4]
	}

	version := fields["Version"]

	_, afterEpoch, hasEpoch := strings.Cut(version, ":")
	if hasEpoch {
		version = afterEpoch
	}

	arch := fields["Architecture"]
	fileName := fmt.Sprintf("%s_%s_%s.deb", fields["Package"], version, arch)

	return path.Join("pool", suite, component, prefix, name, arch, fileName), nil
}

func fileSHA256(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()

	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyVerified(src, target, wantSHA256 string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	h := sha256.New()

	return writeAtomic(target, io.TeeReader(in, h), 0o644, func() error {
		if hex.EncodeToString(h.Sum(nil)) != wantSHA256 {
			return fmt.Errorf("%s changed during the add", src)
		}

		return nil
	})
}

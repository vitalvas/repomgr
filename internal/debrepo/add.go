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
	configPath := filepath.Join(workdir, "config", "repo.yaml")

	_, err := os.Stat(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return AddResult{}, fmt.Errorf("add to %s: %w", workdir, ErrNotInitialized)
	}

	if err != nil {
		return AddResult{}, fmt.Errorf("stat %s: %w", configPath, err)
	}

	err = checkNames(suite, component)
	if err != nil {
		return AddResult{}, err
	}

	pkg, err := debfile.Open(debPath)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	rel, err := poolPath(suite, component, pkg.Control.Fields)
	if err != nil {
		return AddResult{}, err
	}

	poolDir := filepath.Join(workdir, "public", "pool")
	err = checkPoolConflicts(poolDir, path.Base(rel), pkg.SHA256)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	target := filepath.Join(workdir, "public", filepath.FromSlash(rel))

	existing, err := fileSHA256(target)
	if err == nil {
		if existing != pkg.SHA256 {
			return AddResult{}, fmt.Errorf("add %s: %w", target, ErrConflict)
		}

		return AddResult{Path: rel, Added: false}, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return AddResult{}, fmt.Errorf("hash %s: %w", target, err)
	}

	cache, err := loadCache(workdir)
	if err != nil {
		return AddResult{}, err
	}

	err = copyVerified(debPath, target, pkg.SHA256)
	if err != nil {
		return AddResult{}, err
	}

	err = cacheAddedPackage(workdir, target, rel, pkg, cache)
	if err != nil {
		if rollbackErr := os.Remove(target); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("remove %s after cache failure: %w", target, rollbackErr))
		}

		return AddResult{}, err
	}

	return AddResult{Path: rel, Added: true}, nil
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

	fileName := fmt.Sprintf("%s_%s_%s.deb", fields["Package"], version, fields["Architecture"])

	return path.Join("pool", suite, component, prefix, name, fileName), nil
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

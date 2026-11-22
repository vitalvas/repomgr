package debrepo

import (
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

// checkInitialized returns ErrNotInitialized when workdir has no signing key; op names the caller in the message.
func checkInitialized(workdir, op string) error {
	keyPath := filepath.Join(workdir, "config", "signing.asc")

	_, err := os.Stat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s to %s: %w", op, workdir, ErrNotInitialized)
	}

	if err != nil {
		return fmt.Errorf("stat %s: %w", keyPath, err)
	}

	return nil
}

func Add(workdir, suite, component, debPath string, replace bool) (AddResult, error) {
	err := checkInitialized(workdir, "add")
	if err != nil {
		return AddResult{}, err
	}

	p, err := placePackage(workdir, suite, component, debPath, replace)
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
func placePackage(workdir, suite, component, debPath string, replace bool) (placement, error) {
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

	p := placement{rel: rel, target: filepath.Join(workdir, "public", filepath.FromSlash(rel)), pkg: pkg}

	// With replace, the target itself may hold different bytes; copies elsewhere still conflict.
	skip := ""
	if replace {
		skip = p.target
	}

	poolDir := filepath.Join(workdir, "public", "pool")

	err = checkPoolConflicts(poolDir, path.Base(rel), pkg.SHA256, skip)
	if err != nil {
		return placement{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	existing, err := fileSHA256(p.target)
	if err == nil {
		if existing != pkg.SHA256 && !replace {
			return placement{}, fmt.Errorf("add %s: %w", p.target, ErrConflict)
		}

		p.exists = existing == pkg.SHA256

		return p, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return placement{}, fmt.Errorf("hash %s: %w", p.target, err)
	}

	return p, nil
}

// checkPoolConflicts fails on a same-named file with other bytes; skip, when
// not empty, is a path that is exempt from the check.
func checkPoolConflicts(poolDir, filename, wantSHA256, skip string) error {
	return walkPool(poolDir, func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() != filename || file == skip {
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

	name := fields["package"]
	if source, ok := fields["source"]; ok {
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

	version := fields["version"]

	_, afterEpoch, hasEpoch := strings.Cut(version, ":")
	if hasEpoch {
		version = afterEpoch
	}

	arch := fields["architecture"]
	fileName := fmt.Sprintf("%s_%s_%s.deb", fields["package"], version, arch)

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

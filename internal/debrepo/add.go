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
	Path     string
	Added    bool
	Replaced bool
}

type placementOptions struct {
	replace  bool
	expected map[string]string
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

	return addPackage(workdir, suite, component, debPath, placementOptions{replace: replace})
}

func addPackage(workdir, suite, component, debPath string, opts placementOptions) (AddResult, error) {
	p, err := placePackage(workdir, suite, component, debPath, opts)
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

	var backup string

	if p.replaces {
		dir, err := os.MkdirTemp(filepath.Dir(p.target), ".replace-*")
		if err != nil {
			return AddResult{}, fmt.Errorf("create replacement backup directory: %w", err)
		}
		defer os.Remove(dir)

		backup = filepath.Join(dir, "original")
		if err := os.Link(p.target, backup); err != nil {
			return AddResult{}, fmt.Errorf("back up %s: %w", p.target, err)
		}
		defer func() {
			if backup != "" {
				os.Remove(backup)
			}
		}()
	}

	err = copyVerified(debPath, p.target, p.pkg.SHA256)
	if err != nil {
		return AddResult{}, err
	}

	err = cacheAddedPackage(workdir, p.target, p.rel, p.pkg, cache)
	if err != nil {
		if p.replaces {
			if rollbackErr := os.Rename(backup, p.target); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("restore %s from %s after cache failure: %w", p.target, backup, rollbackErr))
				backup = ""
			}
		} else if rollbackErr := os.Remove(p.target); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("remove %s after cache failure: %w", p.target, rollbackErr))
		}

		return AddResult{}, err
	}

	return AddResult{Path: p.rel, Added: true, Replaced: p.replaces}, nil
}

type placement struct {
	rel      string
	target   string
	pkg      debfile.Package
	exists   bool
	replaces bool
}

// placePackage validates and parses debPath and finds its pool path. exists
// reports that the pool already holds the same bytes there.
func placePackage(workdir, suite, component, debPath string, opts placementOptions) (placement, error) {
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

	if opts.expected != nil {
		if !strings.EqualFold(pkg.SHA256, opts.expected["sha256"]) {
			return placement{}, fmt.Errorf("%s changed after download", debPath)
		}
		if err := checkIndexControl(pkg.Control.Fields, opts.expected); err != nil {
			return placement{}, fmt.Errorf("%s: %w", debPath, err)
		}
	}

	p := placement{rel: rel, target: filepath.Join(workdir, "public", filepath.FromSlash(rel)), pkg: pkg}

	// With replace, the target itself may hold different bytes; copies elsewhere still conflict.
	skip := ""
	if opts.replace {
		skip = p.target
	}

	poolDir := filepath.Join(workdir, "public", "pool")

	err = checkPoolConflicts(poolDir, path.Base(rel), pkg.SHA256, skip)
	if err != nil {
		return placement{}, fmt.Errorf("add %s: %w", debPath, err)
	}

	existing, _, err := fileSHA256(p.target)
	if err == nil {
		if existing != pkg.SHA256 && !opts.replace {
			return placement{}, fmt.Errorf("add %s: %w", p.target, ErrConflict)
		}

		p.exists = existing == pkg.SHA256
		p.replaces = !p.exists

		return p, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return placement{}, fmt.Errorf("hash %s: %w", p.target, err)
	}

	return p, nil
}

func checkIndexControl(actual, expected map[string]string) error {
	for _, field := range []string{"package", "version", "architecture"} {
		if actual[field] != expected[field] {
			return fmt.Errorf("%s differs from index", field)
		}
	}

	if sourcePackage(actual) != sourcePackage(expected) {
		return errors.New("source package differs from index")
	}

	return nil
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

		sum, _, err := fileSHA256(file)
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

	name := sourcePackage(fields)
	if !sourceRe.MatchString(name) {
		return "", fmt.Errorf("%w: Source %q", debfile.ErrInvalidField, name)
	}

	if err := (debfile.Control{Fields: fields}).Validate(); err != nil {
		return "", err
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

func sourcePackage(fields map[string]string) string {
	if source, ok := fields["source"]; ok {
		name, _, _ := strings.Cut(source, "(")
		return strings.TrimSpace(name)
	}

	return fields["package"]
}

func fileSHA256(file string) (string, int64, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return "", 0, err
	}

	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%s is not a regular file", file)
	}

	f, err := os.Open(file)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()

	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
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

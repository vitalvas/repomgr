package repofs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

var (
	ErrNotInitialized = errors.New("workdir not initialized")
	ErrInvalidName    = errors.New("invalid name")
	ErrConflict       = errors.New("conflicting package already exists")

	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// CheckInitialized returns ErrNotInitialized when workdir has no signing key; op names the caller in the message.
func CheckInitialized(workdir, op string) error {
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

func CheckName(kind, value string) error {
	if !nameRe.MatchString(value) {
		return fmt.Errorf("%w: %s %q", ErrInvalidName, kind, value)
	}

	return nil
}

func WalkPool(pool string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(pool)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("stat %s: %w", pool, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("pool %s is not a directory", pool)
	}

	return filepath.WalkDir(pool, visit)
}

func FileSHA256(file string) (string, int64, error) {
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

// CheckPoolConflicts fails on a same-named file with other bytes; skip, when
// not empty, is a path that is exempt from the check.
func CheckPoolConflicts(poolDir, filename, wantSHA256, skip string) error {
	return WalkPool(poolDir, func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() != filename || file == skip {
			return err
		}

		if !entry.Type().IsRegular() {
			return fmt.Errorf("package %s is not a regular file", file)
		}

		sum, _, err := FileSHA256(file)
		if err != nil {
			return fmt.Errorf("hash %s: %w", file, err)
		}

		if sum != wantSHA256 {
			return fmt.Errorf("different content at %s: %w", file, ErrConflict)
		}

		return nil
	})
}

func CopyVerified(src, target, wantSHA256 string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	h := sha256.New()

	return WriteAtomic(target, io.TeeReader(in, h), 0o644, func() error {
		if hex.EncodeToString(h.Sum(nil)) != wantSHA256 {
			return fmt.Errorf("%s changed during the add", src)
		}

		return nil
	})
}

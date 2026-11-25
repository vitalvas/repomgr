package repofs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
)

var ErrAlreadyInitialized = errors.New("workdir already initialized")

type KeyInit struct {
	Workdir string
	Name    string
	Email   string
	// Publish receives the binary public key.
	Publish func(ctx context.Context, public []byte) error
}

// InitKey generates the signing key and the workdir directories. signing.asc
// is written last: its presence marks the workdir as initialized.
func InitKey(ctx context.Context, in KeyInit) error {
	workdir := in.Workdir
	keyPath := filepath.Join(workdir, "config", "signing.asc")

	_, err := os.Lstat(keyPath)
	if err == nil {
		return fmt.Errorf("init %s: %w", keyPath, ErrAlreadyInitialized)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", keyPath, err)
	}

	key, err := pgpsign.GenerateKey(in.Name, in.Email)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}

	for _, dirName := range []string{"config", "cache", "public"} {
		dir := filepath.Join(workdir, dirName)

		err = os.MkdirAll(dir, 0o755)
		if err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	err = in.Publish(ctx, key.Public)
	if err != nil {
		return err
	}

	err = WriteAtomic(keyPath, bytes.NewReader(key.Private), 0o600, nil)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "created", "path", LogPath(workdir, keyPath))

	return nil
}

func LogPath(workdir, file string) string {
	rel, err := filepath.Rel(workdir, file)
	if err != nil {
		return filepath.ToSlash(file)
	}

	return filepath.ToSlash(rel)
}

// WriteAtomic writes r to target through a temp file and a rename. A non-nil
// verify runs after the data is written and before the rename; a failure
// removes the temp file and leaves target untouched.
func WriteAtomic(target string, r io.Reader, mode fs.FileMode, verify func() error) error {
	dir := filepath.Dir(target)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".build-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}

	_, err = io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())

		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}

	err = tmp.Close()

	if err == nil && verify != nil {
		err = verify()
	}

	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}

	if err == nil {
		err = os.Rename(tmp.Name(), target)
	}

	if err != nil {
		os.Remove(tmp.Name())

		return fmt.Errorf("write %s: %w", target, err)
	}

	return nil
}

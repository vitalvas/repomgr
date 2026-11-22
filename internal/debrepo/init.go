package debrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
)

var ErrAlreadyInitialized = errors.New("workdir already initialized")

func Init(ctx context.Context, workdir, name, email string) error {
	keyPath := filepath.Join(workdir, "config", "signing.asc")

	_, err := os.Lstat(keyPath)
	if err == nil {
		return fmt.Errorf("init %s: %w", keyPath, ErrAlreadyInitialized)
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", keyPath, err)
	}

	key, err := pgpsign.GenerateKey(name, email)
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

	publicFiles, err := publicKeyFiles(workdir, key.Public)
	if err != nil {
		return err
	}

	err = publishFiles(ctx, workdir, publicFiles, "created")
	if err != nil {
		return err
	}

	// signing.asc is written last: its presence marks the workdir as initialized.
	err = writeAtomic(keyPath, bytes.NewReader(key.Private), 0o600, nil)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "created", "path", logPath(workdir, keyPath))

	return nil
}

// publicKeyFiles returns public/key.gpg for keyring files and public/key.asc
// for keys embedded in Signed-By.
func publicKeyFiles(workdir string, public []byte) ([]outputFile, error) {
	armored, err := pgpsign.ArmorPublicKey(public)
	if err != nil {
		return nil, err
	}

	return []outputFile{
		{path: filepath.Join(workdir, "public", "key.gpg"), data: public},
		{path: filepath.Join(workdir, "public", "key.asc"), data: armored},
	}, nil
}

package debrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"go.vitalvas.com/repomgr/internal/pgpsign"
)

const repoConfigContent string = `origin: ""
label: ""
description: ""
`

var ErrAlreadyInitialized = errors.New("workdir already initialized")

func Init(ctx context.Context, workdir, name, email string) error {
	configPath := filepath.Join(workdir, "config", "repo.yaml")
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

	configInfo, err := os.Stat(configPath)

	switch {
	case errors.Is(err, os.ErrNotExist):
		err = writeAtomic(configPath, strings.NewReader(repoConfigContent), 0o644, nil)
		if err != nil {
			return err
		}

		slog.InfoContext(ctx, "created", "path", logPath(workdir, configPath))
	case err != nil:
		return fmt.Errorf("stat %s: %w", configPath, err)
	case !configInfo.Mode().IsRegular():
		return fmt.Errorf("config %s is not a regular file", configPath)
	default:
		slog.InfoContext(ctx, "kept", "path", logPath(workdir, configPath))
	}

	publicPath := filepath.Join(workdir, "public", "key.gpg")

	err = writeAtomic(publicPath, bytes.NewReader(key.Public), 0o644, nil)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "created", "path", logPath(workdir, publicPath))

	// signing.asc is written last: its presence marks the workdir as initialized.
	err = writeAtomic(keyPath, bytes.NewReader(key.Private), 0o600, nil)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "created", "path", logPath(workdir, keyPath))

	return nil
}

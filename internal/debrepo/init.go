package debrepo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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

	_, err := os.Stat(keyPath)
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

	_, err = os.Stat(configPath)

	switch {
	case errors.Is(err, os.ErrNotExist):
		err = os.WriteFile(configPath, []byte(repoConfigContent), 0o644)
		if err != nil {
			return fmt.Errorf("write %s: %w", configPath, err)
		}

		slog.InfoContext(ctx, "created", "path", logPath(workdir, configPath))
	case err != nil:
		return fmt.Errorf("stat %s: %w", configPath, err)
	default:
		slog.InfoContext(ctx, "kept", "path", logPath(workdir, configPath))
	}

	publicPath := filepath.Join(workdir, "public", "key.gpg")

	err = os.WriteFile(publicPath, key.Public, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", publicPath, err)
	}

	slog.InfoContext(ctx, "created", "path", logPath(workdir, publicPath))

	// signing.asc is written last: its presence marks the workdir as initialized.
	err = os.WriteFile(keyPath, key.Private, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}

	slog.InfoContext(ctx, "created", "path", logPath(workdir, keyPath))

	return nil
}

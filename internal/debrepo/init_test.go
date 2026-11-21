package debrepo

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wantConfig string = "origin: \"\"\nlabel: \"\"\ndescription: \"\"\n"

func TestInit(t *testing.T) {
	t.Run("creates layout and keys", func(t *testing.T) {
		workdir := filepath.Join(t.TempDir(), "wd")
		logs := captureLogs(t)

		require.NoError(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))

		out := logs.String()
		assert.Contains(t, out, "msg=created path=config/repo.yaml\n")
		assert.Contains(t, out, "msg=created path=public/key.gpg\n")
		assert.Contains(t, out, "msg=created path=config/signing.asc\n")
		assert.NotContains(t, out, "PGP")

		for _, name := range []string{"config", "cache", "public"} {
			info, err := os.Stat(filepath.Join(workdir, name))
			require.NoError(t, err)
			assert.True(t, info.IsDir())
		}

		data, err := os.ReadFile(filepath.Join(workdir, "config", "repo.yaml"))
		require.NoError(t, err)
		assert.Equal(t, wantConfig, string(data))

		keyPath := filepath.Join(workdir, "config", "signing.asc")
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		private, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Contains(t, string(private), "-----BEGIN PGP PRIVATE KEY BLOCK-----")

		public, err := os.ReadFile(filepath.Join(workdir, "public", "key.gpg"))
		require.NoError(t, err)
		require.NotEmpty(t, public)
		assert.Equal(t, byte(0xc6), public[0])

		pubInfo, err := os.Stat(filepath.Join(workdir, "public", "key.gpg"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), pubInfo.Mode().Perm())
	})

	t.Run("second run fails and keeps key", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))

		keyPath := filepath.Join(workdir, "config", "signing.asc")
		before, err := os.ReadFile(keyPath)
		require.NoError(t, err)

		err = Init(t.Context(), workdir, "Other", "other@example.com")
		require.ErrorIs(t, err, ErrAlreadyInitialized)

		after, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})

	t.Run("existing repo.yaml is kept", func(t *testing.T) {
		workdir := t.TempDir()
		configPath := filepath.Join(workdir, "config", "repo.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(configPath), 0o755))
		require.NoError(t, os.WriteFile(configPath, []byte("origin: x\n"), 0o644))

		logs := captureLogs(t)

		require.NoError(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))

		out := logs.String()
		assert.Contains(t, out, "msg=kept path=config/repo.yaml\n")
		assert.NotContains(t, out, "msg=created path=config/repo.yaml")

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Equal(t, "origin: x\n", string(data))
		assert.FileExists(t, filepath.Join(workdir, "config", "signing.asc"))
	})

	t.Run("key generation failure leaves workdir untouched", func(t *testing.T) {
		workdir := filepath.Join(t.TempDir(), "wd")

		require.Error(t, Init(t.Context(), workdir, "Bad <Name>", "repo@example.com"))

		assert.NoDirExists(t, workdir)
	})

	t.Run("workdir is a file", func(t *testing.T) {
		workdir := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(workdir, nil, 0o644))

		assert.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
	})

	t.Run("config dir blocked by file", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "config"), nil, 0o644))

		assert.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
	})

	t.Run("public key path is a directory", func(t *testing.T) {
		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "public", "key.gpg"), 0o755))

		assert.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
	})

	t.Run("stat fails on unreadable config dir", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks do not apply to root")
		}

		workdir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workdir, "config"), 0o755))
		require.NoError(t, os.Chmod(filepath.Join(workdir, "config"), 0o000))
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(workdir, "config"), 0o755) })

		err := Init(t.Context(), workdir, "Repo", "repo@example.com")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrAlreadyInitialized)
	})

	t.Run("write fails in read-only config", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks do not apply to root")
		}

		workdir := t.TempDir()
		configDir := filepath.Join(workdir, "config")
		require.NoError(t, os.MkdirAll(configDir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(configDir, 0o755) })

		assert.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
	})

	t.Run("public key write failure can be rerun", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks do not apply to root")
		}

		workdir := t.TempDir()
		publicDir := filepath.Join(workdir, "public")
		require.NoError(t, os.MkdirAll(publicDir, 0o755))
		require.NoError(t, os.Chmod(publicDir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(publicDir, 0o755) })

		require.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
		assert.NoFileExists(t, filepath.Join(workdir, "config", "signing.asc"))

		require.NoError(t, os.Chmod(publicDir, 0o755))
		require.NoError(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
		assert.FileExists(t, filepath.Join(workdir, "config", "signing.asc"))
	})

	t.Run("signing key write fails in read-only config", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks do not apply to root")
		}

		workdir := t.TempDir()
		configDir := filepath.Join(workdir, "config")
		require.NoError(t, os.MkdirAll(configDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(configDir, "repo.yaml"), nil, 0o644))
		require.NoError(t, os.Chmod(configDir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(configDir, 0o755) })

		assert.Error(t, Init(t.Context(), workdir, "Repo", "repo@example.com"))
	})
}

func BenchmarkInit(b *testing.B) {
	root := b.TempDir()

	for i := 0; b.Loop(); i++ {
		err := Init(b.Context(), filepath.Join(root, strconv.Itoa(i)), "Repo", "repo@example.com")
		if err != nil {
			b.Fatal(err)
		}
	}
}

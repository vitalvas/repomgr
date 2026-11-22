package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/debtest"
)

func run(t *testing.T, args ...string) error {
	t.Helper()

	p, err := New("")
	require.NoError(t, err)

	p.SetArgs(args)
	p.SetOutput(&bytes.Buffer{})

	return p.Execute(context.Background())
}

func TestVersion(t *testing.T) {
	t.Run("prints version when set", func(t *testing.T) {
		p, err := New("1.2.3")
		require.NoError(t, err)

		var out bytes.Buffer

		p.SetArgs([]string{"--version"})
		p.SetOutput(&out)

		require.NoError(t, p.Execute(t.Context()))
		assert.Equal(t, "repomgr version 1.2.3\n", out.String())
	})

	t.Run("no version flag when unset", func(t *testing.T) {
		assert.Error(t, run(t, "--version"))
	})
}

func TestDebAdd(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, run(t, "deb", "--workdir", dir, "init", "--name", "Repo", "--email", "repo@example.com"))

	data, err := debtest.Build("Package: foo\nVersion: 1.0\nArchitecture: amd64\n")
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "test.deb")
	require.NoError(t, os.WriteFile(file, data, 0o600))

	base := []string{"deb", "--workdir", dir, "add"}

	t.Run("adds then reports unchanged", func(t *testing.T) {
		args := append(slices.Clone(base), "--suite", "stable", "--component", "main", file)

		require.NoError(t, run(t, args...))
		assert.FileExists(t, filepath.Join(dir, "public", "pool", "stable", "main", "f", "foo", "foo_1.0_amd64.deb"))
		require.NoError(t, run(t, args...))
	})

	failures := map[string][]string{
		"missing suite":     {"--component", "main", file},
		"missing component": {"--suite", "stable", file},
		"no file":           {"--suite", "stable", "--component", "main"},
		"two files":         {"--suite", "stable", "--component", "main", file, file},
		"invalid suite":     {"--suite", "Bad", "--component", "main", file},
	}

	for name, args := range failures {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, run(t, append(slices.Clone(base), args...)...))
		})
	}
}

func TestDebBuild(t *testing.T) {
	t.Run("init add build", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, run(t, "deb", "--workdir", dir, "init", "--name", "Repo", "--email", "repo@example.com"))

		data, err := debtest.Build("Package: foo\nVersion: 1.0\nArchitecture: amd64\n")
		require.NoError(t, err)

		file := filepath.Join(t.TempDir(), "test.deb")
		require.NoError(t, os.WriteFile(file, data, 0o600))
		require.NoError(t, run(t, "deb", "--workdir", dir, "add", "--suite", "stable", "--component", "main", file))
		require.NoError(t, run(t, "deb", "--workdir", dir, "build"))

		assert.FileExists(t, filepath.Join(dir, "public", "dists", "stable", "main", "binary-amd64", "Packages"))
		assert.FileExists(t, filepath.Join(dir, "public", "dists", "stable", "Release"))
	})

	t.Run("uninitialized fails", func(t *testing.T) {
		assert.Error(t, run(t, "deb", "--workdir", t.TempDir(), "build"))
	})
}

func TestUnexpectedPositionals(t *testing.T) {
	dir := t.TempDir()
	err := run(t, "deb", "--workdir", dir, "init", "--name", "Repo", "--email", "repo@example.com", "extra")
	require.ErrorContains(t, err, "init takes no positional arguments")
	assert.NoDirExists(t, filepath.Join(dir, "config"))

	err = run(t, "deb", "--workdir", dir, "build", "extra")
	require.ErrorContains(t, err, "build takes no positional arguments")
}

func TestEmptyRequiredOptions(t *testing.T) {
	dir := t.TempDir()
	err := run(t, "deb", "--workdir=", "build")
	require.ErrorContains(t, err, "--workdir")

	err = run(t, "deb", "--workdir", dir, "init", "--name=", "--email", "repo@example.com")
	require.ErrorContains(t, err, "--name")
	assert.NoDirExists(t, filepath.Join(dir, "config"))
}

func TestDebInit(t *testing.T) {
	t.Run("creates layout and keys", func(t *testing.T) {
		dir := t.TempDir()

		require.NoError(t, run(t, "deb", "--workdir", dir, "init", "--name", "Repo", "--email", "repo@example.com"))

		for _, name := range []string{"config", "cache", "public"} {
			assert.DirExists(t, filepath.Join(dir, name))
		}

		data, err := os.ReadFile(filepath.Join(dir, "config", "repo.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "origin: \"\"\nlabel: \"\"\ndescription: \"\"\n", string(data))

		keyPath := filepath.Join(dir, "config", "signing.asc")
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		private, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		assert.Contains(t, string(private), "-----BEGIN PGP PRIVATE KEY BLOCK-----")

		public, err := os.ReadFile(filepath.Join(dir, "public", "key.gpg"))
		require.NoError(t, err)
		require.NotEmpty(t, public)
		assert.Equal(t, byte(0xc6), public[0])
	})

	t.Run("second run fails", func(t *testing.T) {
		dir := t.TempDir()
		args := []string{"deb", "--workdir", dir, "init", "--name", "Repo", "--email", "repo@example.com"}
		require.NoError(t, run(t, args...))

		assert.Error(t, run(t, args...))
	})

	t.Run("missing workdir fails", func(t *testing.T) {
		assert.Error(t, run(t, "deb", "init", "--name", "Repo", "--email", "repo@example.com"))
	})

	t.Run("missing name fails", func(t *testing.T) {
		assert.Error(t, run(t, "deb", "--workdir", t.TempDir(), "init", "--email", "repo@example.com"))
	})

	for name, args := range map[string][]string{
		"without email":     {"--name", "Repo"},
		"empty email value": {"--name", "Repo", "--email="},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()

			require.NoError(t, run(t, append([]string{"deb", "--workdir", dir, "init"}, args...)...))
			assert.FileExists(t, filepath.Join(dir, "config", "signing.asc"))
			assert.FileExists(t, filepath.Join(dir, "public", "key.gpg"))
		})
	}

	t.Run("invalid name creates no key", func(t *testing.T) {
		dir := t.TempDir()

		require.Error(t, run(t, "deb", "--workdir", dir, "init", "--name", "Bad <Name>", "--email", "repo@example.com"))

		assert.NoFileExists(t, filepath.Join(dir, "config", "signing.asc"))
	})
}

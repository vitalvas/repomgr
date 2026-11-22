package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/gokit/xflags"
	"go.vitalvas.com/repomgr/internal/debrepo"
	"go.vitalvas.com/repomgr/internal/debtest"
	"go.vitalvas.com/repomgr/internal/pgpsign"
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
		assert.FileExists(t, filepath.Join(dir, "public", "pool", "stable", "main", "f", "foo", "amd64", "foo_1.0_amd64.deb"))
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

	t.Run("rejected upload logs built and fails", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, run(t, "deb", "--workdir", dir, "init", "--name", "Repo"))

		data, err := debtest.Build("Package: foo\nVersion: 1.0\nArchitecture: amd64\n")
		require.NoError(t, err)

		for name, content := range map[string][]byte{"foo.deb": data, "broken.deb": []byte("not a deb")} {
			file := filepath.Join(dir, "upload", "stable", "main", name)
			require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
			require.NoError(t, os.WriteFile(file, content, 0o600))
		}

		logs := captureLogs(t)

		err = run(t, "deb", "--workdir", dir, "build")
		require.ErrorIs(t, err, debrepo.ErrUploadRejected)
		assert.Contains(t, logs.String(), "msg=built suite=stable packages=1")
	})

	t.Run("uninitialized fails", func(t *testing.T) {
		assert.Error(t, run(t, "deb", "--workdir", t.TempDir(), "build"))
	})
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// fakeUpstream serves one package. With corrupt set, the served .deb bytes do
// not match the index SHA256. The counter holds the number of requests.
func fakeUpstream(t *testing.T, corrupt bool) (string, *atomic.Int32, []byte) {
	t.Helper()

	deb, err := debtest.Build("Package: foo\nVersion: 1.0\nArchitecture: amd64\n")
	require.NoError(t, err)

	index := []byte(fmt.Sprintf("Package: foo\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/foo.deb\nSize: %d\nSHA256: %s\n", len(deb), hexSum(deb)))
	release := fmt.Sprintf("Suite: stable\nArchitectures: amd64\nComponents: main\nSHA256:\n %s %d main/binary-amd64/Packages\n", hexSum(index), len(index))

	key, err := pgpsign.GenerateKey("Upstream", "up@example.com")
	require.NoError(t, err)

	signed, err := pgpsign.Sign(key.Private, []byte(release))
	require.NoError(t, err)

	served := slices.Clone(deb)
	if corrupt {
		served[len(served)-1] ^= 0xff
	}

	files := map[string][]byte{
		"dists/stable/InRelease":                  signed.Clear,
		"dists/stable/main/binary-amd64/Packages": index,
		"pool/foo.deb":                            served,
	}

	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)

		data, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	return srv.URL, &requests, key.Public
}

func TestDebMirror(t *testing.T) {
	upstream, _, _ := fakeUpstream(t, false)
	base := mirrorArgs(t, upstream)
	dir := base[2]

	t.Run("mirrors a package", func(t *testing.T) {
		logs := captureLogs(t)

		require.NoError(t, run(t, base...))
		assert.FileExists(t, filepath.Join(dir, "public", "pool", "mirror", "main", "f", "foo", "amd64", "foo_1.0_amd64.deb"))
		assert.Contains(t, logs.String(), "msg=mirrored")
		assert.Contains(t, logs.String(), "added=1 replaced=0 unchanged=0 failed=0")
	})

	t.Run("positional argument fails", func(t *testing.T) {
		require.ErrorContains(t, run(t, append(slices.Clone(base), "extra")...), "deb-mirror takes no positional arguments")
	})

	for _, flag := range []string{"workdir", "source-repo", "source-suite", "source-component", "target-suite", "target-component"} {
		long := fmt.Sprintf("--%s", flag)

		t.Run(fmt.Sprintf("missing %s", flag), func(t *testing.T) {
			args := []string{"deb-mirror"}

			for i := 1; i < len(base); i += 2 {
				if base[i] != long {
					args = append(args, base[i], base[i+1])
				}
			}

			require.ErrorContains(t, run(t, args...), flag)
		})

		t.Run(fmt.Sprintf("empty %s", flag), func(t *testing.T) {
			args := slices.Clone(base)

			for i := range args {
				if args[i] == long {
					args[i+1] = ""
				}
			}

			require.ErrorContains(t, run(t, args...), flag)
		})
	}
}

func mirrorArgs(t *testing.T, upstream string) []string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, run(t, "deb", "--workdir", dir, "init", "--name", "Repo"))

	return []string{
		"deb-mirror", "--workdir", dir, "--source-repo", upstream, "--source-suite", "stable",
		"--source-component", "main", "--target-suite", "mirror", "--target-component", "main",
	}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &logs
}

func TestDebMirrorSourceKey(t *testing.T) {
	writeKey := func(t *testing.T, data []byte) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "source.key")
		require.NoError(t, os.WriteFile(path, data, 0o600))

		return path
	}

	t.Run("correct key mirrors", func(t *testing.T) {
		upstream, _, pub := fakeUpstream(t, false)
		args := append(mirrorArgs(t, upstream), "--source-key", writeKey(t, pub))

		require.NoError(t, run(t, args...))
		assert.FileExists(t, filepath.Join(args[2], "public", "pool", "mirror", "main", "f", "foo", "amd64", "foo_1.0_amd64.deb"))
	})

	t.Run("wrong key fails before any deb request", func(t *testing.T) {
		upstream, requests, _ := fakeUpstream(t, false)
		other, err := pgpsign.GenerateKey("Other", "other@example.com")
		require.NoError(t, err)

		args := append(mirrorArgs(t, upstream), "--source-key", writeKey(t, other.Public))

		require.ErrorContains(t, run(t, args...), "verify InRelease")
		assert.Equal(t, int32(1), requests.Load())
	})

	t.Run("empty key file fails with no requests", func(t *testing.T) {
		upstream, requests, _ := fakeUpstream(t, false)
		keyFile := writeKey(t, nil)
		args := append(mirrorArgs(t, upstream), "--source-key", keyFile)

		require.ErrorContains(t, run(t, args...), keyFile)
		assert.Zero(t, requests.Load())
	})

	t.Run("missing key file fails with no requests", func(t *testing.T) {
		upstream, requests, _ := fakeUpstream(t, false)
		args := append(mirrorArgs(t, upstream), "--source-key", filepath.Join(t.TempDir(), "absent.key"))

		require.Error(t, run(t, args...))
		assert.Zero(t, requests.Load())
	})
}

func TestDebMirrorFailure(t *testing.T) {
	upstream, _, _ := fakeUpstream(t, true)
	logs := captureLogs(t)

	err := run(t, mirrorArgs(t, upstream)...)
	require.ErrorIs(t, err, debrepo.ErrMirrorFailed)
	assert.Contains(t, logs.String(), "msg=mirrored")
	assert.Contains(t, logs.String(), "added=0 replaced=0 unchanged=0 failed=1")
}

func TestDebMirrorForce(t *testing.T) {
	upstream, _, _ := fakeUpstream(t, false)
	args := mirrorArgs(t, upstream)
	target := filepath.Join(args[2], "public", "pool", "mirror", "main", "f", "foo", "amd64", "foo_1.0_amd64.deb")

	require.NoError(t, run(t, args...))

	want, err := os.ReadFile(target)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target, []byte("corrupted"), 0o644))

	t.Run("without force fails", func(t *testing.T) {
		require.ErrorIs(t, run(t, args...), debrepo.ErrMirrorFailed)

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, []byte("corrupted"), got)
	})

	t.Run("with force replaces", func(t *testing.T) {
		logs := captureLogs(t)

		require.NoError(t, run(t, append(slices.Clone(args), "--force")...))

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, want, got)
		assert.Contains(t, logs.String(), "added=0 replaced=1 unchanged=0 failed=0")
	})
}

func TestDebMirrorFilters(t *testing.T) {
	upstream, requests, _ := fakeUpstream(t, false)

	t.Run("defaults keep everything", func(t *testing.T) {
		logs := captureLogs(t)

		require.NoError(t, run(t, mirrorArgs(t, upstream)...))
		assert.Contains(t, logs.String(), "added=1 replaced=0 unchanged=0 failed=0")
	})

	t.Run("exclude flag drops a package", func(t *testing.T) {
		logs := captureLogs(t)
		before := requests.Load()

		args := append(mirrorArgs(t, upstream), "--filter-name-exclude", "foo")

		require.NoError(t, run(t, args...))
		assert.Contains(t, logs.String(), "added=0 replaced=0 unchanged=0 failed=0")
		assert.Equal(t, before+2, requests.Load(), "InRelease and Packages only, no .deb")
	})

	t.Run("include flag that matches nothing drops a package", func(t *testing.T) {
		logs := captureLogs(t)

		require.NoError(t, run(t, append(mirrorArgs(t, upstream), "--filter-architecture", "arm64")...))
		assert.Contains(t, logs.String(), "added=0 replaced=0 unchanged=0 failed=0")
	})

	t.Run("invalid expression fails before any request", func(t *testing.T) {
		for _, flag := range []string{
			"filter-name", "filter-name-exclude", "filter-version", "filter-version-exclude",
			"filter-architecture", "filter-architecture-exclude",
		} {
			before := requests.Load()

			err := run(t, append(mirrorArgs(t, upstream), fmt.Sprintf("--%s", flag), "(")...)
			require.ErrorContains(t, err, flag)
			require.ErrorContains(t, err, `"("`, flag)
			assert.Equal(t, before, requests.Load(), flag)
		}
	})

	t.Run("parsing sets defaults and leaves excludes empty", func(t *testing.T) {
		var got *mirrorConfig

		_, cmd, err := xflags.BindCommand("deb-mirror", "mirror", func(_ context.Context, _ *xflags.Command, cfg *mirrorConfig, _ []string) error {
			got = cfg

			return nil
		})
		require.NoError(t, err)

		p := xflags.New("repomgr")
		require.NoError(t, p.AddCommand(cmd))

		p.SetArgs(mirrorArgs(t, upstream))
		p.SetOutput(&bytes.Buffer{})
		require.NoError(t, p.Execute(t.Context()))

		require.NotNil(t, got)
		assert.Equal(t, ".*", got.Name)
		assert.Equal(t, ".*", got.Version)
		assert.Empty(t, got.Architecture)
		assert.Empty(t, got.NameExclude)
		assert.Empty(t, got.VersionExclude)
		assert.Empty(t, got.ArchitectureExclude)
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

		assert.NoFileExists(t, filepath.Join(dir, "config", "repo.yaml"))

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

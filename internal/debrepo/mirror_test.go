package debrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/pgpsign"
)

const (
	upInRelease string = "dists/stable/InRelease"
	upAmd64     string = "dists/stable/main/binary-amd64/Packages"
)

type fakeRepo struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func (f *fakeRepo) count(suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0

	for p, c := range f.hits {
		if strings.HasSuffix(p, suffix) {
			n += c
		}
	}

	return n
}

func serveFiles(t testing.TB, files map[string][]byte) *fakeRepo {
	t.Helper()

	f := &fakeRepo{hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()

		data, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write(data)
	}))
	t.Cleanup(f.srv.Close)

	return f
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// packagesEntry returns the Packages paragraph for deb stored at filename.
func packagesEntry(control, filename string, deb []byte) string {
	return fmt.Sprintf("%s\nFilename: %s\nSize: %d\nSHA256: %s", control, filename, len(deb), hexSum(deb))
}

// upstreamKey is generated once per test binary because key generation is slow
// under the race detector.
var upstreamKey = sync.OnceValues(func() (pgpsign.Key, error) {
	return pgpsign.GenerateKey("Upstream", "up@example.com")
})

func signedRelease(t testing.TB, archs, comps string, listed map[string][]byte) []byte {
	t.Helper()

	paths := make([]string, 0, len(listed))
	for p := range listed {
		paths = append(paths, p)
	}

	sort.Strings(paths)

	var sb strings.Builder

	fmt.Fprintf(&sb, "Suite: stable\nArchitectures: %s\nComponents: %s\nSHA256:\n", archs, comps)

	for _, p := range paths {
		fmt.Fprintf(&sb, " %s %d %s\n", hexSum(listed[p]), len(listed[p]), p)
	}

	key, err := upstreamKey()
	require.NoError(t, err)

	signed, err := pgpsign.Sign(key.Private, []byte(sb.String()))
	require.NoError(t, err)

	return signed.Clear
}

// upstreamFiles builds a signed InRelease listing every index path in indexes
// (keyed by path below dists/stable/) plus the .deb files.
func upstreamFiles(t testing.TB, archs, comps string, indexes map[string]string, debs map[string][]byte) map[string][]byte {
	t.Helper()

	files := map[string][]byte{}
	listed := map[string][]byte{}

	for p, content := range indexes {
		files[fmt.Sprintf("dists/stable/%s", p)] = []byte(content)
		listed[p] = []byte(content)
	}

	for p, data := range debs {
		files[p] = data
	}

	files[upInRelease] = signedRelease(t, archs, comps, listed)

	return files
}

func mirrorOpts(f *fakeRepo) MirrorOptions {
	return MirrorOptions{
		SourceRepo:      f.srv.URL,
		SourceSuite:     "stable",
		SourceComponent: "main",
		TargetSuite:     "mirror",
		TargetComponent: "main",
	}
}

func archCtl(pkg, arch string) string {
	return fmt.Sprintf("Package: %s\nVersion: 1.0\nArchitecture: %s", pkg, arch)
}

const (
	poolFoo string = "pool/mirror/main/f/foo/amd64/foo_1.0_amd64.deb"
	poolBar string = "pool/mirror/main/b/bar/arm64/bar_1.0_arm64.deb"
)

func TestMirror(t *testing.T) {
	fooDeb := debBytes(t, archCtl("foo", "amd64"))
	barDeb := debBytes(t, archCtl("bar", "arm64"))

	t.Run("adds packages then second run is unchanged", func(t *testing.T) {
		workdir := newWorkdir(t)
		files := upstreamFiles(t, "amd64 arm64", "main", map[string]string{
			"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
			"main/binary-arm64/Packages": packagesEntry(archCtl("bar", "arm64"), "pool/b/bar.deb", barDeb),
		}, map[string][]byte{"pool/f/foo.deb": fooDeb, "pool/b/bar.deb": barDeb})
		repo := serveFiles(t, files)
		logs := captureLogs(t)

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 2}, res)
		assert.Contains(t, logs.String(), fmt.Sprintf("public/%s", poolFoo))

		got, err := os.ReadFile(filepath.Join(workdir, "public", poolBar))
		require.NoError(t, err)
		assert.Equal(t, barDeb, got)

		cache, err := loadCache(workdir)
		require.NoError(t, err)
		assert.Contains(t, cache, poolFoo)
		assert.Contains(t, cache, poolBar)

		res, err = Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Unchanged: 2}, res)
		assert.Equal(t, 2, repo.count(".deb"))
	})

	t.Run("arch all in two indexes is added once", func(t *testing.T) {
		workdir := newWorkdir(t)
		allDeb := debBytes(t, archCtl("docs", "all"))
		entry := packagesEntry(archCtl("docs", "all"), "pool/d/docs.deb", allDeb)
		files := upstreamFiles(t, "amd64 arm64", "main", map[string]string{
			"main/binary-amd64/Packages": entry,
			"main/binary-arm64/Packages": entry,
		}, map[string][]byte{"pool/d/docs.deb": allDeb})
		repo := serveFiles(t, files)

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
		assert.Equal(t, 1, repo.count(".deb"))
	})

	t.Run("unsupported arch is never requested", func(t *testing.T) {
		workdir := newWorkdir(t)
		files := upstreamFiles(t, "amd64 riscv64", "main", map[string]string{
			"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
		}, map[string][]byte{"pool/f/foo.deb": fooDeb})
		repo := serveFiles(t, files)

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
		assert.Zero(t, repo.count("riscv64/Packages"))
	})

	t.Run("fatal errors", func(t *testing.T) {
		okIndex := packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb)
		okDebs := map[string][]byte{"pool/f/foo.deb": fooDeb}
		amd64Only := map[string]string{"main/binary-amd64/Packages": okIndex}

		noSHA := fmt.Sprintf("%s\nFilename: pool/f/foo.deb\nSize: %d", archCtl("foo", "amd64"), len(fooDeb))
		badSize := fmt.Sprintf("%s\nFilename: pool/f/foo.deb\nSize: -1\nSHA256: %s", archCtl("foo", "amd64"), hexSum(fooDeb))
		noFilename := fmt.Sprintf("%s\nSize: %d\nSHA256: %s", archCtl("foo", "amd64"), len(fooDeb), hexSum(fooDeb))
		noSize := fmt.Sprintf("%s\nFilename: pool/f/foo.deb\nSHA256: %s", archCtl("foo", "amd64"), hexSum(fooDeb))

		tests := []struct {
			name  string
			files func() map[string][]byte
			want  string
		}{
			{"not clearsigned", func() map[string][]byte {
				return map[string][]byte{upInRelease: []byte("Suite: stable\n")}
			}, "not clearsigned"},
			{"missing component", func() map[string][]byte {
				return upstreamFiles(t, "amd64", "contrib", amd64Only, okDebs)
			}, "source has no component"},
			{"no supported arch", func() map[string][]byte {
				return upstreamFiles(t, "riscv64", "main", amd64Only, okDebs)
			}, "architecture"},
			{"index hash mismatch", func() map[string][]byte {
				files := upstreamFiles(t, "amd64", "main", amd64Only, okDebs)
				files[upAmd64] = []byte(fmt.Sprintf("%s\n\n", okIndex))

				return files
			}, "mismatch"},
			{"stanza without sha256", func() map[string][]byte {
				return upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": noSHA}, okDebs)
			}, "SHA256"},
			{"stanza without filename", func() map[string][]byte {
				return upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": noFilename}, okDebs)
			}, "lacks Filename"},
			{"stanza without size", func() map[string][]byte {
				return upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": noSize}, okDebs)
			}, "lacks Size"},
			{"negative size", func() map[string][]byte {
				return upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": badSize}, okDebs)
			}, "Size"},
			{"listed index returns 404", func() map[string][]byte {
				files := upstreamFiles(t, "amd64", "main", amd64Only, okDebs)
				delete(files, upAmd64)

				return files
			}, "404"},
			{"missing InRelease", func() map[string][]byte {
				return map[string][]byte{}
			}, "404"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				workdir := newWorkdir(t)
				repo := serveFiles(t, tt.files())

				_, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
				require.ErrorContains(t, err, tt.want)
				assert.NotErrorIs(t, err, ErrMirrorFailed)
			})
		}
	})

	t.Run("bad package fails only itself", func(t *testing.T) {
		workdir := newWorkdir(t)
		// Same file name in another suite makes the pool conflict check fail.
		other := filepath.Join(workdir, "public", "pool", "other", "main", "b", "bar", "arm64")
		require.NoError(t, os.MkdirAll(other, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(other, "bar_1.0_arm64.deb"), []byte("different"), 0o644))

		bazDeb := debBytes(t, archCtl("baz", "amd64"))
		qux := packagesEntry(archCtl("Qux", "amd64"), "pool/q/qux.deb", fooDeb)
		badHash := strings.Replace(packagesEntry(archCtl("baz", "amd64"), "pool/z/baz.deb", bazDeb), hexSum(bazDeb), hexSum([]byte("nope")), 1)
		index := strings.Join([]string{
			packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
			badHash,
			packagesEntry(archCtl("bar", "arm64"), "pool/b/bar.deb", barDeb),
			qux,
		}, "\n\n")
		files := upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": index},
			map[string][]byte{"pool/f/foo.deb": fooDeb, "pool/z/baz.deb": bazDeb, "pool/b/bar.deb": barDeb})
		repo := serveFiles(t, files)
		logs := captureLogs(t)

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, 1, res.Added)
		assert.Equal(t, 3, res.Failed)

		logLine := func(name string) string {
			for line := range strings.SplitSeq(logs.String(), "\n") {
				if strings.Contains(line, fmt.Sprintf("filename=%s", name)) {
					return line
				}
			}

			return ""
		}

		assert.Contains(t, logLine("pool/z/baz.deb"), "mismatch with index")
		assert.Contains(t, logLine("pool/b/bar.deb"), "conflicting package")
		assert.Contains(t, logLine("pool/q/qux.deb"), "invalid control field")

		assert.NotContains(t, logs.String(), "filename=pool/f/foo.deb")
		assert.Zero(t, repo.count("pool/q/qux.deb"))

		_, err = os.Stat(filepath.Join(workdir, "public", poolFoo))
		require.NoError(t, err)

		_, err = os.Stat(filepath.Join(workdir, "public", poolBar))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("size-only mismatch of a deb fails only that package", func(t *testing.T) {
		wrongSize := strings.Replace(packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
			fmt.Sprintf("Size: %d", len(fooDeb)), fmt.Sprintf("Size: %d", len(fooDeb)+1), 1)
		files := upstreamFiles(t, "amd64", "main", map[string]string{"main/binary-amd64/Packages": wrongSize},
			map[string][]byte{"pool/f/foo.deb": fooDeb})
		repo := serveFiles(t, files)
		logs := captureLogs(t)

		res, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)
		assert.Contains(t, logs.String(), "size mismatch")
	})

	t.Run("trailing slash in source repo", func(t *testing.T) {
		files := upstreamFiles(t, "amd64", "main", map[string]string{
			"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
		}, map[string][]byte{"pool/f/foo.deb": fooDeb})
		repo := serveFiles(t, files)
		opts := mirrorOpts(repo)
		opts.SourceRepo = fmt.Sprintf("%s/", repo.srv.URL)

		res, err := Mirror(t.Context(), newWorkdir(t), opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
		assert.Zero(t, repo.count("//"))
	})

	t.Run("invalid target name makes no request", func(t *testing.T) {
		repo := serveFiles(t, map[string][]byte{})

		for name, set := range map[string]func(o *MirrorOptions){
			"suite":     func(o *MirrorOptions) { o.TargetSuite = "Stable" },
			"component": func(o *MirrorOptions) { o.TargetComponent = "Main" },
		} {
			t.Run(name, func(t *testing.T) {
				opts := mirrorOpts(repo)
				set(&opts)

				_, err := Mirror(t.Context(), newWorkdir(t), opts)
				require.ErrorIs(t, err, ErrInvalidName)
				assert.Zero(t, repo.count(""))
			})
		}
	})

	t.Run("uninitialized workdir makes no request", func(t *testing.T) {
		repo := serveFiles(t, map[string][]byte{})

		_, err := Mirror(t.Context(), t.TempDir(), mirrorOpts(repo))
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Zero(t, repo.count(""))
	})
}

func TestMirrorForce(t *testing.T) {
	fooDeb := debBytes(t, archCtl("foo", "amd64"))
	files := upstreamFiles(t, "amd64", "main", map[string]string{
		"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
	}, map[string][]byte{"pool/f/foo.deb": fooDeb})

	corrupt := func(t *testing.T, workdir, suite string) string {
		t.Helper()

		dir := filepath.Join(workdir, "public", "pool", suite, "main", "f", "foo", "amd64")
		require.NoError(t, os.MkdirAll(dir, 0o755))

		target := filepath.Join(dir, "foo_1.0_amd64.deb")
		require.NoError(t, os.WriteFile(target, []byte("corrupted"), 0o644))

		return target
	}

	t.Run("without force a corrupted target conflicts and nothing is downloaded", func(t *testing.T) {
		workdir := newWorkdir(t)
		target := corrupt(t, workdir, "mirror")
		repo := serveFiles(t, files)

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)
		assert.Zero(t, repo.count(".deb"))

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, []byte("corrupted"), got)
	})

	t.Run("force replaces a corrupted target", func(t *testing.T) {
		workdir := newWorkdir(t)
		target := corrupt(t, workdir, "mirror")
		repo := serveFiles(t, files)
		logs := captureLogs(t)
		opts := mirrorOpts(repo)
		opts.Force = true

		res, err := Mirror(t.Context(), workdir, opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Replaced: 1}, res)
		assert.Contains(t, logs.String(), "replaced")
		assert.Contains(t, logs.String(), fmt.Sprintf("public/%s", poolFoo))
		assert.NotContains(t, logs.String(), "msg=added")

		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, fooDeb, got)

		cache, err := loadCache(workdir)
		require.NoError(t, err)
		assert.Equal(t, hexSum(fooDeb), cache[poolFoo].SHA256)

		res, err = Mirror(t.Context(), workdir, opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Unchanged: 1}, res)
	})

	t.Run("force on a missing target counts as added", func(t *testing.T) {
		workdir := newWorkdir(t)
		repo := serveFiles(t, files)
		opts := mirrorOpts(repo)
		opts.Force = true

		res, err := Mirror(t.Context(), workdir, opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
	})

	t.Run("force still conflicts with the same name in another suite", func(t *testing.T) {
		workdir := newWorkdir(t)
		target := corrupt(t, workdir, "mirror")
		elsewhere := corrupt(t, workdir, "other")
		repo := serveFiles(t, files)
		opts := mirrorOpts(repo)
		opts.Force = true

		res, err := Mirror(t.Context(), workdir, opts)
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)

		for _, file := range []string{target, elsewhere} {
			got, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Equal(t, []byte("corrupted"), got)
		}
	})
}

func TestMirrorIndexValidation(t *testing.T) {
	control := archCtl("foo", "amd64")
	deb := debBytes(t, control)
	const filename = "pool/foo+1#main.deb"

	entry := packagesEntry(control, filename, deb)
	build := func(t *testing.T, content string) map[string][]byte {
		t.Helper()

		return upstreamFiles(t, "all amd64 arm64", "main", map[string]string{
			"main/binary-amd64/Packages": content,
		}, map[string][]byte{filename: deb})
	}

	t.Run("sparse indexes with CRLF and a repository base path", func(t *testing.T) {
		upper := strings.ReplaceAll(entry, hexSum(deb), strings.ToUpper(hexSum(deb)))
		content := strings.ReplaceAll(fmt.Sprintf("%s\n\n%s\n", upper, entry), "\n", "\r\n")
		files := map[string][]byte{}
		for name, data := range build(t, content) {
			files[fmt.Sprintf("repo path/%s", name)] = data
		}

		repo := serveFiles(t, files)
		opts := mirrorOpts(repo)
		opts.SourceRepo = fmt.Sprintf("%s/repo%%20path/", opts.SourceRepo)
		opts.Name = `f|\Qfoo`

		res, err := Mirror(t.Context(), newWorkdir(t), opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
		assert.Equal(t, 1, repo.count(filename))
	})

	t.Run("base path is used exactly as given", func(t *testing.T) {
		files := map[string][]byte{}
		for name, data := range build(t, entry) {
			files[fmt.Sprintf("mirrors//debian/%s", name)] = data
		}

		repo := serveFiles(t, files)
		opts := mirrorOpts(repo)
		opts.SourceRepo = fmt.Sprintf("%s/mirrors//debian/", opts.SourceRepo)

		res, err := Mirror(t.Context(), newWorkdir(t), opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
		assert.Equal(t, 1, repo.count(filename))
	})

	t.Run("conflicting duplicate entries", func(t *testing.T) {
		wrongVersion := strings.Replace(entry, "Version: 1.0", "Version: 2.0", 1)
		repo := serveFiles(t, build(t, strings.Join([]string{entry, wrongVersion}, "\n\n")))
		_, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
		require.ErrorContains(t, err, "conflicting index entries")
		assert.Zero(t, repo.count(filename))
	})

	t.Run("downloaded control disagrees with selected version", func(t *testing.T) {
		wrongVersion := strings.Replace(entry, "Version: 1.0", "Version: 2:1.0", 1)
		repo := serveFiles(t, build(t, wrongVersion))
		opts := mirrorOpts(repo)
		opts.Version = "2:.*"

		workdir := newWorkdir(t)
		logs := captureLogs(t)
		res, err := Mirror(t.Context(), workdir, opts)
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)
		assert.Contains(t, logs.String(), "version differs from index")
		assert.NoFileExists(t, filepath.Join(workdir, "public", poolFoo))

		addPkg(t, workdir, "mirror", "main", control)
		res, err = Mirror(t.Context(), workdir, opts)
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)
		assert.Equal(t, 1, repo.count(filename))
	})

	t.Run("existing package must match the advertised size", func(t *testing.T) {
		workdir := newWorkdir(t)
		addPkg(t, workdir, "mirror", "main", control)
		wrongSize := strings.Replace(entry, fmt.Sprintf("Size: %d", len(deb)), fmt.Sprintf("Size: %d", len(deb)+1), 1)
		repo := serveFiles(t, build(t, wrongSize))

		res, err := Mirror(t.Context(), workdir, mirrorOpts(repo))
		require.ErrorIs(t, err, ErrMirrorFailed)
		assert.Equal(t, MirrorResult{Failed: 1}, res)
		assert.Zero(t, repo.count(filename))
	})

	t.Run("filename must be relative to repository", func(t *testing.T) {
		invalid := strings.Replace(entry, filename, "/pool/foo.deb", 1)
		repo := serveFiles(t, build(t, invalid))

		_, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
		require.ErrorContains(t, err, "invalid Filename")
		assert.Zero(t, repo.count(".deb"))
	})
}

func TestCopySized(t *testing.T) {
	var dst bytes.Buffer
	src := strings.NewReader("extra trailing bytes")

	err := copySized(&dst, src, 5)
	require.ErrorContains(t, err, "size mismatch")
	assert.Equal(t, "extra", dst.String())
	assert.Equal(t, len("trailing bytes"), src.Len())
}

func TestMirrorIndexCompression(t *testing.T) {
	fooDeb := debBytes(t, archCtl("foo", "amd64"))
	index := []byte(packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb))

	var gzBuf bytes.Buffer

	gw := gzip.NewWriter(&gzBuf)
	_, err := gw.Write(index)
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	zw, err := zstd.NewWriter(nil)
	require.NoError(t, err)

	zstData := zw.EncodeAll(index, nil)

	const (
		base    string = "main/binary-amd64/Packages"
		baseGz  string = "main/binary-amd64/Packages.gz"
		baseXz  string = "main/binary-amd64/Packages.xz"
		baseZst string = "main/binary-amd64/Packages.zst"
	)

	gzData := gzBuf.Bytes()
	junk := []byte("not compressed")

	// Every index in content is both listed in Release and served.
	build := func(content map[string][]byte) map[string][]byte {
		files := map[string][]byte{
			upInRelease:      signedRelease(t, "amd64", "main", content),
			"pool/f/foo.deb": fooDeb,
		}
		for p, data := range content {
			files[fmt.Sprintf("dists/stable/%s", p)] = data
		}

		return files
	}

	t.Run("preference", func(t *testing.T) {
		tests := []struct {
			name    string
			content map[string][]byte
			hit     string
			missed  []string
		}{
			{"zst wins", map[string][]byte{base: index, baseGz: gzData, baseZst: zstData}, ".zst", []string{".gz", "/Packages"}},
			{"gz over plain", map[string][]byte{base: index, baseGz: gzData}, ".gz", []string{".zst", "/Packages"}},
			{"xz is never used", map[string][]byte{base: index, baseXz: junk}, "/Packages", []string{".xz"}},
			{"plain only", map[string][]byte{base: index}, "/Packages", []string{".zst", ".gz"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				repo := serveFiles(t, build(tt.content))

				res, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
				require.NoError(t, err)
				assert.Equal(t, MirrorResult{Added: 1}, res)
				assert.Equal(t, 1, repo.count(tt.hit))

				for _, s := range tt.missed {
					assert.Zero(t, repo.count(s), s)
				}
			})
		}
	})

	t.Run("gz index labeled Content-Encoding gzip still verifies", func(t *testing.T) {
		files := build(map[string][]byte{baseGz: gzData})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
			if !ok {
				http.NotFound(w, r)

				return
			}

			if strings.HasSuffix(r.URL.Path, ".gz") {
				w.Header().Set("Content-Encoding", "gzip")
			}

			_, _ = w.Write(data)
		}))
		t.Cleanup(srv.Close)

		opts := mirrorOpts(&fakeRepo{srv: srv})

		res, err := Mirror(t.Context(), newWorkdir(t), opts)
		require.NoError(t, err)
		assert.Equal(t, MirrorResult{Added: 1}, res)
	})

	t.Run("fatal", func(t *testing.T) {
		tests := []struct {
			name    string
			content map[string][]byte
			want    string
		}{
			{"corrupt zst", map[string][]byte{baseZst: junk}, fmt.Sprintf("decompress %s", baseZst)},
			{"corrupt gz", map[string][]byte{baseGz: junk}, fmt.Sprintf("decompress %s", baseGz)},
			{"nothing listed", map[string][]byte{}, "does not list a supported Packages index"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				repo := serveFiles(t, build(tt.content))

				_, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
				require.ErrorContains(t, err, tt.want)
				assert.NotErrorIs(t, err, ErrMirrorFailed)
			})
		}
	})
}

func TestMirrorSourceKey(t *testing.T) {
	fooDeb := debBytes(t, archCtl("foo", "amd64"))

	upstream, err := pgpsign.GenerateKey("Upstream", "up@example.com")
	require.NoError(t, err)

	wrong, err := pgpsign.GenerateKey("Wrong", "wrong@example.com")
	require.NoError(t, err)

	files := upstreamFiles(t, "amd64", "main", map[string]string{
		"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
	}, map[string][]byte{"pool/f/foo.deb": fooDeb})

	block, _ := clearsign.Decode(files[upInRelease])
	require.NotNil(t, block)

	signed, err := pgpsign.Sign(upstream.Private, block.Plaintext)
	require.NoError(t, err)

	files[upInRelease] = signed.Clear

	armored, err := pgpsign.ArmorPublicKey(upstream.Public)
	require.NoError(t, err)

	t.Run("correct key mirrors", func(t *testing.T) {
		for name, key := range map[string][]byte{"binary": upstream.Public, "armored": armored} {
			t.Run(name, func(t *testing.T) {
				repo := serveFiles(t, files)
				opts := mirrorOpts(repo)
				opts.SourceKey = key

				res, err := Mirror(t.Context(), newWorkdir(t), opts)
				require.NoError(t, err)
				assert.Equal(t, MirrorResult{Added: 1}, res)
			})
		}
	})

	edited := maps.Clone(files)
	edited[upInRelease] = bytes.Replace(files[upInRelease], []byte("Suite: stable"), []byte("Suite: edited"), 1)

	t.Run("empty key accepts any signature", func(t *testing.T) {
		for name, served := range map[string]map[string][]byte{"valid": files, "broken signature": edited} {
			t.Run(name, func(t *testing.T) {
				repo := serveFiles(t, served)

				res, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
				require.NoError(t, err)
				assert.Equal(t, MirrorResult{Added: 1}, res)
			})
		}
	})

	t.Run("fatal without package requests", func(t *testing.T) {
		cases := map[string]struct {
			files map[string][]byte
			key   []byte
		}{
			"wrong key":        {files, wrong.Public},
			"edited InRelease": {edited, upstream.Public},
			"garbage key":      {files, []byte("not a key")},
		}

		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				repo := serveFiles(t, tc.files)
				opts := mirrorOpts(repo)
				opts.SourceKey = tc.key

				_, err := Mirror(t.Context(), newWorkdir(t), opts)
				require.ErrorContains(t, err, "verify InRelease")
				assert.Zero(t, repo.count(".deb"))
				assert.Zero(t, repo.count("Packages"))
			})
		}
	})
}

func TestMirrorFilters(t *testing.T) {
	ctl := map[string]string{
		"foo":          "Package: foo\nVersion: 1.0\nArchitecture: amd64",
		"bar":          "Package: bar\nVersion: 2:2.0\nArchitecture: arm64",
		"baz":          "Package: baz\nVersion: 2.0\nArchitecture: amd64",
		"foobar":       "Package: foobar\nVersion: 1.0\nArchitecture: amd64",
		"salt-rc-tool": "Package: salt-rc-tool\nVersion: 3006.9\nArchitecture: amd64",
		"salt-rc":      "Package: salt-rc\nVersion: 3008.0~rc1\nArchitecture: amd64",
		"salt":         "Package: salt\nVersion: 3008.0\nArchitecture: amd64",
		"epoch":        "Package: epoch\nVersion: 1:3006.0\nArchitecture: amd64",
	}

	var amd64, arm64 []string

	debs := map[string][]byte{}

	for name, c := range ctl {
		file := fmt.Sprintf("pool/%s.deb", name)
		debs[file] = debBytes(t, c)

		entry := packagesEntry(c, file, debs[file])
		if name == "bar" {
			arm64 = append(arm64, entry)
		} else {
			amd64 = append(amd64, entry)
		}
	}

	files := upstreamFiles(t, "amd64 arm64", "main", map[string]string{
		"main/binary-amd64/Packages": strings.Join(amd64, "\n\n"),
		"main/binary-arm64/Packages": strings.Join(arm64, "\n\n"),
	}, debs)

	all := slices.Sorted(maps.Keys(ctl))
	without := func(names ...string) []string {
		return slices.DeleteFunc(slices.Clone(all), func(n string) bool { return slices.Contains(names, n) })
	}

	tests := []struct {
		name   string
		set    func(o *MirrorOptions)
		wanted []string
	}{
		{"empty patterns keep everything", func(*MirrorOptions) {}, all},
		{"name include", func(o *MirrorOptions) { o.Name = `ba.*` }, []string{"bar", "baz"}},
		{"name include is not a substring", func(o *MirrorOptions) { o.Name = `foo` }, []string{"foo"}},
		{"name include alternation matches the whole value", func(o *MirrorOptions) { o.Name = `foo|foobar` }, []string{"foo", "foobar"}},
		{"name exclude", func(o *MirrorOptions) { o.NameExclude = `ba.*` }, without("bar", "baz")},
		{"name exclude is not a substring", func(o *MirrorOptions) { o.NameExclude = `rc` }, all},
		{"name exclude wildcard", func(o *MirrorOptions) { o.NameExclude = `.*rc.*` }, without("salt-rc-tool", "salt-rc")},
		{"version include keeps epoch", func(o *MirrorOptions) { o.Version = `2:.*` }, []string{"bar"}},
		{"version include is not a prefix", func(o *MirrorOptions) { o.Version = `3006` }, nil},
		{"version include wildcard skips epoch", func(o *MirrorOptions) { o.Version = `3006.*` }, []string{"salt-rc-tool"}},
		{"version include with epoch", func(o *MirrorOptions) { o.Version = `1:3006.*` }, []string{"epoch"}},
		{"version exclude", func(o *MirrorOptions) { o.VersionExclude = `2\..*` }, without("baz")},
		{"version exclude wildcard", func(o *MirrorOptions) { o.VersionExclude = `.*~rc.*` }, without("salt-rc")},
		{"architecture include", func(o *MirrorOptions) { o.Architecture = `arm64` }, []string{"bar"}},
		{"architecture exclude", func(o *MirrorOptions) { o.ArchitectureExclude = `arm64` }, without("bar")},
		{"include and exclude combine", func(o *MirrorOptions) {
			o.Architecture = `amd64`
			o.NameExclude = `foo`
		}, without("foo", "bar")},
		{"match nothing", func(o *MirrorOptions) { o.Name = `nope` }, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := serveFiles(t, files)
			opts := mirrorOpts(repo)
			tt.set(&opts)

			res, err := Mirror(t.Context(), newWorkdir(t), opts)
			require.NoError(t, err)
			assert.Equal(t, MirrorResult{Added: len(tt.wanted)}, res)

			for name := range ctl {
				want := 0
				if slices.Contains(tt.wanted, name) {
					want = 1
				}

				assert.Equal(t, want, repo.count(fmt.Sprintf("pool/%s.deb", name)), name)
			}
		})
	}
}

func TestMirrorInvalidFilter(t *testing.T) {
	repo := serveFiles(t, map[string][]byte{})
	workdir := newWorkdir(t)

	tests := map[string]func(o *MirrorOptions, pattern string){
		"filter-name":                 func(o *MirrorOptions, p string) { o.Name = p },
		"filter-name-exclude":         func(o *MirrorOptions, p string) { o.NameExclude = p },
		"filter-version":              func(o *MirrorOptions, p string) { o.Version = p },
		"filter-version-exclude":      func(o *MirrorOptions, p string) { o.VersionExclude = p },
		"filter-architecture":         func(o *MirrorOptions, p string) { o.Architecture = p },
		"filter-architecture-exclude": func(o *MirrorOptions, p string) { o.ArchitectureExclude = p },
	}

	// "a)|(b" compiles once wrapped, but it is invalid on its own.
	for _, pattern := range []string{"(", "a)|(b"} {
		for flag, set := range tests {
			opts := mirrorOpts(repo)
			set(&opts, pattern)

			_, err := Mirror(t.Context(), workdir, opts)
			require.ErrorContains(t, err, flag)
			require.ErrorContains(t, err, fmt.Sprintf("%q", pattern))
			assert.Zero(t, repo.count(""), flag)
		}
	}
}

func TestMirrorFieldNameCase(t *testing.T) {
	foo := debBytes(t, archCtl("foo", "amd64"))
	bar := debBytes(t, archCtl("bar", "amd64"))
	baz := debBytes(t, archCtl("baz", "amd64"))

	key, err := upstreamKey()
	require.NoError(t, err)

	for name, change := range map[string]func(string) string{"lower": strings.ToLower, "upper": strings.ToUpper} {
		t.Run(name, func(t *testing.T) {
			entry := func(pkg string, data []byte) string {
				return fmt.Sprintf("%s: %s\n%s: 1.0\n%s: amd64\n%s: pool/%s.deb\n%s: %d\n%s: %s",
					change("Package"), pkg, change("Version"), change("Architecture"), change("Filename"), pkg,
					change("Size"), len(data), change("SHA256"), hexSum(data))
			}

			// A whitespace-only line and a run of blank lines both separate paragraphs.
			index := fmt.Sprintf("%s\n \t\n%s\n\n\n\n%s\n", entry("foo", foo), entry("bar", bar), entry("baz", baz))
			release := fmt.Sprintf("Suite: stable\n%s: amd64\n%s: main\n%s:\n", change("Architectures"), change("Components"), change("SHA256"))
			release += fmt.Sprintf(" %s %d main/binary-amd64/Packages\n", hexSum([]byte(index)), len(index))

			signed, err := pgpsign.Sign(key.Private, []byte(release))
			require.NoError(t, err)

			repo := serveFiles(t, map[string][]byte{
				upInRelease:    signed.Clear,
				upAmd64:        []byte(index),
				"pool/foo.deb": foo,
				"pool/bar.deb": bar,
				"pool/baz.deb": baz,
			})

			res, err := Mirror(t.Context(), newWorkdir(t), mirrorOpts(repo))
			require.NoError(t, err)
			assert.Equal(t, MirrorResult{Added: 3}, res)
		})
	}
}

func BenchmarkMirror(b *testing.B) {
	fooDeb := debBytes(b, archCtl("foo", "amd64"))
	files := upstreamFiles(b, "amd64", "main", map[string]string{
		"main/binary-amd64/Packages": packagesEntry(archCtl("foo", "amd64"), "pool/f/foo.deb", fooDeb),
	}, map[string][]byte{"pool/f/foo.deb": fooDeb})
	repo := serveFiles(b, files)
	workdir := newWorkdir(b)
	opts := mirrorOpts(repo)

	_, err := Mirror(b.Context(), workdir, opts)
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		_, err := Mirror(b.Context(), workdir, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzMirrorIndex(f *testing.F) {
	f.Add(" abc 12 main/binary-amd64/Packages\n def 3 main/binary-amd64/Packages.gz", "Package: foo\nVersion: 1.0\nFilename: pool/foo.deb\nSize: 10\nSHA256: abc")
	f.Add("", "")
	f.Add(" abc -1 x\n bad line", "Package: foo\nSize: -5\nSHA256: abc\nFilename: x")

	f.Fuzz(func(t *testing.T, release, paragraph string) {
		files, err := parseReleaseHashes(release)
		if err == nil {
			for name, file := range files {
				assert.NotEmpty(t, name)
				assert.GreaterOrEqual(t, file.size, int64(0))
			}
		}

		e, err := parseIndexEntry(paragraph)
		if err != nil {
			return
		}

		assert.NotEmpty(t, e.filename)
		assert.NotEmpty(t, e.sha256)
		assert.GreaterOrEqual(t, e.size, int64(0))
	})
}

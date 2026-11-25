package rpmrepo

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/pgpsign"
)

var metaName = regexp.MustCompile(`^[0-9a-f]{64}-(primary|filelists|other)\.xml\.gz$`)

// metaFiles returns the names of the metadata files of type typ in repodata.
func metaFiles(t *testing.T, repodata, typ string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(repodata, fmt.Sprintf("*-%s.xml.gz", typ)))
	require.NoError(t, err)

	names := make([]string, 0, len(matches))

	for _, m := range matches {
		names = append(names, filepath.Base(m))
	}

	slices.Sort(names)

	return names
}

type retentionEnv struct {
	workdir  string
	repoDir  string
	repodata string
	seen     map[string]bool
	step     int
}

func newRetentionEnv(t *testing.T) *retentionEnv {
	t.Helper()

	workdir := initWorkdir(t)
	repoDir := filepath.Join(workdir, "public", "x86_64", "9", "main")

	return &retentionEnv{workdir: workdir, repoDir: repoDir, repodata: filepath.Join(repoDir, "repodata"), seen: make(map[string]bool)}
}

// addVersion adds a package of the given version to the pool.
func (e *retentionEnv) addVersion(t *testing.T, version string) string {
	t.Helper()

	p := basePkg()
	p.Version = version

	return addPkg(t, e.workdir, "9/main", p)
}

// build runs a build and stamps every metadata file it created with an
// increasing mtime, so ranking never depends on the clock.
func (e *retentionEnv) build(t *testing.T) {
	t.Helper()

	e.step++

	_, err := Build(t.Context(), e.workdir, buildTime.Add(time.Duration(e.step)*time.Hour))
	require.NoError(t, err)

	entries, err := os.ReadDir(e.repodata)
	require.NoError(t, err)

	stamp := time.Unix(1700000000, 0).Add(time.Duration(e.step) * time.Minute)

	for _, d := range entries {
		if !metaName.MatchString(d.Name()) || e.seen[d.Name()] {
			continue
		}

		e.seen[d.Name()] = true

		require.NoError(t, os.Chtimes(filepath.Join(e.repodata, d.Name()), stamp, stamp))
	}
}

func TestRetention(t *testing.T) {
	types := []string{"primary", "filelists", "other"}

	t.Run("keeps current plus two previous generations", func(t *testing.T) {
		env := newRetentionEnv(t)
		logs := captureLogs(t)

		gens := make([]map[string][]string, 0, 4)

		for _, v := range []string{"1.0", "2.0", "3.0", "4.0"} {
			env.addVersion(t, v)
			env.build(t)

			gen := make(map[string][]string)
			for _, typ := range types {
				gen[typ] = metaFiles(t, env.repodata, typ)
			}

			gens = append(gens, gen)
		}

		for _, typ := range types {
			got := metaFiles(t, env.repodata, typ)
			assert.Len(t, got, 3, typ)

			oldest := gens[0][typ]
			require.Len(t, oldest, 1)
			assert.NotContains(t, got, oldest[0])
			assert.Contains(t, logs.String(), fmt.Sprintf("msg=removed path=public/x86_64/9/main/repodata/%s\n", oldest[0]))
		}

		assert.Equal(t, 3, strings.Count(logs.String(), "msg=removed "))
	})

	t.Run("no-op build removes and touches nothing", func(t *testing.T) {
		env := newRetentionEnv(t)

		for _, v := range []string{"1.0", "2.0", "3.0"} {
			env.addVersion(t, v)
			env.build(t)
		}

		before := mtimes(t, filepath.Join(env.workdir, "public"))
		logs := captureLogs(t)

		env.build(t)

		assert.Empty(t, logs.String())
		assert.Equal(t, before, mtimes(t, filepath.Join(env.workdir, "public")))
	})

	t.Run("reverting touches the reused file", func(t *testing.T) {
		env := newRetentionEnv(t)

		env.addVersion(t, "1.0")
		env.build(t)
		env.addVersion(t, "2.0")
		env.build(t)
		last := env.addVersion(t, "3.0")
		env.build(t)

		// Back to the content of the second generation.
		require.NoError(t, os.Remove(last))

		logs := captureLogs(t)

		env.build(t)

		now := buildTime.Add(time.Duration(env.step) * time.Hour)

		referenced := repomdFiles(t, env.repodata)

		for _, typ := range types {
			files := metaFiles(t, env.repodata, typ)
			assert.Len(t, files, 3, typ)

			info, err := os.Stat(filepath.Join(env.repodata, referenced[typ]))
			require.NoError(t, err)
			assert.True(t, info.ModTime().Equal(now), typ)
		}

		assert.NotContains(t, logs.String(), "msg=removed")
	})

	t.Run("unrelated names stay", func(t *testing.T) {
		env := newRetentionEnv(t)
		env.addVersion(t, "1.0")
		env.build(t)

		extras := []string{"notes.txt", "abc-primary.xml.gz", ".hidden-primary.xml"}
		for _, name := range extras {
			require.NoError(t, os.WriteFile(filepath.Join(env.repodata, name), []byte("x"), 0o644))
		}

		dirName := fmt.Sprintf("%s-primary.xml.gz", strings.Repeat("a", 64))

		require.NoError(t, os.Mkdir(filepath.Join(env.repodata, dirName), 0o755))

		for _, v := range []string{"2.0", "3.0", "4.0"} {
			env.addVersion(t, v)
			env.build(t)
		}

		for _, name := range extras {
			assert.FileExists(t, filepath.Join(env.repodata, name))
		}

		assert.DirExists(t, filepath.Join(env.repodata, dirName))
	})

	t.Run("current repository keeps published hrefs", func(t *testing.T) {
		env := newRetentionEnv(t)
		env.addVersion(t, "1.0")
		env.build(t)

		// Publish a repomd whose hrefs differ from the rendered names, with the
		// same open checksums and a valid signature.
		var md repomd

		data, err := os.ReadFile(filepath.Join(env.repodata, "repomd.xml"))
		require.NoError(t, err)
		require.NoError(t, xml.Unmarshal(data, &md))

		for i, d := range md.Data {
			gz, err := os.ReadFile(filepath.Join(env.repoDir, d.Location.Href))
			require.NoError(t, err)

			var other bytes.Buffer
			zw := gzip.NewWriter(&other)
			zw.Name = fmt.Sprintf("%s.xml", d.Type)
			_, err = zw.Write(gunzip(t, gz))
			require.NoError(t, err)
			require.NoError(t, zw.Close())

			sum := hexSHA256(other.Bytes())
			name := fmt.Sprintf("%s-%s.xml.gz", sum, d.Type)

			require.NoError(t, os.WriteFile(filepath.Join(env.repodata, name), other.Bytes(), 0o644))

			md.Data[i].Size = other.Len()
			md.Data[i].Checksum.Value = sum
			md.Data[i].Location.Href = path.Join("repodata", name)
		}

		out, err := marshalXML(md)
		require.NoError(t, err)

		signed, err := pgpsign.Sign(readSigningKey(t, env.workdir), out)
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(filepath.Join(env.repodata, "repomd.xml"), out, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(env.repodata, "repomd.xml.asc"), signed.Detached, 0o644))

		logs := captureLogs(t)

		env.build(t)

		assert.NotContains(t, logs.String(), "repomd.xml")

		for _, d := range md.Data {
			assert.FileExists(t, filepath.Join(env.repoDir, d.Location.Href))
		}
	})
}

// repomdFiles returns the file name each type of the published repomd points at.
func repomdFiles(t *testing.T, repodata string) map[string]string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repodata, "repomd.xml"))
	require.NoError(t, err)

	var md repomd

	require.NoError(t, xml.Unmarshal(data, &md))

	out := make(map[string]string)
	for _, d := range md.Data {
		out[d.Type] = filepath.Base(d.Location.Href)
	}

	return out
}

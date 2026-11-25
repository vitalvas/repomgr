package rpmrepo

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
	"go.vitalvas.com/repomgr/internal/rpmfile"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

var buildTime = time.Unix(1800000000, 0)

func readSigningKey(t testing.TB, workdir string) []byte {
	t.Helper()

	key, err := os.ReadFile(filepath.Join(workdir, "config", "signing.asc"))
	require.NoError(t, err)

	return key
}

// addPkg adds p to the pool and returns the absolute pool file path. target is
// "<release>/<component>".
func addPkg(t *testing.T, workdir, target string, p rpmtest.Package) string {
	t.Helper()

	release, component, _ := strings.Cut(target, "/")

	res, err := Add(workdir, release, component, writeRPM(t, p))
	require.NoError(t, err)

	return filepath.Join(workdir, "public", filepath.FromSlash(res.Path))
}

func parseFile(t *testing.T, file string) rpmfile.Package {
	t.Helper()

	f, err := os.Open(file)
	require.NoError(t, err)

	defer f.Close()

	pkg, err := rpmfile.Parse(f)
	require.NoError(t, err)

	return pkg
}

type gotRepo struct {
	primary   gotPrimary
	filelists gotList
	other     gotList
}

// readRepo checks the repomd.xml signature, checksums, sizes, and timestamps
// against the files it points at and returns the parsed metadata.
func readRepo(t *testing.T, workdir, repoDir string) gotRepo {
	t.Helper()

	repomd, err := os.ReadFile(filepath.Join(repoDir, "repodata", "repomd.xml"))
	require.NoError(t, err)

	asc, err := os.ReadFile(filepath.Join(repoDir, "repodata", "repomd.xml.asc"))
	require.NoError(t, err)

	key := readSigningKey(t, workdir)

	public, err := pgpsign.PublicKey(key)
	require.NoError(t, err)

	// Verify also checks a clearsigned copy, which build does not write.
	clearSigned, err := pgpsign.Sign(key, repomd)
	require.NoError(t, err)
	require.NoError(t, pgpsign.Verify(public, repomd, pgpsign.Signed{Clear: clearSigned.Clear, Detached: asc}))

	var md gotRepomd
	require.NoError(t, xml.Unmarshal(repomd, &md))
	assert.Equal(t, buildTime.Unix(), md.Revision)

	var got gotRepo

	targets := []struct {
		typ string
		dst any
	}{
		{"primary", &got.primary},
		{"filelists", &got.filelists},
		{"other", &got.other},
	}

	require.Len(t, md.Data, len(targets))

	for i, target := range targets {
		d := md.Data[i]
		assert.Equal(t, target.typ, d.Type)

		gz, err := os.ReadFile(filepath.Join(repoDir, filepath.FromSlash(d.Location.Href)))
		require.NoError(t, err)

		open := gunzip(t, gz)

		assert.Equal(t, fmt.Sprintf("repodata/%s-%s.xml.gz", hexSHA256(gz), target.typ), d.Location.Href)
		assert.Equal(t, gotChecksum{Type: "sha256", Value: hexSHA256(gz)}, d.Checksum)
		assert.Equal(t, gotChecksum{Type: "sha256", Value: hexSHA256(open)}, d.OpenChecksum)
		assert.Equal(t, len(gz), d.Size)
		assert.Equal(t, len(open), d.OpenSize)
		assert.Equal(t, buildTime.Unix(), d.Timestamp)
		require.NoError(t, xml.Unmarshal(open, target.dst))
	}

	return got
}

func TestBuild(t *testing.T) {
	t.Run("x86_64 and noarch", func(t *testing.T) {
		workdir := initWorkdir(t)
		epoch := uint32(3)

		binFile := addPkg(t, workdir, "9/main", basePkg())

		doc := basePkg()
		doc.Name = "pdns-doc"
		doc.Arch = "noarch"
		doc.Epoch = &epoch
		docFile := addPkg(t, workdir, "9/main", doc)

		mtime := time.Unix(1700000000, 0)
		require.NoError(t, os.Chtimes(binFile, mtime, mtime))

		var logs bytes.Buffer

		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })

		summaries, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, []Summary{{Release: "9", Component: "main", Packages: 2, Arches: []string{"aarch64", "x86_64"}}}, summaries)

		out := logs.String()
		assert.Regexp(t, `msg=added path=public/x86_64/9/main/repodata/[0-9a-f]{64}-primary\.xml\.gz\n`, out)
		assert.Contains(t, out, "msg=updated path=public/aarch64/9/main/repodata/repomd.xml.asc\n")
		assert.Contains(t, out, "msg=updated path=public/x86_64/9/main/repodata/repomd.xml\n")

		repoDir := filepath.Join(workdir, "public", "x86_64", "9", "main")
		x86 := readRepo(t, workdir, repoDir)

		assert.Equal(t, xml.Name{Space: nsCommon, Local: "metadata"}, x86.primary.XMLName)
		assert.Equal(t, 2, x86.primary.Packages)
		require.Len(t, x86.primary.Package, 2)

		bin := parseFile(t, binFile)
		got := x86.primary.Package[0]
		assert.Equal(t, "rpm", got.Type)
		assert.Equal(t, "pdns", got.Name)
		assert.Equal(t, "x86_64", got.Arch)
		assert.Equal(t, gotVersion{Epoch: "0", Ver: "5.1.0", Rel: "1.el9"}, got.Version)
		assert.Equal(t, gotChecksum{Type: "sha256", PkgID: "YES", Value: bin.SHA256}, got.Checksum)

		for _, empty := range []*string{got.Summary, got.Description, got.Packager, got.URL, got.Format.License, got.Format.Vendor, got.Format.Group, got.Format.BuildHost} {
			require.NotNil(t, empty)
			assert.Empty(t, *empty)
		}

		assert.Equal(t, mtime.Unix(), got.Time.File)
		assert.Zero(t, got.Time.Build)
		assert.Equal(t, bin.Size, got.Size.Package)
		assert.Zero(t, got.Size.Installed)
		assert.Zero(t, got.Size.Archive)
		assert.Equal(t, "pdns-5.1.0-1.el9.src.rpm", got.Format.SourceRPM)
		assert.Equal(t, bin.HeaderStart, got.Format.HeaderRange.Start)
		assert.Equal(t, bin.HeaderEnd, got.Format.HeaderRange.End)

		linked, err := os.Stat(filepath.Join(repoDir, filepath.FromSlash(got.Location.Href)))
		require.NoError(t, err)

		pool, err := os.Stat(binFile)
		require.NoError(t, err)
		assert.True(t, os.SameFile(pool, linked))

		noarch := x86.primary.Package[1]
		assert.Equal(t, "pdns-doc", noarch.Name)
		assert.Equal(t, "noarch", noarch.Arch)
		assert.Equal(t, "3", noarch.Version.Epoch)

		for _, list := range []gotList{x86.filelists, x86.other} {
			assert.Equal(t, 2, list.Packages)
			require.Len(t, list.Package, 2)
			assert.Equal(t, bin.SHA256, list.Package[0].PkgID)
			assert.Equal(t, "pdns", list.Package[0].Name)
			assert.Equal(t, "x86_64", list.Package[0].Arch)
			assert.Equal(t, gotVersion{Epoch: "0", Ver: "5.1.0", Rel: "1.el9"}, list.Package[0].Version)
			assert.Equal(t, "pdns-doc", list.Package[1].Name)
		}

		assert.Equal(t, xml.Name{Space: nsFilelists, Local: "filelists"}, x86.filelists.XMLName)
		assert.Equal(t, xml.Name{Space: nsOther, Local: "otherdata"}, x86.other.XMLName)

		arm := readRepo(t, workdir, filepath.Join(workdir, "public", "aarch64", "9", "main"))
		require.Len(t, arm.primary.Package, 1)
		assert.Equal(t, "pdns-doc", arm.primary.Package[0].Name)
		assert.Equal(t, parseFile(t, docFile).SHA256, arm.primary.Package[0].Checksum.Value)
	})

	t.Run("aarch64 only", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Arch = "aarch64"
		addPkg(t, workdir, "9/main", p)

		summaries, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, []Summary{{Release: "9", Component: "main", Packages: 1, Arches: []string{"aarch64"}}}, summaries)
		assertArchEmpty(t, workdir, "x86_64")

		repo := readRepo(t, workdir, filepath.Join(workdir, "public", "aarch64", "9", "main"))
		require.Len(t, repo.primary.Package, 1)
		assert.Equal(t, "aarch64", repo.primary.Package[0].Arch)
	})

	t.Run("dependencies", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Tags = []rpmtest.Tag{
			{ID: 1047, Type: 8, Value: []string{"pdns", "pdns(x86-64)"}},
			{ID: 1112, Type: 4, Value: []uint32{8, 8}},
			{ID: 1113, Type: 8, Value: []string{"5.1.0-1.el9", "5.1.0-1.el9"}},
			{ID: 1049, Type: 8, Value: []string{"libc.so.6()(64bit)", "rpmlib(PayloadIsXz)", "/bin/sh", "pdns(x86-64)", "libc.so.6(GLIBC_2.17)(64bit)"}},
			{ID: 1048, Type: 4, Value: []uint32{0, 8, 1 << 9, 8, 0}},
			{ID: 1050, Type: 8, Value: []string{"", "5.2-1", "", "5.1.0-1.el9", ""}},
			{ID: 1156, Type: 8, Value: []string{"weak", "strong"}},
			{ID: 1158, Type: 4, Value: []uint32{0, 1 << 27}},
			{ID: 1157, Type: 8, Value: []string{"", ""}},
		}
		addPkg(t, workdir, "9/main", p)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		repo := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
		require.Len(t, repo.primary.Package, 1)

		f := repo.primary.Package[0].Format
		assert.Equal(t, []gotEntry{
			{Name: "pdns", Flags: "EQ", Epoch: "0", Ver: "5.1.0", Rel: "1.el9"},
			{Name: "pdns(x86-64)", Flags: "EQ", Epoch: "0", Ver: "5.1.0", Rel: "1.el9"},
		}, f.Provides.Entry)
		assert.Equal(t, []gotEntry{{Name: "/bin/sh", Pre: "1"}, {Name: "libc.so.6(GLIBC_2.17)(64bit)"}}, f.Requires.Entry)
		require.NotNil(t, f.Suggests)
		require.NotNil(t, f.Recommends)
		assert.Equal(t, []gotEntry{{Name: "weak"}}, f.Suggests.Entry)
		assert.Equal(t, []gotEntry{{Name: "strong"}}, f.Recommends.Entry)
		assert.Nil(t, f.Conflicts)
	})

	t.Run("files", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Tags = []rpmtest.Tag{
			{ID: 1117, Type: 8, Value: []string{"pdns", "pdns", "run"}},
			{ID: 1118, Type: 8, Value: []string{"/usr/bin/", "/usr/share/doc/"}},
			{ID: 1116, Type: 4, Value: []uint32{0, 1, 1}},
			{ID: 1030, Type: 3, Value: []uint16{0o100755, 0o040755, 0o100644}},
			{ID: 1037, Type: 4, Value: []uint32{0, 0, 1 << 6}},
		}
		addPkg(t, workdir, "9/main", p)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		repo := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
		require.Len(t, repo.primary.Package, 1)
		assert.Equal(t, []gotFile{{Path: "/usr/bin/pdns"}}, repo.primary.Package[0].Format.Files)

		require.Len(t, repo.filelists.Package, 1)
		assert.Equal(t, []gotFile{
			{Path: "/usr/bin/pdns"},
			{Type: "dir", Path: "/usr/share/doc/pdns"},
			{Type: "ghost", Path: "/usr/share/doc/run"},
		}, repo.filelists.Package[0].Files)
		assert.Empty(t, repo.other.Package[0].Files)
	})

	t.Run("changelog", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Tags = []rpmtest.Tag{
			{ID: 1080, Type: 4, Value: []uint32{1700000000, 1700000000, 1600000000}},
			{ID: 1081, Type: 8, Value: []string{"B - 5.1.0-1  ", "A - 5.0.0-2", "A - 5.0.0-1"}},
			{ID: 1082, Type: 8, Value: []string{"- third", "- second", "- first"}},
		}
		addPkg(t, workdir, "9/main", p)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		repo := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
		require.Len(t, repo.other.Package, 1)
		assert.Equal(t, []gotChangelog{
			{Author: "A - 5.0.0-1", Date: 1600000000, Text: "- first"},
			{Author: "A - 5.0.0-2", Date: 1700000000, Text: "- second"},
			{Author: "B - 5.1.0-1", Date: 1700000001, Text: "- third"},
		}, repo.other.Package[0].Changelog)

		require.Len(t, repo.filelists.Package, 1)
		assert.Empty(t, repo.filelists.Package[0].Changelog)
	})

	t.Run("descriptive fields and sizes", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Tags = []rpmtest.Tag{
			{ID: 1004, Type: 9, Value: []string{"PowerDNS", "PowerDNS de"}},
			{ID: 1005, Type: 9, Value: []string{"The PowerDNS server.", "de"}},
			{ID: 1006, Type: 4, Value: []uint32{1600000000}},
			{ID: 1007, Type: 6, Value: "build.example"},
			{ID: 1009, Type: 4, Value: []uint32{4096}},
			{ID: 1011, Type: 6, Value: "Vendor"},
			{ID: 1014, Type: 6, Value: "GPLv2"},
			{ID: 1015, Type: 6, Value: "Packager"},
			{ID: 1016, Type: 9, Value: []string{"System Environment/Daemons"}},
			{ID: 1020, Type: 6, Value: "https://www.powerdns.com/"},
		}
		p.SigTags = []rpmtest.Tag{{ID: 1007, Type: 4, Value: []uint32{8192}}}
		addPkg(t, workdir, "9/main", p)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		repo := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
		require.Len(t, repo.primary.Package, 1)

		got := repo.primary.Package[0]
		assert.Equal(t, "PowerDNS", *got.Summary)
		assert.Equal(t, "The PowerDNS server.", *got.Description)
		assert.Equal(t, "Packager", *got.Packager)
		assert.Equal(t, "https://www.powerdns.com/", *got.URL)
		assert.Equal(t, int64(1600000000), got.Time.Build)
		assert.Equal(t, int64(4096), got.Size.Installed)
		assert.Equal(t, int64(8192), got.Size.Archive)
		assert.Equal(t, "GPLv2", *got.Format.License)
		assert.Equal(t, "Vendor", *got.Format.Vendor)
		assert.Equal(t, "System Environment/Daemons", *got.Format.Group)
		assert.Equal(t, "build.example", *got.Format.BuildHost)
	})

	t.Run("one summary per release and component", func(t *testing.T) {
		workdir := initWorkdir(t)
		addPkg(t, workdir, "9/main", basePkg())
		addPkg(t, workdir, "10/main", basePkg())
		addPkg(t, workdir, "9/extra", basePkg())

		summaries, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, []Summary{
			{Release: "10", Component: "main", Packages: 1, Arches: []string{"x86_64"}},
			{Release: "9", Component: "extra", Packages: 1, Arches: []string{"x86_64"}},
			{Release: "9", Component: "main", Packages: 1, Arches: []string{"x86_64"}},
		}, summaries)

		for _, dir := range []string{"10/main", "9/extra", "9/main"} {
			assert.FileExists(t, filepath.Join(workdir, "public", "x86_64", filepath.FromSlash(dir), "repodata", "repomd.xml"))
		}
	})

	t.Run("misplaced", func(t *testing.T) {
		for _, rel := range []string{
			"9/main/p/pdns/aarch64/pdns-5.1.0-1.el9.x86_64.rpm",
			"9/main/p/pdns/x86_64/renamed.rpm",
			"7/main/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm",
			"9/ma.in/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm",
			"pdns-5.1.0-1.el9.x86_64.rpm",
		} {
			t.Run(rel, func(t *testing.T) {
				workdir := initWorkdir(t)
				file := addPkg(t, workdir, "9/main", basePkg())
				target := filepath.Join(workdir, "public", "pool", filepath.FromSlash(rel))
				require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				require.NoError(t, os.Rename(file, target))

				_, err := Build(t.Context(), workdir, buildTime)
				require.ErrorIs(t, err, ErrMisplaced)
				assertArchEmpty(t, workdir, "x86_64")
			})
		}
	})

	t.Run("conflict writes no repodata", func(t *testing.T) {
		workdir := initWorkdir(t)
		addPkg(t, workdir, "9/main", basePkg())

		other := basePkg()
		other.Payload = []byte("other")
		data, err := rpmtest.Build(other)
		require.NoError(t, err)

		target := filepath.Join(workdir, "public", "pool", "10", "main", "p", "pdns", "x86_64", "pdns-5.1.0-1.el9.x86_64.rpm")
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
		require.NoError(t, os.WriteFile(target, data, 0o644))

		_, err = Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, repofs.ErrConflict)
		assertArchEmpty(t, workdir, "x86_64")
	})

	t.Run("unparseable package", func(t *testing.T) {
		workdir := initWorkdir(t)
		target := filepath.Join(workdir, "public", "pool", "9", "main", "p", "pdns", "x86_64", "bad.rpm")
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
		require.NoError(t, os.WriteFile(target, []byte("not an rpm"), 0o644))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorContains(t, err, target)
	})

	t.Run("Latin-1 summary renders as UTF-8", func(t *testing.T) {
		workdir := initWorkdir(t)
		p := basePkg()
		p.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: "caf\xe9"}}
		addPkg(t, workdir, "9/main", p)

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, "caf\xc3\xa9", primarySummary(t, workdir))
		assert.NotContains(t, logs.String(), "msg=parsed")
	})

	t.Run("bad text in the pool", func(t *testing.T) {
		for _, summary := range []string{"a\x01b", "\xed\xa0\x80"} {
			workdir := initWorkdir(t)
			p := basePkg()
			p.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: summary}}
			data, err := rpmtest.Build(p)
			require.NoError(t, err)

			target := filepath.Join(workdir, "public", "pool", "9", "main", "p", "pdns", "x86_64", "pdns-5.1.0-1.el9.x86_64.rpm")
			require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
			require.NoError(t, os.WriteFile(target, data, 0o644))

			_, err = Build(t.Context(), workdir, buildTime)
			require.ErrorIs(t, err, rpmfile.ErrInvalidField)
			require.ErrorContains(t, err, target)
			assert.Contains(t, err.Error(), "SUMMARY")
			assertArchEmpty(t, workdir, "x86_64")
		}
	})

	t.Run("non-regular entry", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		link := filepath.Join(filepath.Dir(file), "link")
		require.NoError(t, os.Symlink(file, link))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorContains(t, err, "not a regular file")
		assertArchEmpty(t, workdir, "x86_64")
	})

	t.Run("empty pool builds nothing", func(t *testing.T) {
		workdir := initWorkdir(t)
		stray := filepath.Join(workdir, "public", "pool", "9", "README")
		require.NoError(t, os.MkdirAll(filepath.Dir(stray), 0o755))
		require.NoError(t, os.WriteFile(stray, nil, 0o644))

		summaries, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Empty(t, summaries)
		assertArchEmpty(t, workdir, "x86_64")
		assertArchEmpty(t, workdir, "aarch64")
	})

	t.Run("deb workdir refused", func(t *testing.T) {
		workdir := initWorkdir(t)
		require.NoError(t, os.Mkdir(filepath.Join(workdir, "public", "dists"), 0o755))

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrDebWorkdir)
	})

	t.Run("creates arch directories", func(t *testing.T) {
		workdir := initWorkdir(t)
		require.NoError(t, os.Remove(filepath.Join(workdir, "public", "x86_64")))
		require.NoError(t, os.Remove(filepath.Join(workdir, "public", "aarch64")))

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.DirExists(t, filepath.Join(workdir, "public", "x86_64"))
		assert.DirExists(t, filepath.Join(workdir, "public", "aarch64"))
	})

	t.Run("arch directory that is not a directory", func(t *testing.T) {
		t.Run("symlink to a directory", func(t *testing.T) {
			f := newUploadFixture(t)
			src := f.put(t, "8/main/x.rpm", rpmBytes(t, basePkg()))

			shared := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(shared, "other", "sub"), 0o755))

			link := filepath.Join(f.workdir, "public", "x86_64")
			require.NoError(t, os.Remove(link))
			require.NoError(t, os.Symlink(shared, link))

			_, err := Build(t.Context(), f.workdir, buildTime)
			require.ErrorContains(t, err, "is not a directory")
			assert.DirExists(t, filepath.Join(shared, "other", "sub"))
			assert.FileExists(t, src)
			assert.NoDirExists(t, filepath.Join(f.workdir, "public", "pool"))
		})

		t.Run("regular file", func(t *testing.T) {
			workdir := initWorkdir(t)
			file := filepath.Join(workdir, "public", "aarch64")
			require.NoError(t, os.Remove(file))
			require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

			_, err := Build(t.Context(), workdir, buildTime)
			require.ErrorContains(t, err, "is not a directory")
		})
	})

	t.Run("unparsable signing key leaves the upload in place", func(t *testing.T) {
		f := newUploadFixture(t)
		src := f.put(t, "8/main/x.rpm", rpmBytes(t, basePkg()))
		require.NoError(t, os.WriteFile(filepath.Join(f.workdir, "config", "signing.asc"), []byte("not a key"), 0o600))

		_, err := Build(t.Context(), f.workdir, buildTime)
		require.ErrorContains(t, err, "derive public key from")
		assert.FileExists(t, src)
		assert.NoDirExists(t, filepath.Join(f.workdir, "public", "pool"))
	})

	t.Run("not initialized", func(t *testing.T) {
		_, err := Build(t.Context(), t.TempDir(), buildTime)
		require.ErrorIs(t, err, repofs.ErrNotInitialized)
	})
}

// cacheKey is the pool path of file, the key build and add use in the cache.
func cacheKey(t *testing.T, workdir, file string) string {
	t.Helper()

	rel, err := filepath.Rel(filepath.Join(workdir, "public"), file)
	require.NoError(t, err)

	return filepath.ToSlash(rel)
}

// editCache changes the entry of key in the saved cache.
func editCache(t *testing.T, workdir, key string, edit func(t *testing.T, e *cacheEntry)) {
	t.Helper()

	cache, err := repofs.LoadCache[cacheEntry](workdir)
	require.NoError(t, err)

	entry, ok := cache[key]
	require.True(t, ok)

	edit(t, &entry)
	cache[key] = entry
	require.NoError(t, repofs.SaveCache(workdir, cache))
}

func primarySummary(t *testing.T, workdir string) string {
	t.Helper()

	got := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
	require.Len(t, got.primary.Package, 1)
	require.NotNil(t, got.primary.Package[0].Summary)

	return *got.primary.Package[0].Summary
}

func TestBuildCache(t *testing.T) {
	const stale = "stale summary"

	setStale := func(t *testing.T, e *cacheEntry) {
		editPackage(t, e, func(p *rpmfile.Package) { p.Summary = stale })
	}

	t.Run("reuses a matching entry", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		key := cacheKey(t, workdir, file)
		editCache(t, workdir, key, setStale)

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Equal(t, stale, primarySummary(t, workdir))
		assert.NotContains(t, logs.String(), "msg=parsed")

		touched := buildTime.Add(-time.Hour)
		require.NoError(t, os.Chtimes(file, touched, touched))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Empty(t, primarySummary(t, workdir))
		assert.Contains(t, logs.String(), fmt.Sprintf("msg=parsed path=public/%s\n", key))

		info, err := os.Stat(file)
		require.NoError(t, err)

		cache, err := repofs.LoadCache[cacheEntry](workdir)
		require.NoError(t, err)
		assert.Equal(t, info.ModTime().UnixNano(), cache[key].MTime)
	})

	for _, tt := range mismatches {
		t.Run(fmt.Sprintf("parses again on %s", tt.name), func(t *testing.T) {
			workdir := initWorkdir(t)
			key := cacheKey(t, workdir, addPkg(t, workdir, "9/main", basePkg()))
			editCache(t, workdir, key, func(t *testing.T, e *cacheEntry) {
				setStale(t, e)
				tt.edit(t, e)
			})

			logs := captureLogs(t)

			_, err := Build(t.Context(), workdir, buildTime)
			require.NoError(t, err)
			assert.Empty(t, primarySummary(t, workdir))
			assert.Contains(t, logs.String(), fmt.Sprintf("msg=parsed path=public/%s\n", key))
		})
	}

	t.Run("drops entries of deleted files", func(t *testing.T) {
		workdir := initWorkdir(t)
		keep := cacheKey(t, workdir, addPkg(t, workdir, "9/main", basePkg()))

		other := basePkg()
		other.Name = "other"
		gone := addPkg(t, workdir, "9/main", other)
		goneKey := cacheKey(t, workdir, gone)
		require.NoError(t, os.Remove(gone))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Contains(t, logs.String(), fmt.Sprintf("msg=\"cache dropped\" path=public/%s\n", goneKey))
		assert.NotContains(t, logs.String(), "msg=parsed")

		cache, err := repofs.LoadCache[cacheEntry](workdir)
		require.NoError(t, err)
		assert.Len(t, cache, 1)
		assert.Contains(t, cache, keep)
	})

	t.Run("invalid cache file is ignored", func(t *testing.T) {
		workdir := initWorkdir(t)
		key := cacheKey(t, workdir, addPkg(t, workdir, "9/main", basePkg()))
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "cache", "index.json"), []byte("{bad"), 0o644))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Contains(t, logs.String(), fmt.Sprintf("msg=parsed path=public/%s\n", key))

		cache, err := repofs.LoadCache[cacheEntry](workdir)
		require.NoError(t, err)
		assert.Contains(t, cache, key)
	})

	t.Run("cached package keeps the pool checks", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		key := cacheKey(t, workdir, file)
		editCache(t, workdir, key, func(t *testing.T, e *cacheEntry) {
			editPackage(t, e, func(p *rpmfile.Package) { p.Arch = "aarch64" })
		})

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, ErrMisplaced)
	})

	t.Run("cached package keeps the text checks", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		key := cacheKey(t, workdir, file)
		editCache(t, workdir, key, func(t *testing.T, e *cacheEntry) {
			editPackage(t, e, func(p *rpmfile.Package) { p.Summary = "a\x01b" })
		})

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		require.ErrorContains(t, err, file)
		assertArchEmpty(t, workdir, "x86_64")
	})

	t.Run("cached control byte in converted text is refused", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		key := cacheKey(t, workdir, file)
		editCache(t, workdir, key, func(t *testing.T, e *cacheEntry) {
			editPackage(t, e, func(p *rpmfile.Package) { p.Summary = "\xe9\x01" })
		})

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		assertArchEmpty(t, workdir, "x86_64")
	})

	t.Run("pool control byte in converted text is refused", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		require.NoError(t, os.Remove(filepath.Join(workdir, "cache", "index.json")))

		data, err := rpmtest.Build(func() rpmtest.Package {
			p := basePkg()
			p.Tags = []rpmtest.Tag{{ID: 1004, Type: 6, Value: "\xe9\x01"}}

			return p
		}())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(file, data, 0o644))

		_, err = Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		assertArchEmpty(t, workdir, "x86_64")
	})

	t.Run("cached epoch 0 is written as 0", func(t *testing.T) {
		workdir := initWorkdir(t)
		zero := uint32(0)
		p := basePkg()
		p.Epoch = &zero
		addPkg(t, workdir, "9/main", p)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		got := readRepo(t, workdir, filepath.Join(workdir, "public", "x86_64", "9", "main"))
		require.Len(t, got.primary.Package, 1)
		assert.Equal(t, "0", got.primary.Package[0].Version.Epoch)
	})

	t.Run("version 1 cache is dropped", func(t *testing.T) {
		workdir := initWorkdir(t)
		key := cacheKey(t, workdir, addPkg(t, workdir, "9/main", basePkg()))

		v1 := fmt.Sprintf(`{"%s":{"version":1,"size":1,"mtime":1,"package":{"name":"pdns","summary":"stale"}}}`, key)
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "cache", "index.json"), []byte(v1), 0o644))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Empty(t, primarySummary(t, workdir))
		assert.Contains(t, logs.String(), fmt.Sprintf("msg=parsed path=public/%s\n", key))
	})

	t.Run("cached loose UTF-8 text is refused", func(t *testing.T) {
		workdir := initWorkdir(t)
		file := addPkg(t, workdir, "9/main", basePkg())
		key := cacheKey(t, workdir, file)
		editCache(t, workdir, key, func(t *testing.T, e *cacheEntry) {
			editPackage(t, e, func(p *rpmfile.Package) { p.Summary = "\xc1\x81" })
		})

		_, err := Build(t.Context(), workdir, buildTime)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		require.ErrorContains(t, err, file)
		assertArchEmpty(t, workdir, "x86_64")
	})
}

// assertArchEmpty checks that a failed or empty build left public/<arch>/ without any repository.
func assertArchEmpty(t *testing.T, workdir, arch string) {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(workdir, "public", arch))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// mtimes returns the modification time of every file under root.
func mtimes(t *testing.T, root string) map[string]time.Time {
	t.Helper()

	out := make(map[string]time.Time)

	require.NoError(t, filepath.WalkDir(root, func(file string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		out[file] = info.ModTime()

		return nil
	}))

	return out
}

func revision(t *testing.T, repoDir string) int64 {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repoDir, "repodata", "repomd.xml"))
	require.NoError(t, err)

	var md gotRepomd
	require.NoError(t, xml.Unmarshal(data, &md))

	return md.Revision
}

func TestBuildCurrent(t *testing.T) {
	later := buildTime.Add(time.Hour)

	setup := func(t *testing.T) (workdir, repoDir string) {
		t.Helper()

		workdir = initWorkdir(t)
		addPkg(t, workdir, "9/main", basePkg())

		_, err := Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)

		return workdir, filepath.Join(workdir, "public", "x86_64", "9", "main")
	}

	t.Run("unchanged build writes nothing", func(t *testing.T) {
		workdir, repoDir := setup(t)
		before := mtimes(t, filepath.Join(workdir, "public"))
		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, later)
		require.NoError(t, err)
		assert.Empty(t, logs.String())
		assert.Equal(t, before, mtimes(t, filepath.Join(workdir, "public")))
		assert.Equal(t, buildTime.Unix(), revision(t, repoDir))
	})

	t.Run("key.asc", func(t *testing.T) {
		workdir, _ := setup(t)
		keyFile := filepath.Join(workdir, "public", "key.asc")

		want, err := os.ReadFile(keyFile)
		require.NoError(t, err)

		logs := captureLogs(t)

		require.NoError(t, os.Remove(keyFile))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Contains(t, logs.String(), "msg=created path=public/key.asc\n")
		assert.Equal(t, 1, strings.Count(logs.String(), "\n"))

		got, err := os.ReadFile(keyFile)
		require.NoError(t, err)
		assert.Equal(t, want, got)

		logs.Reset()
		require.NoError(t, os.WriteFile(keyFile, []byte("edited"), 0o644))

		_, err = Build(t.Context(), workdir, buildTime)
		require.NoError(t, err)
		assert.Contains(t, logs.String(), "msg=updated path=public/key.asc\n")

		got, err = os.ReadFile(keyFile)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("rewrites", func(t *testing.T) {
		cases := map[string]func(t *testing.T, workdir, repoDir string){
			"tampered signature": func(t *testing.T, _, repoDir string) {
				require.NoError(t, os.WriteFile(filepath.Join(repoDir, "repodata", "repomd.xml.asc"), []byte("tampered"), 0o644))
			},
			"edited repomd": func(t *testing.T, _, repoDir string) {
				file := filepath.Join(repoDir, "repodata", "repomd.xml")

				data, err := os.ReadFile(file)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(file, append(data, '\n'), 0o644))
			},
			"deleted metadata file": func(t *testing.T, _, repoDir string) {
				matches, err := filepath.Glob(filepath.Join(repoDir, "repodata", "*-primary.xml.gz"))
				require.NoError(t, err)
				require.Len(t, matches, 1)
				require.NoError(t, os.Remove(matches[0]))
			},
			"changed signing key": func(t *testing.T, workdir, _ string) {
				key, err := pgpsign.GenerateKey("Other", "other@example.com")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(workdir, "config", "signing.asc"), key.Private, 0o600))
			},
		}

		for name, tamper := range cases {
			t.Run(name, func(t *testing.T) {
				workdir, repoDir := setup(t)
				tamper(t, workdir, repoDir)

				logs := captureLogs(t)

				_, err := Build(t.Context(), workdir, later)
				require.NoError(t, err)
				assert.Contains(t, logs.String(), "msg=updated path=public/x86_64/9/main/repodata/repomd.xml.asc\n")
				assert.Contains(t, logs.String(), "msg=updated path=public/x86_64/9/main/repodata/repomd.xml\n")
				assert.Equal(t, later.Unix(), revision(t, repoDir))
			})
		}
	})

	t.Run("write order", func(t *testing.T) {
		workdir, repoDir := setup(t)
		require.NoError(t, os.Remove(filepath.Join(workdir, "public", "key.asc")))
		require.NoError(t, os.RemoveAll(filepath.Join(repoDir, "repodata")))

		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, later)
		require.NoError(t, err)

		var got []string

		for line := range strings.Lines(logs.String()) {
			_, msg, _ := strings.Cut(strings.TrimSpace(line), "msg=")
			got = append(got, msg)
		}

		const prefix string = "added path=public/x86_64/9/main/repodata/"

		require.Len(t, got, 6)
		assert.Equal(t, "created path=public/key.asc", got[0])
		assert.True(t, strings.HasPrefix(got[1], prefix) && strings.HasSuffix(got[1], "-primary.xml.gz"), got[1])
		assert.True(t, strings.HasPrefix(got[2], prefix) && strings.HasSuffix(got[2], "-filelists.xml.gz"), got[2])
		assert.True(t, strings.HasPrefix(got[3], prefix) && strings.HasSuffix(got[3], "-other.xml.gz"), got[3])
		assert.Equal(t, "updated path=public/x86_64/9/main/repodata/repomd.xml.asc", got[4])
		assert.Equal(t, "updated path=public/x86_64/9/main/repodata/repomd.xml", got[5])
	})

	t.Run("repaired metadata file", func(t *testing.T) {
		damage := map[string]func(t *testing.T, file string){
			"symlink": func(t *testing.T, file string) {
				data, err := os.ReadFile(file)
				require.NoError(t, err)

				copied := filepath.Join(t.TempDir(), "copy.gz")
				require.NoError(t, os.WriteFile(copied, data, 0o644))
				require.NoError(t, os.Remove(file))
				require.NoError(t, os.Symlink(copied, file))
			},
			"other bytes": func(t *testing.T, file string) {
				require.NoError(t, os.WriteFile(file, []byte("other bytes"), 0o644))
			},
		}

		for name, f := range damage {
			t.Run(name, func(t *testing.T) {
				workdir, repoDir := setup(t)

				matches, err := filepath.Glob(filepath.Join(repoDir, "repodata", "*-primary.xml.gz"))
				require.NoError(t, err)
				require.Len(t, matches, 1)

				want, err := os.ReadFile(matches[0])
				require.NoError(t, err)

				f(t, matches[0])

				logs := captureLogs(t)

				_, err = Build(t.Context(), workdir, later)
				require.NoError(t, err)
				assert.Equal(t, 1, strings.Count(logs.String(), "msg=added"))
				assert.Equal(t, 2, strings.Count(logs.String(), "msg=updated"))

				info, err := os.Lstat(matches[0])
				require.NoError(t, err)
				assert.True(t, info.Mode().IsRegular())

				got, err := os.ReadFile(matches[0])
				require.NoError(t, err)
				assert.Equal(t, want, got)

				logs.Reset()

				_, err = Build(t.Context(), workdir, later.Add(time.Hour))
				require.NoError(t, err)
				assert.Empty(t, logs.String())
			})
		}
	})

	t.Run("directory in place of a metadata file", func(t *testing.T) {
		workdir, repoDir := setup(t)

		matches, err := filepath.Glob(filepath.Join(repoDir, "repodata", "*-primary.xml.gz"))
		require.NoError(t, err)
		require.Len(t, matches, 1)
		require.NoError(t, os.Remove(matches[0]))
		require.NoError(t, os.Mkdir(matches[0], 0o755))

		_, err = Build(t.Context(), workdir, later)
		require.Error(t, err)
		assert.Contains(t, err.Error(), matches[0])
	})

	t.Run("failed repomd.xml.asc rename leaves the old pair and no temp file", func(t *testing.T) {
		workdir, repoDir := setup(t)
		repodata := filepath.Join(repoDir, "repodata")
		oldXML, err := os.ReadFile(filepath.Join(repodata, "repomd.xml"))
		require.NoError(t, err)

		ascPath := filepath.Join(repodata, "repomd.xml.asc")
		require.NoError(t, os.Remove(ascPath))
		require.NoError(t, os.MkdirAll(filepath.Join(ascPath, "sub"), 0o755))

		other := basePkg()
		other.Name = "other"
		addPkg(t, workdir, "9/main", other)

		_, err = Build(t.Context(), workdir, later)
		require.ErrorContains(t, err, "repomd.xml.asc")

		newXML, err := os.ReadFile(filepath.Join(repodata, "repomd.xml"))
		require.NoError(t, err)
		assert.Equal(t, oldXML, newXML)

		temps, err := filepath.Glob(filepath.Join(repodata, ".build-*"))
		require.NoError(t, err)
		assert.Empty(t, temps)
	})

	t.Run("unparsable signing key", func(t *testing.T) {
		workdir, _ := setup(t)
		require.NoError(t, os.WriteFile(filepath.Join(workdir, "config", "signing.asc"), []byte("not a key"), 0o600))

		before := mtimes(t, filepath.Join(workdir, "public"))

		_, err := Build(t.Context(), workdir, later)
		require.ErrorContains(t, err, "derive public key from")
		assert.Equal(t, before, mtimes(t, filepath.Join(workdir, "public")))
	})

	t.Run("added package changes the revision", func(t *testing.T) {
		workdir, repoDir := setup(t)

		other := basePkg()
		other.Name = "other"
		addPkg(t, workdir, "9/main", other)

		_, err := Build(t.Context(), workdir, later)
		require.NoError(t, err)
		assert.Equal(t, later.Unix(), revision(t, repoDir))
	})

	t.Run("tampered signature keeps the metadata files", func(t *testing.T) {
		workdir, repoDir := setup(t)
		repodata := filepath.Join(repoDir, "repodata")
		require.NoError(t, os.WriteFile(filepath.Join(repodata, "repomd.xml.asc"), []byte("tampered"), 0o644))

		before := mtimes(t, repodata)
		logs := captureLogs(t)

		_, err := Build(t.Context(), workdir, later)
		require.NoError(t, err)
		assert.Equal(t, 2, strings.Count(logs.String(), "msg=updated"))
		assert.NotContains(t, logs.String(), "msg=added")

		after := mtimes(t, repodata)

		for file, mtime := range before {
			if filepath.Base(file) == "repomd.xml.asc" || filepath.Base(file) == "repomd.xml" {
				continue
			}

			assert.Equal(t, mtime, after[file], file)
		}

		assert.Equal(t, later.Unix(), revision(t, repoDir))
	})
}

func BenchmarkBuild(b *testing.B) {
	workdir := b.TempDir()
	require.NoError(b, Init(b.Context(), workdir, "Test", ""))

	data, err := rpmtest.Build(basePkg())
	require.NoError(b, err)

	src := filepath.Join(b.TempDir(), "in.rpm")
	require.NoError(b, os.WriteFile(src, data, 0o644))

	_, err = Add(workdir, "9", "main", src)
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		_, err := Build(b.Context(), workdir, buildTime)
		require.NoError(b, err)
	}
}

package rpmrepo

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

type gotVersion struct {
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type gotChecksum struct {
	Type  string `xml:"type,attr"`
	PkgID string `xml:"pkgid,attr"`
	Value string `xml:",chardata"`
}

type gotHref struct {
	Href string `xml:"href,attr"`
}

type gotPrimary struct {
	XMLName  xml.Name
	Packages int `xml:"packages,attr"`
	Package  []struct {
		Type        string      `xml:"type,attr"`
		Name        string      `xml:"name"`
		Arch        string      `xml:"arch"`
		Version     gotVersion  `xml:"version"`
		Checksum    gotChecksum `xml:"checksum"`
		Summary     *string     `xml:"summary"`
		Description *string     `xml:"description"`
		Packager    *string     `xml:"packager"`
		URL         *string     `xml:"url"`
		Time        struct {
			File  int64 `xml:"file,attr"`
			Build int64 `xml:"build,attr"`
		} `xml:"time"`
		Size struct {
			Package   int64 `xml:"package,attr"`
			Installed int64 `xml:"installed,attr"`
			Archive   int64 `xml:"archive,attr"`
		} `xml:"size"`
		Location gotHref `xml:"location"`
		Format   struct {
			License     *string `xml:"http://linux.duke.edu/metadata/rpm license"`
			Vendor      *string `xml:"http://linux.duke.edu/metadata/rpm vendor"`
			Group       *string `xml:"http://linux.duke.edu/metadata/rpm group"`
			BuildHost   *string `xml:"http://linux.duke.edu/metadata/rpm buildhost"`
			SourceRPM   string  `xml:"http://linux.duke.edu/metadata/rpm sourcerpm"`
			HeaderRange struct {
				Start int64 `xml:"start,attr"`
				End   int64 `xml:"end,attr"`
			} `xml:"http://linux.duke.edu/metadata/rpm header-range"`
			Provides    *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm provides"`
			Requires    *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm requires"`
			Conflicts   *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm conflicts"`
			Obsoletes   *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm obsoletes"`
			Recommends  *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm recommends"`
			Suggests    *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm suggests"`
			Supplements *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm supplements"`
			Enhances    *gotDeps  `xml:"http://linux.duke.edu/metadata/rpm enhances"`
			Files       []gotFile `xml:"file"`
		} `xml:"format"`
	} `xml:"package"`
}

type gotEntry struct {
	Name  string `xml:"name,attr"`
	Flags string `xml:"flags,attr"`
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
	Pre   string `xml:"pre,attr"`
}

type gotDeps struct {
	Entry []gotEntry `xml:"http://linux.duke.edu/metadata/rpm entry"`
}

type gotFile struct {
	Type string `xml:"type,attr"`
	Path string `xml:",chardata"`
}

type gotList struct {
	XMLName  xml.Name
	Packages int `xml:"packages,attr"`
	Package  []struct {
		PkgID     string         `xml:"pkgid,attr"`
		Name      string         `xml:"name,attr"`
		Arch      string         `xml:"arch,attr"`
		Version   gotVersion     `xml:"version"`
		Files     []gotFile      `xml:"file"`
		Changelog []gotChangelog `xml:"changelog"`
	} `xml:"package"`
}

type gotChangelog struct {
	Author string `xml:"author,attr"`
	Date   int64  `xml:"date,attr"`
	Text   string `xml:",chardata"`
}

type gotRepomd struct {
	XMLName  xml.Name
	Revision int64 `xml:"revision"`
	Data     []struct {
		Type         string      `xml:"type,attr"`
		Checksum     gotChecksum `xml:"checksum"`
		OpenChecksum gotChecksum `xml:"open-checksum"`
		Location     gotHref     `xml:"location"`
		Timestamp    int64       `xml:"timestamp"`
		Size         int         `xml:"size"`
		OpenSize     int         `xml:"open-size"`
	} `xml:"data"`
}

func gunzip(t testing.TB, data []byte) []byte {
	t.Helper()

	r, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	return out
}

func samplePackage() repoPackage {
	epoch := uint32(2)

	return repoPackage{
		pkg: rpmfile.Package{
			Name:        "pdns",
			Version:     "5.1.0",
			Release:     "1.el9",
			Arch:        "x86_64",
			SourceRPM:   "pdns-5.1.0-1.el9.src.rpm",
			Epoch:       &epoch,
			HeaderStart: 200,
			HeaderEnd:   400,
			Size:        1000,
			SHA256:      strings.Repeat("a", 64),
		},
		path:  "pool/9/main/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm",
		mtime: 1700000000,
	}
}

func TestRenderPrimary(t *testing.T) {
	t.Run("prefixed names and namespaces", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{samplePackage()})
		require.NoError(t, err)

		out := string(data)
		assert.True(t, strings.HasPrefix(out, xml.Header))
		assert.Contains(t, out, `<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">`)
		assert.Contains(t, out, "<rpm:sourcerpm>pdns-5.1.0-1.el9.src.rpm</rpm:sourcerpm>")
		assert.Contains(t, out, `<rpm:header-range start="200" end="400">`)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Equal(t, xml.Name{Space: nsCommon, Local: "metadata"}, got.XMLName)
		require.Len(t, got.Package, 1)
		assert.Equal(t, gotVersion{Epoch: "2", Ver: "5.1.0", Rel: "1.el9"}, got.Package[0].Version)
		assert.Equal(t, "../../../pool/9/main/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm", got.Package[0].Location.Href)
	})

	t.Run("no epoch is zero", func(t *testing.T) {
		p := samplePackage()
		p.pkg.Epoch = nil

		data, err := renderPrimary([]repoPackage{p})
		require.NoError(t, err)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Equal(t, "0", got.Package[0].Version.Epoch)
	})

	t.Run("descriptive fields and sizes", func(t *testing.T) {
		p := samplePackage()
		p.pkg.Summary = "summary"
		p.pkg.Description = "line one\nline two"
		p.pkg.Packager = "packager"
		p.pkg.URL = "http://example.com/"
		p.pkg.License = "GPLv2+"
		p.pkg.Vendor = "vendor"
		p.pkg.Group = "Applications/File"
		p.pkg.BuildHost = "host"
		p.pkg.BuildTime = 0xfffffffe
		p.pkg.InstalledSize = 1 << 40
		p.pkg.ArchiveSize = 1 << 33

		data, err := renderPrimary([]repoPackage{p})
		require.NoError(t, err)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		require.Len(t, got.Package, 1)

		pkg := got.Package[0]
		for want, value := range map[string]*string{
			"summary":             pkg.Summary,
			"line one\nline two":  pkg.Description,
			"packager":            pkg.Packager,
			"http://example.com/": pkg.URL,
			"GPLv2+":              pkg.Format.License,
			"vendor":              pkg.Format.Vendor,
			"Applications/File":   pkg.Format.Group,
			"host":                pkg.Format.BuildHost,
		} {
			require.NotNil(t, value, want)
			assert.Equal(t, want, *value)
		}

		assert.Equal(t, int64(1700000000), pkg.Time.File)
		assert.Equal(t, int64(0xfffffffe), pkg.Time.Build)
		assert.Equal(t, int64(1000), pkg.Size.Package)
		assert.Equal(t, int64(1<<40), pkg.Size.Installed)
		assert.Equal(t, int64(1<<33), pkg.Size.Archive)
	})

	t.Run("sizes are written as signed 64-bit numbers", func(t *testing.T) {
		p := samplePackage()
		p.pkg.InstalledSize = 1 << 63
		p.pkg.ArchiveSize = 1<<64 - 1

		data, err := renderPrimary([]repoPackage{p})
		require.NoError(t, err)
		assert.Contains(t, string(data), `<size package="1000" installed="-9223372036854775808" archive="-1"></size>`)
	})

	t.Run("element order", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{samplePackage()})
		require.NoError(t, err)

		var names []string

		dec := xml.NewDecoder(bytes.NewReader(data))

		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}

			require.NoError(t, err)

			if start, ok := tok.(xml.StartElement); ok {
				names = append(names, fmt.Sprintf("%s %s", start.Name.Space, start.Name.Local))
			}
		}

		assert.Equal(t, []string{
			"http://linux.duke.edu/metadata/common metadata",
			"http://linux.duke.edu/metadata/common package",
			"http://linux.duke.edu/metadata/common name",
			"http://linux.duke.edu/metadata/common arch",
			"http://linux.duke.edu/metadata/common version",
			"http://linux.duke.edu/metadata/common checksum",
			"http://linux.duke.edu/metadata/common summary",
			"http://linux.duke.edu/metadata/common description",
			"http://linux.duke.edu/metadata/common packager",
			"http://linux.duke.edu/metadata/common url",
			"http://linux.duke.edu/metadata/common time",
			"http://linux.duke.edu/metadata/common size",
			"http://linux.duke.edu/metadata/common location",
			"http://linux.duke.edu/metadata/common format",
			"http://linux.duke.edu/metadata/rpm license",
			"http://linux.duke.edu/metadata/rpm vendor",
			"http://linux.duke.edu/metadata/rpm group",
			"http://linux.duke.edu/metadata/rpm buildhost",
			"http://linux.duke.edu/metadata/rpm sourcerpm",
			"http://linux.duke.edu/metadata/rpm header-range",
		}, names)
	})

	t.Run("empty elements are written", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{samplePackage()})
		require.NoError(t, err)

		out := string(data)
		for _, el := range []string{"summary", "description", "packager", "url", "rpm:license", "rpm:vendor", "rpm:group", "rpm:buildhost"} {
			assert.Contains(t, out, fmt.Sprintf("<%s></%s>", el, el))
		}

		assert.Contains(t, out, `<time file="1700000000" build="0"></time>`)
		assert.Contains(t, out, `<size package="1000" installed="0" archive="0"></size>`)
	})

	t.Run("empty", func(t *testing.T) {
		data, err := renderPrimary(nil)
		require.NoError(t, err)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Zero(t, got.Packages)
		assert.Empty(t, got.Package)
	})
}

func renderDeps(t *testing.T, mut func(*rpmfile.Package)) (string, gotPrimary) {
	t.Helper()

	p := samplePackage()
	mut(&p.pkg)

	data, err := renderPrimary([]repoPackage{p})
	require.NoError(t, err)

	var got gotPrimary
	require.NoError(t, xml.Unmarshal(data, &got))
	require.Len(t, got.Package, 1)

	return string(data), got
}

func TestRenderDependencies(t *testing.T) {
	requires := func(deps ...rpmfile.Dep) func(*rpmfile.Package) {
		return func(p *rpmfile.Package) { p.Requires = deps }
	}

	t.Run("flags", func(t *testing.T) {
		tests := []struct {
			flags uint32
			want  string
		}{
			{8, "EQ"},
			{2, "LT"},
			{4, "GT"},
			{10, "LE"},
			{12, "GE"},
			{0, ""},
			{6, ""},
			{14, ""},
			{9, ""},
			{8 | 1<<12, "EQ"},
		}

		for _, tt := range tests {
			t.Run(tt.want, func(t *testing.T) {
				_, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: tt.flags, Version: "1.2-3"}))
				e := got.Package[0].Format.Requires.Entry[0]

				assert.Equal(t, tt.want, e.Flags)

				if tt.want == "" {
					assert.Equal(t, gotEntry{Name: "x"}, e)
					return
				}

				assert.Equal(t, gotEntry{Name: "x", Flags: tt.want, Epoch: "0", Ver: "1.2", Rel: "3"}, e)
			})
		}
	})

	t.Run("version split", func(t *testing.T) {
		tests := []struct {
			version string
			want    gotEntry
		}{
			{"1.2-3", gotEntry{Epoch: "0", Ver: "1.2", Rel: "3"}},
			{"4:1.2-3", gotEntry{Epoch: "4", Ver: "1.2", Rel: "3"}},
			{"0:1.2", gotEntry{Epoch: "0", Ver: "1.2"}},
			{"1.2", gotEntry{Epoch: "0", Ver: "1.2"}},
			{"1.2-3-4", gotEntry{Epoch: "0", Ver: "1.2", Rel: "3-4"}},
			{"1:2-3-4-5", gotEntry{Epoch: "1", Ver: "2", Rel: "3-4-5"}},
			{"1:2:3-4", gotEntry{Epoch: "1", Ver: "2:3", Rel: "4"}},
			{"", gotEntry{}},
			{":1", gotEntry{Epoch: "0", Ver: "1"}},
			{"-1:1", gotEntry{Epoch: "-1", Ver: "1"}},
			{" 1:1", gotEntry{Epoch: " 1", Ver: "1"}},
			{"+1:1", gotEntry{Epoch: "+1", Ver: "1"}},
			{"1:-2", gotEntry{Epoch: "1", Rel: "2"}},
			{"1.0-", gotEntry{Epoch: "0", Ver: "1.0"}},
		}

		for _, tt := range tests {
			t.Run(tt.version, func(t *testing.T) {
				_, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: 8, Version: tt.version}))

				want := tt.want
				want.Name = "x"
				want.Flags = "EQ"

				assert.Equal(t, []gotEntry{want}, got.Package[0].Format.Requires.Entry)
			})
		}
	})

	t.Run("bad epoch drops the dependency whatever its flags", func(t *testing.T) {
		for _, flags := range []uint32{8, 0, 9} {
			for _, version := range []string{"a:1", "x:1", " :1", "1a:1-2"} {
				out, got := renderDeps(t, requires(rpmfile.Dep{Name: "bad", Flags: flags, Version: version}, rpmfile.Dep{Name: "good"}))
				assert.NotContains(t, out, "bad", version)
				assert.Equal(t, []gotEntry{{Name: "good"}}, got.Package[0].Format.Requires.Entry, version)
			}
		}
	})

	t.Run("flags without a version", func(t *testing.T) {
		_, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: 8}))
		assert.Equal(t, []gotEntry{{Name: "x", Flags: "EQ"}}, got.Package[0].Format.Requires.Entry)
	})

	t.Run("no flags string hides the version", func(t *testing.T) {
		out, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: 9, Version: "1:2-3"}))
		assert.Equal(t, []gotEntry{{Name: "x"}}, got.Package[0].Format.Requires.Entry)
		assert.Contains(t, out, `<rpm:entry name="x"></rpm:entry>`)
	})

	t.Run("pre", func(t *testing.T) {
		tests := []struct {
			name  string
			flags uint32
			want  string
		}{
			{"none", 0, ""},
			{"prereq", 1 << 6, "1"},
			{"script pre", 1 << 9, "1"},
			{"script post", 1 << 10, "1"},
			{"other bits", 1<<7 | 1<<8, ""},
			{"with version", 8 | 1<<9, "1"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: tt.flags}))
				assert.Equal(t, tt.want, got.Package[0].Format.Requires.Entry[0].Pre)
			})
		}

		t.Run("not for provides", func(t *testing.T) {
			out, _ := renderDeps(t, func(p *rpmfile.Package) { p.Provides = []rpmfile.Dep{{Name: "x", Flags: 1 << 6}} })
			assert.NotContains(t, out, "pre=")
		})

		t.Run("not for requires moved to recommends", func(t *testing.T) {
			out, got := renderDeps(t, requires(rpmfile.Dep{Name: "x", Flags: 1<<6 | 1<<19}))
			assert.NotContains(t, out, "pre=")
			assert.Nil(t, got.Package[0].Format.Requires)
			assert.Equal(t, []gotEntry{{Name: "x"}}, got.Package[0].Format.Recommends.Entry)
		})
	})

	t.Run("rpmlib requires are dropped", func(t *testing.T) {
		out, got := renderDeps(t, requires(rpmfile.Dep{Name: "rpmlib(PayloadIsXz)", Flags: 8, Version: "5.2-1"}, rpmfile.Dep{Name: "sh"}))
		assert.NotContains(t, out, "rpmlib(")
		assert.Equal(t, []gotEntry{{Name: "sh"}}, got.Package[0].Format.Requires.Entry)

		out, got = renderDeps(t, requires(rpmfile.Dep{Name: "rpmlib(X)"}))
		assert.NotContains(t, out, "requires")
		assert.Nil(t, got.Package[0].Format.Requires)

		out, _ = renderDeps(t, func(p *rpmfile.Package) { p.Provides = []rpmfile.Dep{{Name: "rpmlib(kept)"}} })
		assert.Contains(t, out, "rpmlib(kept)")
	})

	t.Run("empty names are skipped", func(t *testing.T) {
		out, got := renderDeps(t, requires(rpmfile.Dep{}, rpmfile.Dep{Name: "a"}, rpmfile.Dep{Flags: 8, Version: "1"}))
		assert.Equal(t, []gotEntry{{Name: "a"}}, got.Package[0].Format.Requires.Entry)
		assert.NotContains(t, out, `name=""`)
	})

	t.Run("all empty names give an empty container", func(t *testing.T) {
		out, got := renderDeps(t, func(p *rpmfile.Package) {
			p.Requires = []rpmfile.Dep{{}, {Flags: 8, Version: "1"}}
			p.Provides = []rpmfile.Dep{{}}
		})
		assert.Contains(t, out, "<rpm:requires></rpm:requires>")
		assert.Contains(t, out, "<rpm:provides></rpm:provides>")
		assert.NotContains(t, out, "<rpm:entry")
		require.NotNil(t, got.Package[0].Format.Requires)
		assert.Empty(t, got.Package[0].Format.Requires.Entry)
	})

	t.Run("order is kept and duplicates are dropped", func(t *testing.T) {
		_, got := renderDeps(t, requires(rpmfile.Dep{Name: "z"}, rpmfile.Dep{Name: "a"}, rpmfile.Dep{Name: "z"}, rpmfile.Dep{Name: "z", Flags: 1 << 9}))
		assert.Equal(t, []gotEntry{{Name: "z"}, {Name: "a"}, {Name: "z", Pre: "1"}}, got.Package[0].Format.Requires.Entry)
	})

	t.Run("libc.so.6 goes last", func(t *testing.T) {
		_, got := renderDeps(t, requires(
			rpmfile.Dep{Name: "libc.so.6()(64bit)"},
			rpmfile.Dep{Name: "libc.so.6(GLIBC_2.17)(64bit)"},
			rpmfile.Dep{Name: "a"},
		))
		assert.Equal(t, []gotEntry{{Name: "a"}, {Name: "libc.so.6(GLIBC_2.17)(64bit)"}}, got.Package[0].Format.Requires.Entry)
	})

	t.Run("empty kinds are omitted", func(t *testing.T) {
		out, got := renderDeps(t, func(*rpmfile.Package) {})
		assert.NotContains(t, out, "<rpm:provides")
		assert.NotContains(t, out, "<rpm:requires")
		assert.Nil(t, got.Package[0].Format.Provides)
	})

	t.Run("all kinds in order", func(t *testing.T) {
		dep := []rpmfile.Dep{{Name: "x", Flags: 2, Version: "1"}}
		out, got := renderDeps(t, func(p *rpmfile.Package) {
			p.Enhances = dep
			p.Supplements = dep
			p.Suggests = dep
			p.Recommends = dep
			p.Obsoletes = dep
			p.Conflicts = dep
			// The same entry in requires would match the provide and be dropped.
			p.Requires = dep
			p.Provides = []rpmfile.Dep{{Name: "x", Flags: 2, Version: "0:1"}}
		})

		last := strings.Index(out, "<rpm:header-range")
		require.Positive(t, last)

		for _, kind := range []string{"provides", "requires", "conflicts", "obsoletes", "suggests", "enhances", "recommends", "supplements"} {
			i := strings.Index(out, fmt.Sprintf("<rpm:%s>", kind))
			assert.Greater(t, i, last, kind)
			last = i
		}

		f := got.Package[0].Format
		for _, d := range []*gotDeps{f.Provides, f.Requires, f.Conflicts, f.Obsoletes, f.Recommends, f.Suggests, f.Supplements, f.Enhances} {
			require.NotNil(t, d)
			assert.Equal(t, []gotEntry{{Name: "x", Flags: "LT", Epoch: "0", Ver: "1"}}, d.Entry)
		}
	})
}

func TestRenderDependencyRawPresence(t *testing.T) {
	t.Run("attributes emptied by conversion are written", func(t *testing.T) {
		out, got := renderDeps(t, func(p *rpmfile.Package) {
			p.Requires = []rpmfile.Dep{{Name: "x", Flags: 8, Version: "1:\x80-\x80"}}
		})

		assert.Contains(t, out, `name="x" flags="EQ" epoch="1" ver="" rel=""`)
		assert.Equal(t, gotEntry{Name: "x", Flags: "EQ", Epoch: "1"}, got.Package[0].Format.Requires.Entry[0])
	})

	t.Run("version only", func(t *testing.T) {
		out, _ := renderDeps(t, func(p *rpmfile.Package) {
			p.Requires = []rpmfile.Dep{{Name: "x", Flags: 8, Version: "\x80"}}
		})

		assert.Contains(t, out, `name="x" flags="EQ" epoch="0" ver=""`)
		assert.NotContains(t, out, `ver="" rel=`)
	})

	t.Run("name of dropped bytes is written", func(t *testing.T) {
		out, _ := renderDeps(t, func(p *rpmfile.Package) {
			p.Requires = []rpmfile.Dep{{Name: "\x80"}}
		})

		assert.Contains(t, out, `<rpm:entry name=""></rpm:entry>`)
	})
}

func TestRenderList(t *testing.T) {
	for _, tt := range []struct {
		root, ns string
		files    bool
	}{{"filelists", nsFilelists, true}, {"otherdata", nsOther, false}} {
		t.Run(tt.root, func(t *testing.T) {
			data, err := renderList(tt.root, tt.ns, []repoPackage{samplePackage()}, tt.files)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(string(data), xml.Header))

			var got gotList
			require.NoError(t, xml.Unmarshal(data, &got))
			assert.Equal(t, xml.Name{Space: tt.ns, Local: tt.root}, got.XMLName)
			assert.Equal(t, 1, got.Packages)
			require.Len(t, got.Package, 1)
			assert.Equal(t, strings.Repeat("a", 64), got.Package[0].PkgID)
			assert.Equal(t, "pdns", got.Package[0].Name)
			assert.Equal(t, "x86_64", got.Package[0].Arch)
			assert.Equal(t, gotVersion{Epoch: "2", Ver: "5.1.0", Rel: "1.el9"}, got.Package[0].Version)
		})
	}
}

func fileListPackage(files []rpmfile.File) repoPackage {
	p := samplePackage()
	p.pkg.Files = files

	return p
}

func TestRenderFiles(t *testing.T) {
	files := []rpmfile.File{
		{Path: "/etc/x", Mode: 0o100644},
		{Path: "/usr/bin/x", Mode: 0o100755},
		{Path: "/usr/sbin/x", Mode: 0o100755},
		{Path: "/opt/foo/bin/x", Mode: 0o100755},
		{Path: "/usr/lib/sendmail", Mode: 0o100755},
		{Path: "/usr/lib/sendmail.x", Mode: 0o100644},
		{Path: "/usr/share/doc/x", Mode: 0o040755},
		{Path: "/etc/d", Mode: 0o040755},
		{Path: "/usr/bin/g", Mode: 0o100644, Flags: 1 << 6},
		{Path: "/usr/share/g", Mode: 0o100644, Flags: 1 << 6},
		{Path: "/usr/bin/gd", Mode: 0o040755, Flags: 1 << 6},
	}

	t.Run("primary keeps the subset in header order", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{fileListPackage(files)})
		require.NoError(t, err)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Equal(t, []gotFile{
			{Path: "/etc/x"},
			{Path: "/usr/bin/x"},
			{Path: "/usr/sbin/x"},
			{Path: "/opt/foo/bin/x"},
			{Path: "/usr/lib/sendmail"},
			{Type: "dir", Path: "/etc/d"},
			{Type: "ghost", Path: "/usr/bin/g"},
			{Type: "dir", Path: "/usr/bin/gd"},
		}, got.Package[0].Format.Files)

		out := string(data)
		assert.Greater(t, strings.Index(out, "<file"), strings.Index(out, "<rpm:header-range"))
		assert.Equal(t, 1, strings.Count(out, "<file>/etc/x</file>"))
	})

	t.Run("filelists has every file", func(t *testing.T) {
		data, err := renderList("filelists", nsFilelists, []repoPackage{fileListPackage(files)}, true)
		require.NoError(t, err)

		var got gotList
		require.NoError(t, xml.Unmarshal(data, &got))
		assert.Equal(t, []gotFile{
			{Path: "/etc/x"},
			{Path: "/usr/bin/x"},
			{Path: "/usr/sbin/x"},
			{Path: "/opt/foo/bin/x"},
			{Path: "/usr/lib/sendmail"},
			{Path: "/usr/lib/sendmail.x"},
			{Type: "dir", Path: "/usr/share/doc/x"},
			{Type: "dir", Path: "/etc/d"},
			{Type: "ghost", Path: "/usr/bin/g"},
			{Type: "ghost", Path: "/usr/share/g"},
			{Type: "dir", Path: "/usr/bin/gd"},
		}, got.Package[0].Files)

		out := string(data)
		assert.Greater(t, strings.Index(out, "<file>"), strings.Index(out, "<version"))
	})

	t.Run("other lists no files", func(t *testing.T) {
		data, err := renderList("otherdata", nsOther, []repoPackage{fileListPackage(files)}, false)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "<file")
	})

	t.Run("no files", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{samplePackage()})
		require.NoError(t, err)
		assert.NotContains(t, string(data), "<file")
	})
}

func TestRenderChangelog(t *testing.T) {
	p := samplePackage()
	p.pkg.Files = []rpmfile.File{{Path: "/usr/bin/pdns", Mode: 0o100755}}
	p.pkg.Changelog = []rpmfile.ChangelogEntry{
		{Time: 200, Author: "B <b@example.com> - 5.1.0-1 ", Text: "- new <release> & more"},
		{Time: 100, Author: "A <a@example.com> - 5.0.0-1", Text: "- first"},
	}

	t.Run("other has the kept entries after version", func(t *testing.T) {
		data, err := renderList("otherdata", nsOther, []repoPackage{p}, false)
		require.NoError(t, err)

		out := string(data)
		assert.Contains(t, out, `<changelog author="A &lt;a@example.com&gt; - 5.0.0-1" date="100">- first</changelog>`)
		assert.Contains(t, out, `<changelog author="B &lt;b@example.com&gt; - 5.1.0-1" date="200">- new &lt;release&gt; &amp; more</changelog>`)

		var names []string

		dec := xml.NewDecoder(bytes.NewReader(data))

		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}

			require.NoError(t, err)

			if start, ok := tok.(xml.StartElement); ok {
				names = append(names, start.Name.Local)
			}
		}

		assert.Equal(t, []string{"otherdata", "package", "version", "changelog", "changelog"}, names)

		var got gotList
		require.NoError(t, xml.Unmarshal(data, &got))
		require.Len(t, got.Package, 1)
		assert.Equal(t, []gotChangelog{
			{Author: "A <a@example.com> - 5.0.0-1", Date: 100, Text: "- first"},
			{Author: "B <b@example.com> - 5.1.0-1", Date: 200, Text: "- new <release> & more"},
		}, got.Package[0].Changelog)
	})

	t.Run("filelists has no changelog", func(t *testing.T) {
		data, err := renderList("filelists", nsFilelists, []repoPackage{p}, true)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "<changelog")
	})

	t.Run("primary has no changelog", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{p})
		require.NoError(t, err)
		assert.NotContains(t, string(data), "<changelog")
	})

	t.Run("no changelog", func(t *testing.T) {
		data, err := renderList("otherdata", nsOther, []repoPackage{samplePackage()}, false)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "<changelog")
	})
}

func TestRenderText(t *testing.T) {
	p := samplePackage()
	p.pkg.Summary = "caf\xe9"
	p.pkg.Description = "caf\xc3\xa9"
	p.pkg.Requires = []rpmfile.Dep{{Name: "lib\xe9", Flags: 8, Version: "1:v\xe9-r\xe9"}}
	p.pkg.Files = []rpmfile.File{{Path: "/usr/bin/\xe9", Mode: 0o100755}}
	p.pkg.Changelog = []rpmfile.ChangelogEntry{{Time: 1, Author: "\xe9 ", Text: "- \xe9"}}

	t.Run("Latin-1 is written as UTF-8", func(t *testing.T) {
		data, err := renderPrimary([]repoPackage{p})
		require.NoError(t, err)

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		require.Len(t, got.Package, 1)
		assert.Equal(t, "caf\xc3\xa9", *got.Package[0].Summary)
		assert.Equal(t, "caf\xc3\xa9", *got.Package[0].Description)
		assert.Equal(t, []gotEntry{{Name: "lib\xc3\xa9", Flags: "EQ", Epoch: "1", Ver: "v\xc3\xa9", Rel: "r\xc3\xa9"}}, got.Package[0].Format.Requires.Entry)
		assert.Equal(t, []gotFile{{Path: "/usr/bin/\xc3\xa9"}}, got.Package[0].Format.Files)

		data, err = renderList("filelists", nsFilelists, []repoPackage{p}, true)
		require.NoError(t, err)

		var files gotList
		require.NoError(t, xml.Unmarshal(data, &files))
		assert.Equal(t, []gotFile{{Path: "/usr/bin/\xc3\xa9"}}, files.Package[0].Files)

		data, err = renderList("otherdata", nsOther, []repoPackage{p}, false)
		require.NoError(t, err)

		var other gotList
		require.NoError(t, xml.Unmarshal(data, &other))
		assert.Equal(t, []gotChangelog{{Author: "\xc3\xa9", Date: 1, Text: "- \xc3\xa9"}}, other.Package[0].Changelog)
	})

	t.Run("filtering compares the raw strings", func(t *testing.T) {
		q := p
		q.pkg.Provides = []rpmfile.Dep{{Name: "lib\xe9", Flags: 8, Version: "1:v\xe9-r\xe9"}}
		q.pkg.Requires = []rpmfile.Dep{{Name: "lib\xe9", Flags: 8, Version: "1:v\xe9-r\xe9"}, {Name: "lib\xc3\xa9", Flags: 8, Version: "1:v\xc3\xa9-r\xc3\xa9"}}

		_, got := renderDeps(t, func(pkg *rpmfile.Package) { *pkg = q.pkg })
		assert.Equal(t, []gotEntry{{Name: "lib\xc3\xa9", Flags: "EQ", Epoch: "1", Ver: "v\xc3\xa9", Rel: "r\xc3\xa9"}}, got.Package[0].Format.Requires.Entry)
	})

	t.Run("refused while writing", func(t *testing.T) {
		tests := []struct {
			field string
			edit  func(p *rpmfile.Package)
		}{
			{"SUMMARY", func(p *rpmfile.Package) { p.Summary = "\xed\xa0\x80" }},
			{`requires entry "lib`, func(p *rpmfile.Package) { p.Requires[0].Name = "lib\xed\xa0\x80" }},
			{"file 0", func(p *rpmfile.Package) { p.Files[0].Path = "/usr/share/\xed\xa0\x80" }},
			{"changelog entry 0 author", func(p *rpmfile.Package) { p.Changelog[0].Author = "\xed\xa0\x80" }},
		}

		for _, tt := range tests {
			q := p
			q.pkg.Requires = slices.Clone(p.pkg.Requires)
			q.pkg.Files = slices.Clone(p.pkg.Files)
			q.pkg.Changelog = slices.Clone(p.pkg.Changelog)
			tt.edit(&q.pkg)

			var err error

			for _, render := range []func() ([]byte, error){
				func() ([]byte, error) { return renderPrimary([]repoPackage{q}) },
				func() ([]byte, error) { return renderList("filelists", nsFilelists, []repoPackage{q}, true) },
				func() ([]byte, error) { return renderList("otherdata", nsOther, []repoPackage{q}, false) },
			} {
				_, renderErr := render()
				err = errors.Join(err, renderErr)
			}

			require.ErrorIs(t, err, rpmfile.ErrInvalidField, tt.field)
			assert.Contains(t, err.Error(), tt.field)
		}
	})
}

func TestGzipBytes(t *testing.T) {
	first, err := gzipBytes([]byte("same"))
	require.NoError(t, err)

	second, err := gzipBytes([]byte("same"))
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, []byte("same"), gunzip(t, first))

	r, err := gzip.NewReader(bytes.NewReader(first))
	require.NoError(t, err)
	assert.Empty(t, r.Name)
	assert.True(t, r.ModTime.IsZero())
}

func TestRenderRepo(t *testing.T) {
	key := readSigningKey(t, initWorkdir(t))
	now := time.Unix(1800000000, 0)

	md, files, err := renderRepo([]repoPackage{samplePackage()}, key, now)
	require.NoError(t, err)
	require.Len(t, files, 5)
	assert.Equal(t, now.Unix(), md.Revision)
	assert.Len(t, md.Data, 3)

	for i, suffix := range []string{"-primary.xml.gz", "-filelists.xml.gz", "-other.xml.gz"} {
		assert.True(t, strings.HasSuffix(files[i].name, suffix), files[i].name)
		assert.Equal(t, msgAdded, files[i].msg)
	}

	assert.Equal(t, "repomd.xml.asc", files[3].name)
	assert.Equal(t, "repomd.xml", files[4].name)
	assert.Equal(t, msgUpdated, files[3].msg)
	assert.Equal(t, msgUpdated, files[4].msg)

	var got gotRepomd
	require.NoError(t, xml.Unmarshal(files[4].data, &got))
	assert.Equal(t, xml.Name{Space: nsRepo, Local: "repomd"}, got.XMLName)
	assert.Contains(t, string(files[4].data), `xmlns:rpm="http://linux.duke.edu/metadata/rpm"`)
	assert.Equal(t, now.Unix(), got.Revision)

	t.Run("bad key", func(t *testing.T) {
		_, _, err := renderRepo([]repoPackage{samplePackage()}, []byte("not a key"), now)
		assert.Error(t, err)
	})
}

func FuzzRenderPrimary(f *testing.F) {
	f.Add("pdns", "pdns-5.1.0-1.el9.src.rpm", "pool/9/main/p/pdns/x86_64/a.rpm")
	f.Add("<&>\"'", "]]>", "")

	f.Fuzz(func(t *testing.T, name, sourceRPM, poolPath string) {
		p := samplePackage()
		p.pkg.Name = name
		p.pkg.SourceRPM = sourceRPM
		p.path = poolPath

		data, err := renderPrimary([]repoPackage{p})
		if err != nil {
			require.ErrorIs(t, err, rpmfile.ErrInvalidField)
			return
		}

		var got gotPrimary
		require.NoError(t, xml.Unmarshal(data, &got))
		require.Len(t, got.Package, 1)
	})
}

func BenchmarkRenderRepo(b *testing.B) {
	workdir := b.TempDir()
	require.NoError(b, Init(b.Context(), workdir, "Test", ""))

	key := readSigningKey(b, workdir)
	pkgs := []repoPackage{samplePackage(), samplePackage()}
	now := time.Unix(1800000000, 0)

	b.ReportAllocs()

	for b.Loop() {
		_, _, err := renderRepo(pkgs, key, now)
		require.NoError(b, err)
	}
}

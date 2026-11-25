package rpmrepo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

func TestFlagString(t *testing.T) {
	tests := []struct {
		flags uint32
		want  string
	}{
		{0, ""},
		{1, ""},
		{2, "LT"},
		{4, "GT"},
		{6, ""},
		{8, "EQ"},
		{9, ""},
		{10, "LE"},
		{12, "GE"},
		{14, ""},
		{15, ""},
		{8 | 1<<4, "EQ"},
		{12 | 1<<9 | 1<<24, "GE"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, flagString(tt.flags), tt.flags)
	}
}

func TestSplitVersion(t *testing.T) {
	tests := []struct {
		version string
		want    dep
		ok      bool
	}{
		{"", dep{}, true},
		{"1.2", dep{epoch: "0", ver: "1.2"}, true},
		{"1.2-3", dep{epoch: "0", ver: "1.2", rel: "3"}, true},
		{"4:1.2-3", dep{epoch: "4", ver: "1.2", rel: "3"}, true},
		{"0:1.2", dep{epoch: "0", ver: "1.2"}, true},
		{"1.2-3-4", dep{epoch: "0", ver: "1.2", rel: "3-4"}, true},
		{"1:2:3-4", dep{epoch: "1", ver: "2:3", rel: "4"}, true},
		{":1", dep{epoch: "0", ver: "1"}, true},
		{"-1:1", dep{epoch: "-1", ver: "1"}, true},
		{" 1:1", dep{epoch: " 1", ver: "1"}, true},
		{"+1:1", dep{epoch: "+1", ver: "1"}, true},
		{"\t\n\v\f\r -007:1", dep{epoch: "\t\n\v\f\r -007", ver: "1"}, true},
		{"99999999999999999999999999:1", dep{epoch: "99999999999999999999999999", ver: "1"}, true},
		{"1:-2", dep{epoch: "1", rel: "2"}, true},
		{"1.0-", dep{epoch: "0", ver: "1.0"}, true},
		{"1:", dep{epoch: "1"}, true},
		{"-", dep{epoch: "0"}, true},
		{"x:1", dep{}, false},
		{" :1", dep{}, false},
		{"-:1", dep{}, false},
		{"+:1", dep{}, false},
		{"--1:1", dep{}, false},
		{"1 :1", dep{}, false},
		{"1a:1-2", dep{}, false},
		{"\x851:1", dep{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got, ok := splitVersion(tt.version)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCompareLibc(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"libc.so.6", "libc.so.6", 0},
		{"libc.so.6", "libc.so.6(GLIBC_2.17)", 2},
		{"libc.so.6(GLIBC_2.17)", "libc.so.6", 1},
		{"libc.so.6(", "libc.so.6(", -1},
		{"libc.so.6(", "libc.so.6()", 2},
		{"libc.so.6()", "libc.so.6(", 1},
		{"libc.so.6()", "libc.so.6()(64bit)", 0},
		{"libc.so.6()(64bit)", "libc.so.6(GLIBC_2.17)(64bit)", 2},
		{"libc.so.6(GLIBC_2.17)(64bit)", "libc.so.6()(64bit)", 1},
		{"libc.so.6(GLIBC)(64bit)", "libc.so.6(ABC)", 0},
		{"libc.so.6(GLIBC)(64bit)", "libc.so.6(GLIBC_2.3)", 2},
		{"libc.so.6(GLIBC_2.3)", "libc.so.6(GLIBC)(64bit)", 1},
		{"libc.so.6(GLIBC_2.3)", "libc.so.6(GLIBC_2.17)", 2},
		{"libc.so.6(GLIBC_2.17)", "libc.so.6(GLIBC_2.3)", 1},
		{"libc.so.6(GLIBC_2.17)(64bit)", "libc.so.6(GLIBC_2.17)", 0},
		{"libc.so.6(GLIBC_2.3.4)(64 bit)", "libc.so.6(GLIBC_2.4)", 2},
	}

	for _, tt := range tests {
		t.Run(tt.a, func(t *testing.T) {
			assert.Equal(t, tt.want, compareLibc(tt.a, tt.b), tt.b)
		})
	}
}

func TestBuildDeps(t *testing.T) {
	t.Run("every list keeps header order and drops bad epochs", func(t *testing.T) {
		in := []rpmfile.Dep{
			{Name: "b", Flags: 8, Version: "2"},
			{Name: "bad", Flags: 0, Version: "x:1"},
			{Name: "a", Flags: 12, Version: "1:1.0-1"},
			{Name: "bad", Flags: 8, Version: " :1"},
			{Name: "", Flags: 2, Version: "3"},
			{Name: "b", Flags: 8, Version: "2"},
		}
		want := []dep{
			{name: "b", flags: "EQ", epoch: "0", ver: "2"},
			{name: "a", flags: "GE", epoch: "1", ver: "1.0", rel: "1"},
			{name: "", flags: "LT", epoch: "0", ver: "3"},
			{name: "b", flags: "EQ", epoch: "0", ver: "2"},
		}

		got := buildDeps(rpmfile.Package{
			Provides:    in,
			Conflicts:   in,
			Obsoletes:   in,
			Suggests:    in,
			Enhances:    in,
			Recommends:  in,
			Supplements: in,
		})

		for _, list := range [][]dep{got.provides, got.conflicts, got.obsoletes, got.suggests, got.enhances, got.recommends, got.supplements} {
			assert.Equal(t, want, list)
		}

		assert.Empty(t, got.requires)
	})

	t.Run("empty package", func(t *testing.T) {
		assert.Equal(t, depLists{}, buildDeps(rpmfile.Package{}))
	})

	t.Run("requires rules", func(t *testing.T) {
		tests := []struct {
			name     string
			pkg      rpmfile.Package
			requires []dep
		}{
			{
				name:     "rpmlib is dropped",
				pkg:      rpmfile.Package{Requires: []rpmfile.Dep{{Name: "rpmlib(PayloadIsXz)", Flags: 8, Version: "5.2-1"}, {Name: "rpmlibx"}}},
				requires: []dep{{name: "rpmlibx"}},
			},
			{
				name: "own primary files are dropped",
				pkg: rpmfile.Package{
					Files: []rpmfile.File{{Path: "/usr/bin/tree"}, {Path: "/usr/share/doc/x"}, {Path: "/etc/x.conf"}},
					Requires: []rpmfile.Dep{
						{Name: "/usr/bin/tree"},
						{Name: "/usr/share/doc/x"},
						{Name: "/etc/x.conf", Flags: 8, Version: "1"},
						{Name: "/bin/sh"},
					},
				},
				requires: []dep{{name: "/usr/share/doc/x"}, {name: "/bin/sh"}},
			},
			{
				name: "provided entries are dropped by name, flags string, and raw version",
				pkg: rpmfile.Package{
					Provides: []rpmfile.Dep{
						{Name: "foo", Flags: 8, Version: "1.0"},
						{Name: "bar", Flags: 0, Version: "2"},
						{Name: "fooEQ", Flags: 0, Version: "9"},
						{Name: "baz", Flags: 8, Version: "1"},
					},
					Requires: []rpmfile.Dep{
						{Name: "foo", Flags: 8 | 1<<9, Version: "1.0"},
						{Name: "foo", Flags: 12, Version: "1.0"},
						{Name: "bar", Flags: 9, Version: "2"},
						{Name: "foo", Flags: 8, Version: "9"},
						{Name: "baz", Flags: 8, Version: "0:1"},
					},
				},
				requires: []dep{
					{name: "foo", flags: "GE", epoch: "0", ver: "1.0"},
					{name: "baz", flags: "EQ", epoch: "0", ver: "1"},
				},
			},
			{
				name: "pre bits",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "a", Flags: 1 << 6},
					{Name: "b", Flags: 1 << 9},
					{Name: "c", Flags: 1 << 10},
					{Name: "d", Flags: 1<<7 | 1<<8},
				}},
				requires: []dep{{name: "a", pre: true}, {name: "b", pre: true}, {name: "c", pre: true}, {name: "d"}},
			},
			{
				name: "duplicates of the last kept require are dropped",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "z"},
					{Name: "a"},
					{Name: "z"},
					{Name: "z", Flags: 1 << 9},
					{Name: "z", Flags: 1 << 6},
					{Name: "z"},
					{Name: "v", Flags: 8, Version: "1"},
					{Name: "v", Flags: 8 | 1<<4, Version: "1"},
					{Name: "v", Flags: 8, Version: "0:1"},
				}},
				requires: []dep{
					{name: "z"},
					{name: "a"},
					{name: "z", pre: true},
					{name: "z"},
					{name: "v", flags: "EQ", epoch: "0", ver: "1"},
					{name: "v", flags: "EQ", epoch: "0", ver: "1"},
				},
			},
			{
				name: "dropped entries do not count as kept",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "e", Flags: 8, Version: "x:1"},
					{Name: "e", Flags: 8, Version: "x:1"},
					{Name: "w", Flags: 1 << 19},
					{Name: "w"},
					{Name: "libc.so.6"},
					{Name: "libc.so.6"},
				}},
				requires: []dep{{name: "w"}, {name: "libc.so.6"}},
			},
			{
				name:     "bad epoch with flags 0",
				pkg:      rpmfile.Package{Requires: []rpmfile.Dep{{Name: "b", Version: "x:1"}, {Name: "c", Version: "-1:1"}}},
				requires: []dep{{name: "c", epoch: "-1", ver: "1"}},
			},
			{
				name: "libc.so.6 keeps the higher one at the end",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "libc.so.6()(64bit)"},
					{Name: "a"},
					{Name: "libc.so.6(GLIBC_2.17)(64bit)"},
					{Name: "b"},
				}},
				requires: []dep{{name: "a"}, {name: "b"}, {name: "libc.so.6(GLIBC_2.17)(64bit)"}},
			},
			{
				name: "libc.so.6 reversed input",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "libc.so.6(GLIBC_2.17)(64bit)"},
					{Name: "libc.so.6()(64bit)"},
					{Name: "a"},
				}},
				requires: []dep{{name: "a"}, {name: "libc.so.6(GLIBC_2.17)(64bit)"}},
			},
			{
				name: "libc.so.6 equal compare keeps the first",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "libc.so.6(GLIBC_2.17)(64bit)", Flags: 1 << 9},
					{Name: "libc.so.6(GLIBC_2.17)"},
				}},
				requires: []dep{{name: "libc.so.6(GLIBC_2.17)(64bit)", pre: true}},
			},
			{
				name: "libc.so.6 without ( loses",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "libc.so.6"},
					{Name: "libc.so.6(GLIBC_2.3)"},
					{Name: "libc.so.6x"},
				}},
				requires: []dep{{name: "libc.so.6(GLIBC_2.3)"}},
			},
			{
				name: "libc.so.6 later lower is dropped",
				pkg: rpmfile.Package{Requires: []rpmfile.Dep{
					{Name: "libc.so.6(GLIBC_2.3)"},
					{Name: "libc.so.6"},
				}},
				requires: []dep{{name: "libc.so.6(GLIBC_2.3)"}},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := buildDeps(tt.pkg)
				assert.Equal(t, tt.requires, got.requires)
			})
		}
	})

	t.Run("bit 19 duplicate of a kept require is dropped before recommends", func(t *testing.T) {
		got := buildDeps(rpmfile.Package{Requires: []rpmfile.Dep{{Name: "r"}, {Name: "r", Flags: 1 << 19}}})

		assert.Equal(t, []dep{{name: "r"}}, got.requires)
		assert.Empty(t, got.recommends)
	})

	t.Run("libc.so.6 provided by the package leaves no requires", func(t *testing.T) {
		libc := rpmfile.Dep{Name: "libc.so.6(GLIBC_2.3)"}
		got := buildDeps(rpmfile.Package{Provides: []rpmfile.Dep{libc}, Requires: []rpmfile.Dep{libc}})

		assert.Empty(t, got.requires)
		assert.Equal(t, []dep{{name: "libc.so.6(GLIBC_2.3)"}}, got.provides)
	})

	t.Run("bit 19 requires go to recommends first", func(t *testing.T) {
		got := buildDeps(rpmfile.Package{
			Requires: []rpmfile.Dep{
				{Name: "w1", Flags: 1<<19 | 1<<9 | 8, Version: "1"},
				{Name: "r"},
				{Name: "libc.so.6(GLIBC_2.3)", Flags: 1 << 19},
				{Name: "w2", Flags: 1 << 19, Version: "x:1"},
			},
			Recommends:  []rpmfile.Dep{{Name: "rec"}},
			OldSuggests: []rpmfile.Dep{{Name: "os"}, {Name: "osStrong", Flags: 1<<27 | 4, Version: "2"}},
		})

		assert.Equal(t, []dep{{name: "r"}}, got.requires)
		assert.Equal(t, []dep{
			{name: "w1", flags: "EQ", epoch: "0", ver: "1"},
			{name: "libc.so.6(GLIBC_2.3)"},
			{name: "rec"},
			{name: "osStrong", flags: "GT", epoch: "0", ver: "2"},
		}, got.recommends)
		assert.Equal(t, []dep{{name: "os"}}, got.suggests)
	})

	t.Run("old suggests and enhances follow bit 27", func(t *testing.T) {
		got := buildDeps(rpmfile.Package{
			Suggests:    []rpmfile.Dep{{Name: "s"}},
			Enhances:    []rpmfile.Dep{{Name: "e"}},
			Recommends:  []rpmfile.Dep{{Name: "r"}},
			Supplements: []rpmfile.Dep{{Name: "p"}},
			OldSuggests: []rpmfile.Dep{
				{Name: "os1"},
				{Name: "os2", Flags: 1 << 27},
				{Name: "os3", Flags: 1 << 26},
				{Name: "osbad", Flags: 1 << 27, Version: "x:1"},
			},
			OldEnhances: []rpmfile.Dep{
				{Name: "oe1", Flags: 1 << 27},
				{Name: "oe2"},
				{Name: "oebad", Version: "x:1"},
			},
		})

		assert.Equal(t, []dep{{name: "s"}, {name: "os1"}, {name: "os3"}}, got.suggests)
		assert.Equal(t, []dep{{name: "r"}, {name: "os2"}}, got.recommends)
		assert.Equal(t, []dep{{name: "e"}, {name: "oe2"}}, got.enhances)
		assert.Equal(t, []dep{{name: "p"}, {name: "oe1"}}, got.supplements)
	})
}

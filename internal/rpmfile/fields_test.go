package rpmfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/rpmtest"
)

func parseTags(t *testing.T, tags, sigTags []rpmtest.Tag) (Package, error) {
	t.Helper()

	p := basePackage()
	p.Tags = tags
	p.SigTags = sigTags

	return Parse(bytes.NewReader(build(t, p)))
}

func TestParseFields(t *testing.T) {
	type fields struct {
		Summary, Description, URL, Packager, Vendor, Group, BuildHost, License string
		BuildTime                                                              uint64
	}

	of := func(p Package) fields {
		return fields{p.Summary, p.Description, p.URL, p.Packager, p.Vendor, p.Group, p.BuildHost, p.License, p.BuildTime}
	}

	tests := []struct {
		name string
		tags []rpmtest.Tag
		want fields
	}{
		{"absent", nil, fields{}},
		{"strings", []rpmtest.Tag{
			{ID: 1004, Type: 6, Value: "File system tree viewer"},
			{ID: 1005, Type: 6, Value: "The tree utility\nrecursively displays."},
			{ID: 1006, Type: 4, Value: []uint32{1700000000}},
			{ID: 1007, Type: 6, Value: "builder.example"},
			{ID: 1011, Type: 6, Value: "Example Vendor"},
			{ID: 1014, Type: 6, Value: "GPLv2+"},
			{ID: 1015, Type: 6, Value: "Example Packager <p@example.com>"},
			{ID: 1016, Type: 6, Value: "Applications/File"},
			{ID: 1020, Type: 6, Value: "http://example.com/tree"},
		}, fields{
			Summary:     "File system tree viewer",
			Description: "The tree utility\nrecursively displays.",
			BuildTime:   1700000000,
			BuildHost:   "builder.example",
			Vendor:      "Example Vendor",
			License:     "GPLv2+",
			Packager:    "Example Packager <p@example.com>",
			Group:       "Applications/File",
			URL:         "http://example.com/tree",
		}},
		{"i18n strings give the first string", []rpmtest.Tag{
			{ID: 1004, Type: 9, Value: []string{"summary", "Zusammenfassung"}},
			{ID: 1005, Type: 9, Value: []string{"description", "Beschreibung"}},
			{ID: 1016, Type: 9, Value: []string{"Applications/File", "Anwendungen/Datei"}},
		}, fields{Summary: "summary", Description: "description", Group: "Applications/File"}},
		{"i18n with one string", []rpmtest.Tag{{ID: 1004, Type: 9, Value: []string{"only"}}}, fields{Summary: "only"}},
		{"empty i18n first string", []rpmtest.Tag{{ID: 1016, Type: 9, Value: []string{"", "x"}}}, fields{}},
		{"build time is unsigned", []rpmtest.Tag{{ID: 1006, Type: 4, Value: []uint32{0xfffffffe}}}, fields{BuildTime: 0xfffffffe}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTags(t, tt.tags, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, of(got))
		})
	}

	wrong := []struct {
		name string
		tag  rpmtest.Tag
		want string
	}{
		{"summary array", rpmtest.Tag{ID: 1004, Type: 8, Value: []string{"a"}}, "SUMMARY"},
		{"summary bin", rpmtest.Tag{ID: 1004, Type: 7, Value: []byte("a\x00")}, "SUMMARY"},
		{"description array", rpmtest.Tag{ID: 1005, Type: 8, Value: []string{"a"}}, "DESCRIPTION"},
		{"group array", rpmtest.Tag{ID: 1016, Type: 8, Value: []string{"a"}}, "GROUP"},
		{"build time string", rpmtest.Tag{ID: 1006, Type: 6, Value: "1"}, "BUILDTIME"},
		{"build time int64", rpmtest.Tag{ID: 1006, Type: 5, Value: []uint64{1}}, "BUILDTIME"},
		{"build time count 2", rpmtest.Tag{ID: 1006, Type: 4, Value: []uint32{1, 2}}, "BUILDTIME"},
		{"build host i18n", rpmtest.Tag{ID: 1007, Type: 9, Value: []string{"a"}}, "BUILDHOST"},
		{"vendor i18n", rpmtest.Tag{ID: 1011, Type: 9, Value: []string{"a"}}, "VENDOR"},
		{"license array", rpmtest.Tag{ID: 1014, Type: 8, Value: []string{"a"}}, "LICENSE"},
		{"packager array", rpmtest.Tag{ID: 1015, Type: 8, Value: []string{"a"}}, "PACKAGER"},
		{"url i18n", rpmtest.Tag{ID: 1020, Type: 9, Value: []string{"a"}}, "URL"},
	}

	for _, tt := range wrong {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTags(t, []rpmtest.Tag{tt.tag}, nil)
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestHeaderText(t *testing.T) {
	h := header{entries: map[uint32]entry{1: {typ: typeI18NString, offset: 0, count: 1}}, data: []byte("abc")}

	_, err := h.text(1, "X")
	assert.ErrorIs(t, err, ErrInvalidField)
	assert.ErrorContains(t, err, "X has no NUL terminator")
}

func TestParseSizes(t *testing.T) {
	int32Tag := func(id, v uint32) rpmtest.Tag { return rpmtest.Tag{ID: id, Type: 4, Value: []uint32{v}} }
	int64Tag := func(id uint32, v uint64) rpmtest.Tag { return rpmtest.Tag{ID: id, Type: 5, Value: []uint64{v}} }

	tests := []struct {
		name               string
		tags, sigTags      []rpmtest.Tag
		installed, archive uint64
	}{
		{"absent", nil, nil, 0, 0},
		{"installed from SIZE", []rpmtest.Tag{int32Tag(1009, 0xfffffff0)}, nil, 0xfffffff0, 0},
		{"installed from LONGSIZE", []rpmtest.Tag{int64Tag(5009, 1<<40)}, nil, 1 << 40, 0},
		{"LONGSIZE wins over SIZE", []rpmtest.Tag{int32Tag(1009, 100), int64Tag(5009, 1<<40)}, nil, 1 << 40, 0},
		{"installed ignores the signature header", nil, []rpmtest.Tag{int32Tag(1009, 100), int64Tag(5009, 1<<40)}, 0, 0},

		{"archive from ARCHIVESIZE", []rpmtest.Tag{int32Tag(1046, 200)}, nil, 0, 200},
		{"archive from signature PAYLOADSIZE", nil, []rpmtest.Tag{int32Tag(1007, 300)}, 0, 300},
		{"ARCHIVESIZE wins over signature PAYLOADSIZE", []rpmtest.Tag{int32Tag(1046, 200)}, []rpmtest.Tag{int32Tag(1007, 300)}, 0, 200},
		{"archive from LONGARCHIVESIZE", []rpmtest.Tag{int64Tag(271, 1<<34)}, nil, 0, 1 << 34},
		{"archive from signature LONGARCHIVESIZE", nil, []rpmtest.Tag{int64Tag(271, 1<<33)}, 0, 1 << 33},
		{"signature LONGARCHIVESIZE wins over ARCHIVESIZE", []rpmtest.Tag{int32Tag(1046, 200)}, []rpmtest.Tag{int64Tag(271, 1<<33), int32Tag(1007, 300)}, 0, 1 << 33},
		{"LONGARCHIVESIZE wins over signature LONGARCHIVESIZE", []rpmtest.Tag{int64Tag(271, 1<<34), int32Tag(1046, 200)}, []rpmtest.Tag{int64Tag(271, 1<<33), int32Tag(1007, 300)}, 0, 1 << 34},
		{"both sizes", []rpmtest.Tag{int32Tag(1009, 100)}, []rpmtest.Tag{int32Tag(1007, 300)}, 100, 300},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTags(t, tt.tags, tt.sigTags)
			require.NoError(t, err)
			assert.Equal(t, tt.installed, got.InstalledSize)
			assert.Equal(t, tt.archive, got.ArchiveSize)
		})
	}

	wrong := []struct {
		name          string
		tags, sigTags []rpmtest.Tag
		want          string
	}{
		{"LONGSIZE int32", []rpmtest.Tag{int32Tag(5009, 1)}, nil, "LONGSIZE"},
		{"LONGSIZE count 2", []rpmtest.Tag{{ID: 5009, Type: 5, Value: []uint64{1, 2}}}, nil, "LONGSIZE"},
		{"SIZE int64", []rpmtest.Tag{int64Tag(1009, 1)}, nil, ": SIZE has"},
		{"SIZE count 2", []rpmtest.Tag{{ID: 1009, Type: 4, Value: []uint32{1, 2}}}, nil, ": SIZE has"},
		{"LONGARCHIVESIZE int32", []rpmtest.Tag{int32Tag(271, 1)}, nil, ": LONGARCHIVESIZE has"},
		{"signature LONGARCHIVESIZE int32", nil, []rpmtest.Tag{int32Tag(271, 1)}, "signature LONGARCHIVESIZE"},
		{"signature LONGARCHIVESIZE count 2", nil, []rpmtest.Tag{{ID: 271, Type: 5, Value: []uint64{1, 2}}}, "signature LONGARCHIVESIZE"},
		{"ARCHIVESIZE int64", []rpmtest.Tag{int64Tag(1046, 1)}, nil, ": ARCHIVESIZE has"},
		{"signature PAYLOADSIZE int64", nil, []rpmtest.Tag{int64Tag(1007, 1)}, "signature PAYLOADSIZE"},
		{"signature PAYLOADSIZE count 2", nil, []rpmtest.Tag{{ID: 1007, Type: 4, Value: []uint32{1, 2}}}, "signature PAYLOADSIZE"},
	}

	for _, tt := range wrong {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTags(t, tt.tags, tt.sigTags)
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

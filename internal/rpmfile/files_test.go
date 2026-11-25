package rpmfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

type fileSet struct {
	basenames  []string
	dirnames   []string
	dirindexes []uint32
	modes      []uint16
	flags      []uint32
}

func fileTags(f fileSet) []rpmtest.Tag {
	return []rpmtest.Tag{
		{ID: 1117, Type: 8, Value: f.basenames},
		{ID: 1118, Type: 8, Value: f.dirnames},
		{ID: 1116, Type: 4, Value: f.dirindexes},
		{ID: 1030, Type: 3, Value: f.modes},
		{ID: 1037, Type: 4, Value: f.flags},
	}
}

func TestFileKinds(t *testing.T) {
	tests := []struct {
		name      string
		file      File
		dir, ghst bool
	}{
		{"regular", File{Mode: 0o100644}, false, false},
		{"directory", File{Mode: 0o040755}, true, false},
		{"symlink", File{Mode: 0o120777}, false, false},
		{"ghost file", File{Mode: 0o100644, Flags: 1 << 6}, false, true},
		{"ghost directory", File{Mode: 0o040755, Flags: 1<<6 | 1<<4}, true, true},
		{"other flags", File{Mode: 0o100644, Flags: 1<<0 | 1<<4 | 1<<7}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.dir, tt.file.IsDir())
			assert.Equal(t, tt.ghst, tt.file.IsGhost())
		})
	}
}

func TestFilesCompareCountsFirst(t *testing.T) {
	h := header{
		entries: map[uint32]entry{
			1117: {typ: typeStringArray, offset: 0, count: 1 << 30},
			1118: {typ: typeStringArray, offset: 0, count: 1},
			1116: {typ: typeInt32, offset: 0, count: 1},
			1030: {typ: typeInt16, offset: 0, count: 1},
			1037: {typ: typeInt32, offset: 0, count: 1},
		},
		data: []byte("a\x00\x00\x00"),
	}

	err := h.files(&Package{})
	assert.ErrorIs(t, err, ErrInvalidField)
	assert.ErrorContains(t, err, "DIRINDEXES has count 1, BASENAMES has 1073741824")
}

func TestParseFiles(t *testing.T) {
	parseWith := func(t *testing.T, tags []rpmtest.Tag) (Package, error) {
		t.Helper()

		p := basePackage()
		p.Tags = tags

		return Parse(bytes.NewReader(build(t, p)))
	}

	valid := fileTags(fileSet{
		basenames:  []string{"tree", "tree", "README", "a"},
		dirnames:   []string{"/usr/bin/", "/usr/share/doc/tree/", "/"},
		dirindexes: []uint32{0, 1, 1, 2},
		modes:      []uint16{0o100755, 0o040755, 0o100644, 0o100644},
		flags:      []uint32{0, 0, 1 << 7, 1 << 6},
	})

	t.Run("several directories with reused indexes", func(t *testing.T) {
		got, err := parseWith(t, valid)
		require.NoError(t, err)
		assert.Equal(t, []File{
			{Path: "/usr/bin/tree", Mode: 0o100755},
			{Path: "/usr/share/doc/tree/tree", Mode: 0o040755},
			{Path: "/usr/share/doc/tree/README", Mode: 0o100644, Flags: 1 << 7},
			{Path: "/a", Mode: 0o100644, Flags: 1 << 6},
		}, got.Files)
	})

	t.Run("no file tags", func(t *testing.T) {
		got, err := parseWith(t, nil)
		require.NoError(t, err)
		assert.Empty(t, got.Files)
	})

	t.Run("every other tag is required with the basenames", func(t *testing.T) {
		for i, name := range []string{"BASENAMES", "DIRNAMES", "DIRINDEXES", "FILEMODES", "FILEFLAGS"} {
			if i == 0 {
				continue
			}

			without := append(append([]rpmtest.Tag{}, valid[:i]...), valid[i+1:]...)
			_, err := parseWith(t, without)
			assert.ErrorIs(t, err, ErrInvalidField, name)
			assert.ErrorContains(t, err, name)
		}
	})

	t.Run("counts must match", func(t *testing.T) {
		tests := []struct {
			name string
			tags []rpmtest.Tag
			want string
		}{
			{"dirindexes", fileTags(fileSet{[]string{"a", "b"}, []string{"/"}, []uint32{0}, []uint16{1, 1}, []uint32{0, 0}}), "DIRINDEXES"},
			{"modes", fileTags(fileSet{[]string{"a", "b"}, []string{"/"}, []uint32{0, 0}, []uint16{1}, []uint32{0, 0}}), "FILEMODES"},
			{"flags", fileTags(fileSet{[]string{"a", "b"}, []string{"/"}, []uint32{0, 0}, []uint16{1, 1}, []uint32{0}}), "FILEFLAGS"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := parseWith(t, tt.tags)
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, tt.want)
			})
		}
	})

	t.Run("dir index out of range", func(t *testing.T) {
		_, err := parseWith(t, fileTags(fileSet{[]string{"a"}, []string{"/"}, []uint32{1}, []uint16{1}, []uint32{0}}))
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "DIRINDEXES")
	})

	t.Run("wrong type", func(t *testing.T) {
		tags := append([]rpmtest.Tag{}, valid...)
		tags[3] = rpmtest.Tag{ID: 1030, Type: 4, Value: []uint32{1, 1, 1, 1}}
		_, err := parseWith(t, tags)
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "FILEMODES")
	})
}

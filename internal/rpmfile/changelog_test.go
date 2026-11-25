package rpmfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

type changelogValues struct {
	times          []uint32
	authors, texts []string
}

func changelogTags(v changelogValues) []rpmtest.Tag {
	return []rpmtest.Tag{
		{ID: 1080, Type: 4, Value: v.times},
		{ID: 1081, Type: 8, Value: v.authors},
		{ID: 1082, Type: 8, Value: v.texts},
	}
}

func TestChangelogCompareCountsFirst(t *testing.T) {
	h := header{
		entries: map[uint32]entry{
			1080: {typ: typeInt32, offset: 0, count: 1},
			1081: {typ: typeStringArray, offset: 0, count: 1 << 30},
			1082: {typ: typeStringArray, offset: 0, count: 1},
		},
		data: []byte("a\x00\x00\x00"),
	}

	err := h.changelog(&Package{})
	assert.ErrorIs(t, err, ErrInvalidField)
	assert.ErrorContains(t, err, "CHANGELOGNAME has count 1073741824, CHANGELOGTIME has 1")
}

func TestParseChangelog(t *testing.T) {
	parseWith := func(t *testing.T, tags []rpmtest.Tag) (Package, error) {
		t.Helper()

		p := basePackage()
		p.Tags = tags

		return Parse(bytes.NewReader(build(t, p)))
	}

	valid := changelogTags(changelogValues{
		times:   []uint32{1700000000, 0xffffffff, 0},
		authors: []string{"Jane <j@example.com> - 1.0-2  ", "", " "},
		texts:   []string{"- second", "", "- first\n- more"},
	})

	t.Run("every entry raw in header order", func(t *testing.T) {
		got, err := parseWith(t, valid)
		require.NoError(t, err)
		assert.Equal(t, []ChangelogEntry{
			{Time: 1700000000, Author: "Jane <j@example.com> - 1.0-2  ", Text: "- second"},
			{Time: 0xffffffff},
			{Time: 0, Author: " ", Text: "- first\n- more"},
		}, got.Changelog)
	})

	t.Run("more than ten entries are all kept", func(t *testing.T) {
		v := changelogValues{}
		for i := range 11 {
			v.times = append(v.times, uint32(i))
			v.authors = append(v.authors, "a")
			v.texts = append(v.texts, "t")
		}

		got, err := parseWith(t, changelogTags(v))
		require.NoError(t, err)
		assert.Len(t, got.Changelog, 11)
	})

	t.Run("no changelog tags", func(t *testing.T) {
		got, err := parseWith(t, nil)
		require.NoError(t, err)
		assert.Empty(t, got.Changelog)
	})

	t.Run("a missing tag is named", func(t *testing.T) {
		names := []string{"CHANGELOGTIME", "CHANGELOGNAME", "CHANGELOGTEXT"}

		for i, name := range names {
			without := append(append([]rpmtest.Tag{}, valid[:i]...), valid[i+1:]...)
			_, err := parseWith(t, without)
			assert.ErrorIs(t, err, ErrInvalidField, name)
			assert.ErrorContains(t, err, name)

			_, err = parseWith(t, []rpmtest.Tag{valid[i]})
			assert.ErrorIs(t, err, ErrInvalidField, name)
		}
	})

	t.Run("counts must match", func(t *testing.T) {
		tests := []struct {
			name string
			v    changelogValues
			want string
		}{
			{"names", changelogValues{[]uint32{1, 2}, []string{"a"}, []string{"x", "y"}}, "CHANGELOGNAME has count 1, CHANGELOGTIME has 2"},
			{"texts", changelogValues{[]uint32{1, 2}, []string{"a", "b"}, []string{"x"}}, "CHANGELOGTEXT has count 1, CHANGELOGTIME has 2"},
			{"times", changelogValues{[]uint32{1}, []string{"a", "b"}, []string{"x", "y"}}, "CHANGELOGNAME has count 2, CHANGELOGTIME has 1"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := parseWith(t, changelogTags(tt.v))
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, tt.want)
			})
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		tests := []struct {
			name string
			tag  rpmtest.Tag
			at   int
		}{
			{"CHANGELOGTIME", rpmtest.Tag{ID: 1080, Type: 8, Value: []string{"1", "2", "3"}}, 0},
			{"CHANGELOGNAME", rpmtest.Tag{ID: 1081, Type: 9, Value: []string{"a", "b", "c"}}, 1},
			{"CHANGELOGTEXT", rpmtest.Tag{ID: 1082, Type: 4, Value: []uint32{1, 2, 3}}, 2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tags := append([]rpmtest.Tag{}, valid...)
				tags[tt.at] = tt.tag
				_, err := parseWith(t, tags)
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, tt.name)
			})
		}
	})
}

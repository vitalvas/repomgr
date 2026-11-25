package rpmfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/rpmtest"
)

type depSet struct {
	names    []string
	flags    []uint32
	versions []string
}

func depTags(name, flags, version uint32, d depSet) []rpmtest.Tag {
	return []rpmtest.Tag{
		{ID: name, Type: 8, Value: d.names},
		{ID: flags, Type: 4, Value: d.flags},
		{ID: version, Type: 8, Value: d.versions},
	}
}

func TestDependenciesCompareCountsFirst(t *testing.T) {
	h := header{
		entries: map[uint32]entry{
			1047: {typ: typeStringArray, offset: 0, count: 1 << 30},
			1112: {typ: typeInt32, offset: 0, count: 1},
			1113: {typ: typeStringArray, offset: 0, count: 1},
		},
		data: []byte("a\x00\x00\x00"),
	}

	err := h.dependencies(&Package{})
	assert.ErrorIs(t, err, ErrInvalidField)
	assert.ErrorContains(t, err, "provides names, flags, and versions do not match")
}

func TestParseDependencies(t *testing.T) {
	kinds := []struct {
		name                string
		nameTag, flag, vers uint32
		field               func(Package) []Dep
	}{
		{"provides", 1047, 1112, 1113, func(p Package) []Dep { return p.Provides }},
		{"requires", 1049, 1048, 1050, func(p Package) []Dep { return p.Requires }},
		{"conflicts", 1054, 1053, 1055, func(p Package) []Dep { return p.Conflicts }},
		{"obsoletes", 1090, 1114, 1115, func(p Package) []Dep { return p.Obsoletes }},
		{"recommends", 5046, 5048, 5047, func(p Package) []Dep { return p.Recommends }},
		{"suggests", 5049, 5051, 5050, func(p Package) []Dep { return p.Suggests }},
		{"supplements", 5052, 5054, 5053, func(p Package) []Dep { return p.Supplements }},
		{"enhances", 5055, 5057, 5056, func(p Package) []Dep { return p.Enhances }},
		{"old suggests", 1156, 1158, 1157, func(p Package) []Dep { return p.OldSuggests }},
		{"old enhances", 1159, 1161, 1160, func(p Package) []Dep { return p.OldEnhances }},
	}

	parseWith := func(t *testing.T, tags []rpmtest.Tag) (Package, error) {
		t.Helper()

		p := basePackage()
		p.Tags = tags

		return Parse(bytes.NewReader(build(t, p)))
	}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			tags := depTags(k.nameTag, k.flag, k.vers, depSet{[]string{"a", "b(x86-64)"}, []uint32{8, 0}, []string{"1:2-3", ""}})
			got, err := parseWith(t, tags)
			require.NoError(t, err)
			assert.Equal(t, []Dep{{Name: "a", Flags: 8, Version: "1:2-3"}, {Name: "b(x86-64)"}}, k.field(got))

			for _, other := range kinds {
				if other.name != k.name {
					assert.Empty(t, other.field(got), other.name)
				}
			}

			t.Run("empty arrays are rejected by the layout rule", func(t *testing.T) {
				_, err := parseWith(t, depTags(k.nameTag, k.flag, k.vers, depSet{[]string{}, []uint32{}, []string{}}))
				assert.ErrorContains(t, err, "has no data")
			})

			t.Run("missing flags", func(t *testing.T) {
				_, err := parseWith(t, []rpmtest.Tag{tags[0], tags[2]})
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, k.name)
			})

			t.Run("missing versions", func(t *testing.T) {
				_, err := parseWith(t, tags[:2])
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, k.name)
			})

			t.Run("flags count differs", func(t *testing.T) {
				_, err := parseWith(t, depTags(k.nameTag, k.flag, k.vers, depSet{[]string{"a", "b"}, []uint32{0}, []string{"", ""}}))
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, k.name)
			})

			t.Run("versions count differs", func(t *testing.T) {
				_, err := parseWith(t, depTags(k.nameTag, k.flag, k.vers, depSet{[]string{"a", "b"}, []uint32{0, 0}, []string{""}}))
				assert.ErrorIs(t, err, ErrInvalidField)
				assert.ErrorContains(t, err, k.name)
			})

			t.Run("name tag absent", func(t *testing.T) {
				got, err := parseWith(t, tags[1:])
				require.NoError(t, err)
				assert.Empty(t, k.field(got))
			})

			t.Run("wrong type", func(t *testing.T) {
				_, err := parseWith(t, []rpmtest.Tag{{ID: k.nameTag, Type: 6, Value: "a"}, tags[1], tags[2]})
				assert.ErrorIs(t, err, ErrInvalidField)
			})
		})
	}

	t.Run("order is kept and duplicates stay", func(t *testing.T) {
		got, err := parseWith(t, depTags(1049, 1048, 1050, depSet{[]string{"z", "a", "z"}, []uint32{0, 0, 0}, []string{"", "", ""}}))
		require.NoError(t, err)
		assert.Equal(t, []Dep{{Name: "z"}, {Name: "a"}, {Name: "z"}}, got.Requires)
	})
}

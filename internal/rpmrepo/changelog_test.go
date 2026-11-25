package rpmrepo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

// timed returns entries with the given times, author "a", and text "t".
func timed(times ...uint32) []rpmfile.ChangelogEntry {
	out := make([]rpmfile.ChangelogEntry, len(times))
	for i, tm := range times {
		out[i] = rpmfile.ChangelogEntry{Time: tm, Author: "a", Text: "t"}
	}

	return out
}

// dates returns the output dates of kept.
func dates(kept []xmlChangelog) []int64 {
	out := make([]int64, 0, len(kept))
	for _, c := range kept {
		out = append(out, c.Date)
	}

	return out
}

func TestKeptChangelog(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		assert.Empty(t, keptChangelog(nil))
	})

	t.Run("reverse header order", func(t *testing.T) {
		got := keptChangelog([]rpmfile.ChangelogEntry{
			{Time: 300, Author: "c", Text: "third"},
			{Time: 200, Author: "b", Text: "second"},
			{Time: 100, Author: "a", Text: "first"},
		})
		assert.Equal(t, []xmlChangelog{
			{Author: "a", Date: 100, Text: "first"},
			{Author: "b", Date: 200, Text: "second"},
			{Author: "c", Date: 300, Text: "third"},
		}, got)
	})

	t.Run("only the first ten entries", func(t *testing.T) {
		// The eleventh equals the tenth but is never processed.
		got := keptChangelog(timed(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10))
		assert.Equal(t, []int64{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}, dates(got))
	})

	t.Run("author trailing spaces", func(t *testing.T) {
		tests := []struct {
			author, want string
		}{
			{"a  ", "a"},
			{" ", " "},
			{"  ", " "},
			{"", ""},
			{"a b ", "a b"},
			{" a", " a"},
			{"a\t", "a\t"},
			{"Jane <j@example.com> - 1.0-1 ", "Jane <j@example.com> - 1.0-1"},
		}

		for _, tt := range tests {
			got := keptChangelog([]rpmfile.ChangelogEntry{{Author: tt.author}})
			assert.Equal(t, tt.want, got[0].Author, "%q", tt.author)
		}
	})

	t.Run("time fix-up", func(t *testing.T) {
		const top uint32 = 1<<31 - 1

		tests := []struct {
			name  string
			times []uint32
			want  []int64
		}{
			{"distinct", []uint32{30, 20, 10}, []int64{10, 20, 30}},
			{"two equal", []uint32{5, 5}, []int64{5, 6}},
			{"three equal", []uint32{5, 5, 5}, []int64{5, 6, 7}},
			{"equal separated by a different time", []uint32{5, 3, 5}, []int64{5, 3, 5}},
			{"raising reaches an older different time", []uint32{6, 5, 5}, []int64{5, 6, 7}},
			{"raising stops at a time that does not match", []uint32{9, 5, 5}, []int64{5, 6, 9}},
			{"first entry time 0", []uint32{0}, []int64{0}},
			{"first entries time 0", []uint32{0, 0}, []int64{0, 1}},
			{"time 0 after another time", []uint32{0, 7, 7}, []int64{7, 8, 0}},
			{"2^31 never matches", []uint32{1 << 31, 1 << 31}, []int64{1 << 31, 1 << 31}},
			{"2^32-1 never matches", []uint32{0xffffffff, 0xffffffff}, []int64{0xffffffff, 0xffffffff}},
			{"counter wraps at 2^31-1", []uint32{top, top, top}, []int64{int64(top), 1 << 31, 1 << 31}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, dates(keptChangelog(timed(tt.times...))))
			})
		}
	})

	t.Run("input is not changed", func(t *testing.T) {
		in := []rpmfile.ChangelogEntry{{Time: 5, Author: "a "}, {Time: 5, Author: "b"}}
		keptChangelog(in)
		assert.Equal(t, []rpmfile.ChangelogEntry{{Time: 5, Author: "a "}, {Time: 5, Author: "b"}}, in)
	})
}

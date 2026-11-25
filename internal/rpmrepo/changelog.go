package rpmrepo

import (
	"slices"

	"go.vitalvas.com/repomgr/internal/rpmfile"
)

// changelogLimit is the reference writer's default changelog limit.
const changelogLimit int = 10

// trimAuthor drops trailing spaces but never the first byte.
func trimAuthor(s string) string {
	end := len(s)
	for end > 1 && s[end-1] == ' ' {
		end--
	}

	return s[:end]
}

// keptChangelog returns the changelog entries the reference writer
// keeps, with its output dates, in output order: the first entries in header
// order up to the limit, with the equal-time fix-up, written in reverse.
func keptChangelog(entries []rpmfile.ChangelogEntry) []xmlChangelog {
	entries = entries[:min(len(entries), changelogLimit)]
	out := make([]xmlChangelog, 0, len(entries))

	var last int64

	for i, e := range entries {
		date := int64(e.Time)
		out = append(out, xmlChangelog{Author: trimAuthor(e.Author), Date: date, Text: e.Text})

		if date != last {
			last = date
			continue
		}

		// The reference keeps the counter in a C int, so it is truncated to 32
		// bits and a time of 2^31 or more never matches.
		counter := int32(e.Time)
		for j := i - 1; j >= 0 && out[j].Date == int64(counter); j-- {
			out[j].Date++
			counter++
		}
	}

	slices.Reverse(out)

	return out
}

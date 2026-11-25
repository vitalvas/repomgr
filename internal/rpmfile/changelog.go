package rpmfile

import "fmt"

// Changelog tags from rpm 4.14.3 lib/rpmtag.h.
const (
	tagChangelogTime uint32 = 1080
	tagChangelogName uint32 = 1081
	tagChangelogText uint32 = 1082
)

// ChangelogEntry is one changelog entry as stored in the header.
type ChangelogEntry struct {
	Time   uint32
	Author string
	Text   string
}

// changelog fills the changelog of p with every entry in header order. A
// package without the three changelog tags has no changelog; one with any of
// them needs all three, with the same count.
func (h header) changelog(p *Package) error {
	_, okTimes := h.entries[tagChangelogTime]
	_, okNames := h.entries[tagChangelogName]
	_, okTexts := h.entries[tagChangelogText]

	if !okTimes && !okNames && !okTexts {
		return nil
	}

	times, ok := h.entries[tagChangelogTime]
	if !ok {
		return fmt.Errorf("%w: CHANGELOGTIME is missing", ErrInvalidField)
	}

	// Comparing the counts first means a mismatched header allocates nothing.
	for _, t := range []struct {
		tag  uint32
		name string
	}{{tagChangelogName, "CHANGELOGNAME"}, {tagChangelogText, "CHANGELOGTEXT"}} {
		e, ok := h.entries[t.tag]
		if !ok {
			return fmt.Errorf("%w: %s is missing", ErrInvalidField, t.name)
		}

		if e.count != times.count {
			return fmt.Errorf("%w: %s has count %d, CHANGELOGTIME has %d", ErrInvalidField, t.name, e.count, times.count)
		}
	}

	timeValues, _, err := h.int32s(tagChangelogTime, "CHANGELOGTIME")
	if err != nil {
		return err
	}

	authors, _, err := h.strings(tagChangelogName, "CHANGELOGNAME")
	if err != nil {
		return err
	}

	texts, _, err := h.strings(tagChangelogText, "CHANGELOGTEXT")
	if err != nil {
		return err
	}

	entries := make([]ChangelogEntry, len(timeValues))

	for i := range timeValues {
		entries[i] = ChangelogEntry{Time: timeValues[i], Author: authors[i], Text: texts[i]}
	}

	p.Changelog = entries

	return nil
}

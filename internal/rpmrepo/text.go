package rpmrepo

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.vitalvas.com/repomgr/internal/rpmfile"
)

// depField names a dependency entry by its list and name.
const depField string = "%s entry %q"

var errNotText = errors.New("is not valid UTF-8 text")

// isControl is the reference writer's forbidden control byte test.
func isControl(b byte) bool {
	return b < 32 && b != '\t' && b != '\n' && b != '\r'
}

// looseUTF8 is libxml2's xmlCheckUTF8: every lead byte has the right number
// of continuation bytes, with no check of the decoded value. A byte past the
// end is not a continuation byte, as the C string's NUL terminator is not.
func looseUTF8(s string) bool {
	for i := 0; i < len(s); {
		var n int

		switch c := s[i]; {
		case c&0x80 == 0x00:
			n = 0
		case c&0xe0 == 0xc0:
			n = 1
		case c&0xf0 == 0xe0:
			n = 2
		case c&0xf8 == 0xf0:
			n = 3
		default:
			return false
		}

		for j := i + 1; j <= i+n; j++ {
			if j >= len(s) || s[j]&0xc0 != 0x80 {
				return false
			}
		}

		i += n + 1
	}

	return true
}

// latin1ToUTF8 is the reference writer's cr_latin1_to_utf8.
func latin1ToUTF8(s string) string {
	out := make([]byte, 0, 2*len(s))

	for i := range len(s) {
		switch b := s[i]; {
		case isControl(b):
		case b < 128:
			out = append(out, b)
		case b < 192:
			// The reference drops C1 control codes.
		default:
			// The reference's 0xc2 + (b > 0xbf) is always 0xc3 here.
			out = append(out, 0xc3, b&0x3f+0x80)
		}
	}

	return string(out)
}

// textValue returns s as the reference writer writes it, converting a
// value that fails the loose UTF-8 check from Latin-1. It refuses what is then
// still not strict UTF-8 or holds U+FFFE or U+FFFF.
func textValue(s string) (string, error) {
	if !looseUTF8(s) {
		s = latin1ToUTF8(s)
	}

	if !utf8.ValidString(s) || strings.ContainsRune(s, 0xfffe) || strings.ContainsRune(s, 0xffff) {
		return "", errNotText
	}

	return s, nil
}

// textConv checks or converts the values of one package and keeps the first
// error, which names the field.
type textConv struct {
	err error
}

// value returns textValue(s). format and args name the field.
func (c *textConv) value(s, format string, args ...any) string {
	v, err := textValue(s)
	if err != nil && c.err == nil {
		c.err = fmt.Errorf("%w: %s %w", rpmfile.ErrInvalidField, fmt.Sprintf(format, args...), err)
	}

	return v
}

// control records an error when s holds a forbidden control byte. format and
// args name the field.
func (c *textConv) control(s, format string, args ...any) {
	if c.err != nil {
		return
	}

	for i := range len(s) {
		if isControl(s[i]) {
			c.err = fmt.Errorf("%w: %s has a control character", rpmfile.ErrInvalidField, fmt.Sprintf(format, args...))
			return
		}
	}
}

// checkText refuses, before anything is written, a package the reference
// writer refuses for a control byte, or one with a text value that
// textValue refuses.
func checkText(p rpmfile.Package) error {
	var c textConv

	// The pool location is built from NAME, VERSION, RELEASE, ARCH, and
	// SOURCERPM, which Parse limits to ASCII names, and from a checked release
	// and component, so it needs no check of its own.
	for _, f := range []struct{ name, value string }{
		{"NAME", p.Name},
		{"ARCH", p.Arch},
		{"VERSION", p.Version},
		{"RELEASE", p.Release},
		{"SUMMARY", p.Summary},
		{"DESCRIPTION", p.Description},
		{"URL", p.URL},
		{"LICENSE", p.License},
		{"VENDOR", p.Vendor},
		{"GROUP", p.Group},
		{"BUILDHOST", p.BuildHost},
		{"SOURCERPM", p.SourceRPM},
		{"PACKAGER", p.Packager},
	} {
		c.control(f.value, "%s", f.name)
	}

	deps := buildDeps(p)

	// Every entry of the lists counts, also one the writers skip for an empty
	// name or write without a version, as in the reference.
	for _, l := range []struct {
		name string
		deps []dep
	}{
		{"requires", deps.requires},
		{"provides", deps.provides},
		{"conflicts", deps.conflicts},
		{"obsoletes", deps.obsoletes},
		{"suggests", deps.suggests},
		{"enhances", deps.enhances},
		{"recommends", deps.recommends},
		{"supplements", deps.supplements},
	} {
		for _, d := range l.deps {
			for _, s := range []string{d.name, d.epoch, d.ver, d.rel} {
				c.control(s, depField, l.name, d.name)
			}
		}
	}

	for i, f := range p.Files {
		c.control(f.Path, "file %d", i)
	}

	kept := keptChangelog(p.Changelog)
	for i, e := range kept {
		n := len(kept) - 1 - i
		c.control(e.Author, "changelog entry %d author", n)
		c.control(e.Text, "changelog entry %d text", n)
	}

	if c.err != nil {
		return c.err
	}

	rp := repoPackage{pkg: p}

	_, err := newPrimaryPackage(rp)
	if err != nil {
		return err
	}

	_, err = newListPackage(rp, true)
	if err != nil {
		return err
	}

	_, err = newListPackage(rp, false)

	return err
}

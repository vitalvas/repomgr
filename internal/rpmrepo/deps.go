package rpmrepo

import (
	"strings"

	"go.vitalvas.com/repomgr/internal/rpmfile"
)

// Flag bits from rpm 4.14.3 lib/rpmds.h.
const (
	flagCompare   uint32 = 0x0f
	flagPre       uint32 = 1<<6 | 1<<9 | 1<<10
	flagMissingOK uint32 = 1 << 19
	flagStrong    uint32 = 1 << 27

	libcPrefix   string = "libc.so.6"
	rpmlibPrefix string = "rpmlib("
)

var flagNames = map[uint32]string{
	2:  "LT",
	4:  "GT",
	8:  "EQ",
	10: "LE",
	12: "GE",
}

// dep is one entry of an output dependency list.
type dep struct {
	name, flags, epoch, ver, rel string
	pre                          bool
}

type depLists struct {
	provides, requires, conflicts, obsoletes, suggests, enhances, recommends, supplements []dep
}

// keptRequire is what the duplicate rule compares against.
type keptRequire struct {
	flags, version string
	pre            bool
}

func flagString(flags uint32) string {
	return flagNames[flags&flagCompare]
}

// strtolEnd returns where a C strtol base-10 parse of s stops: after leading
// isspace characters, one optional sign, and every digit, or 0 when there is
// no digit.
func strtolEnd(s string) int {
	i := 0
	for i < len(s) && strings.IndexByte(" \t\n\v\f\r", s[i]) >= 0 {
		i++
	}

	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}

	start := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}

	if i == start {
		return 0
	}

	return i
}

// splitVersion splits a raw [E:]V[-R] version. ok is false for a bad epoch.
func splitVersion(version string) (dep, bool) {
	if version == "" {
		return dep{}, true
	}

	d := dep{epoch: "0"}
	rest := version

	if i := strings.IndexByte(version, ':'); i >= 0 {
		if strtolEnd(version) != i {
			return dep{}, false
		}

		if i > 0 {
			d.epoch = version[:i]
		}

		rest = version[i+1:]
	}

	d.ver, d.rel, _ = strings.Cut(rest, "-")

	return d, true
}

func newDep(d rpmfile.Dep) (dep, bool) {
	out, ok := splitVersion(d.Version)
	out.name = d.Name
	out.flags = flagString(d.Flags)

	return out, ok
}

// appendDeps appends the entries of in that have a good epoch.
func appendDeps(out []dep, in []rpmfile.Dep) []dep {
	for _, d := range in {
		if e, ok := newDep(d); ok {
			out = append(out, e)
		}
	}

	return out
}

// compareLibc compares two libc.so.6 names: 0 same, 1 a higher, 2 b higher,
// -1 when neither has a ")" after its "(".
func compareLibc(a, b string) int {
	ia, ib := strings.IndexByte(a, '('), strings.IndexByte(b, '(')

	switch {
	case ia < 0 && ib < 0:
		return 0
	case ia < 0:
		return 2
	case ib < 0:
		return 1
	}

	ea, eb := strings.IndexByte(a[ia:], ')'), strings.IndexByte(b[ib:], ')')

	switch {
	case ea < 0 && eb < 0:
		return -1
	case ea < 0:
		return 2
	case eb < 0:
		return 1
	}

	ea += ia
	eb += ib

	switch {
	case ia+1 == ea && ib+1 == eb:
		return 0
	case ia+1 == ea:
		return 2
	case ib+1 == eb:
		return 1
	}

	// The first digit may lie past the ")", or nowhere.
	da, db := len(a), len(b)
	if i := strings.IndexAny(a[ia:], "0123456789"); i >= 0 {
		da = ia + i
	}

	if i := strings.IndexAny(b[ib:], "0123456789"); i >= 0 {
		db = ib + i
	}

	switch {
	case da > ea && db > eb:
		return 0
	case da > ea:
		return 2
	case db > eb:
		return 1
	}

	if rc := rpmvercmp(a[da:ea], b[db:eb]); rc != -1 {
		return rc
	}

	return 2
}

// buildDeps builds the eight output lists of p in the order and with the
// filters of the reference writer.
func buildDeps(p rpmfile.Package) depLists {
	var l depLists

	provided := make(map[string]struct{}, len(p.Provides))

	for _, d := range p.Provides {
		e, ok := newDep(d)
		if !ok {
			continue
		}

		provided[strings.Join([]string{d.Name, e.flags, d.Version}, "")] = struct{}{}
		l.provides = append(l.provides, e)
	}

	l.conflicts = appendDeps(nil, p.Conflicts)
	l.obsoletes = appendDeps(nil, p.Obsoletes)
	l.requires, l.recommends = buildRequires(p, provided)
	l.suggests = appendDeps(nil, p.Suggests)
	l.enhances = appendDeps(nil, p.Enhances)
	l.recommends = appendDeps(l.recommends, p.Recommends)
	l.supplements = appendDeps(nil, p.Supplements)

	for _, d := range p.OldSuggests {
		e, ok := newDep(d)

		switch {
		case !ok:
		case d.Flags&flagStrong != 0:
			l.recommends = append(l.recommends, e)
		default:
			l.suggests = append(l.suggests, e)
		}
	}

	for _, d := range p.OldEnhances {
		e, ok := newDep(d)

		switch {
		case !ok:
		case d.Flags&flagStrong != 0:
			l.supplements = append(l.supplements, e)
		default:
			l.enhances = append(l.enhances, e)
		}
	}

	return l
}

// buildRequires returns the requires and the requires that move to
// recommends.
func buildRequires(p rpmfile.Package, provided map[string]struct{}) ([]dep, []dep) {
	files := make(map[string]struct{}, len(p.Files))
	for _, f := range p.Files {
		files[f.Path] = struct{}{}
	}

	var (
		requires, recommends []dep
		libc                 *dep
	)

	last := make(map[string]keptRequire)

	for _, d := range p.Requires {
		if strings.HasPrefix(d.Name, rpmlibPrefix) {
			continue
		}

		if _, own := files[d.Name]; own && strings.HasPrefix(d.Name, "/") && inPrimary(d.Name) {
			continue
		}

		flags := flagString(d.Flags)

		if _, ok := provided[strings.Join([]string{d.Name, flags, d.Version}, "")]; ok {
			continue
		}

		kept := keptRequire{flags: flags, version: d.Version, pre: d.Flags&flagPre != 0}

		if prev, ok := last[d.Name]; ok && prev == kept {
			continue
		}

		e, ok := newDep(d)
		if !ok {
			continue
		}

		if d.Flags&flagMissingOK != 0 {
			recommends = append(recommends, e)
			continue
		}

		e.pre = kept.pre

		if strings.HasPrefix(d.Name, libcPrefix) {
			if libc == nil || compareLibc(libc.name, e.name) == 2 {
				libc = &e
			}

			continue
		}

		requires = append(requires, e)
		last[d.Name] = kept
	}

	if libc != nil {
		requires = append(requires, *libc)
	}

	return requires, recommends
}

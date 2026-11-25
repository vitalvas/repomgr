package rpmfile

import "fmt"

// Dep is one dependency. Version is the raw [E:]V[-R] string, empty when the
// dependency has no version.
type Dep struct {
	Name    string
	Flags   uint32
	Version string
}

// depKind lists the three tags of one dependency kind, from rpm 4.14.3
// lib/rpmtag.h.
type depKind struct {
	name    string
	names   uint32
	flags   uint32
	version uint32
	dst     func(*Package) *[]Dep
}

var depKinds = []depKind{
	{"provides", 1047, 1112, 1113, func(p *Package) *[]Dep { return &p.Provides }},
	{"requires", 1049, 1048, 1050, func(p *Package) *[]Dep { return &p.Requires }},
	{"conflicts", 1054, 1053, 1055, func(p *Package) *[]Dep { return &p.Conflicts }},
	{"obsoletes", 1090, 1114, 1115, func(p *Package) *[]Dep { return &p.Obsoletes }},
	{"recommends", 5046, 5048, 5047, func(p *Package) *[]Dep { return &p.Recommends }},
	{"suggests", 5049, 5051, 5050, func(p *Package) *[]Dep { return &p.Suggests }},
	{"supplements", 5052, 5054, 5053, func(p *Package) *[]Dep { return &p.Supplements }},
	{"enhances", 5055, 5057, 5056, func(p *Package) *[]Dep { return &p.Enhances }},
	{"old suggests", 1156, 1158, 1157, func(p *Package) *[]Dep { return &p.OldSuggests }},
	{"old enhances", 1159, 1161, 1160, func(p *Package) *[]Dep { return &p.OldEnhances }},
}

// dependencies fills the dependency lists of p. A kind with no name tag has no
// dependencies; one with a name tag needs the flags and version tags too, with
// the same count.
func (h header) dependencies(p *Package) error {
	for _, k := range depKinds {
		first, ok := h.entries[k.names]
		if !ok {
			continue
		}

		// Comparing the counts first means a mismatched header allocates nothing.
		flagsEntry, okFlags := h.entries[k.flags]
		versionsEntry, okVersions := h.entries[k.version]

		if !okFlags || !okVersions || flagsEntry.count != first.count || versionsEntry.count != first.count {
			return fmt.Errorf("%w: %s names, flags, and versions do not match", ErrInvalidField, k.name)
		}

		names, _, err := h.strings(k.names, k.name)
		if err != nil {
			return err
		}

		flags, _, err := h.int32s(k.flags, fmt.Sprintf("%s flags", k.name))
		if err != nil {
			return err
		}

		versions, _, err := h.strings(k.version, fmt.Sprintf("%s versions", k.name))
		if err != nil {
			return err
		}

		deps := make([]Dep, len(names))

		for i := range names {
			deps[i] = Dep{Name: names[i], Flags: flags[i], Version: versions[i]}
		}

		*k.dst(p) = deps
	}

	return nil
}

package rpmrepo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

func TestTextValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		bad  bool
	}{
		{name: "plain ASCII", in: "tree", want: "tree"},
		{name: "empty", in: "", want: ""},
		{name: "valid UTF-8", in: "caf\xc3\xa9 \xe4\xb8\xad \xf0\x9f\x98\x80", want: "caf\xc3\xa9 \xe4\xb8\xad \xf0\x9f\x98\x80"},
		{name: "control byte in a valid value is kept", in: "a\x01b", want: "a\x01b"},
		{name: "lone Latin-1 byte", in: "caf\xe9", want: "caf\xc3\xa9"},
		{name: "bytes 0x80 to 0xBF are dropped", in: "a\x80\x9f\xbfb", want: "ab"},
		{name: "control byte in a converted value is dropped", in: "\xe9\x01\x1fx", want: "\xc3\xa9x"},
		{name: "tab newline and carriage return are kept when converted", in: "\xe9\t\n\r", want: "\xc3\xa9\t\n\r"},
		{name: "one bad byte converts the whole value", in: "\xc3\xa9\xe9", want: "\xc3\x83\xc3\xa9"},
		{name: "a lead byte at the end has no continuation byte", in: "a\xc3", want: "a\xc3\x83"},
		{name: "F8 fails the loose check", in: "\xf8\x80", want: "\xc3\xb8"},
		{name: "overlong form", in: "\xc1\x81", bad: true},
		{name: "surrogate", in: "\xed\xa0\x80", bad: true},
		{name: "above U+10FFFF", in: "\xf4\x90\x80\x80", bad: true},
		{name: "U+FFFE", in: "a\xef\xbf\xbe", bad: true},
		{name: "U+FFFF", in: "\xef\xbf\xbfa", bad: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := textValue(tt.in)
			if tt.bad {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// textPackage is a valid package that has a value in every checked field.
func textPackage() rpmfile.Package {
	p := samplePackage().pkg
	p.Summary = "summary"
	p.Description = "description"
	p.URL = "https://example.com/"
	p.License = "MIT"
	p.Vendor = "vendor"
	p.Group = "group"
	p.BuildHost = "host"
	p.Packager = "packager"
	p.Provides = []rpmfile.Dep{{Name: "pdns", Flags: 8, Version: "1:5.1.0-1.el9"}}
	p.Requires = []rpmfile.Dep{{Name: "libfoo", Flags: 12, Version: "1:2-3"}}
	p.Files = []rpmfile.File{{Path: "/usr/bin/pdns", Mode: 0o100755}, {Path: "/usr/share/doc/pdns", Mode: 0o040755}}
	p.Changelog = []rpmfile.ChangelogEntry{{Time: 1, Author: "A <a@example.com> - 1-1", Text: "- first"}}

	return p
}

func TestCheckText(t *testing.T) {
	t.Run("valid package", func(t *testing.T) {
		assert.NoError(t, checkText(textPackage()))
	})

	refused := []struct {
		name  string
		field string
		edit  func(p *rpmfile.Package, v string)
	}{
		{"name", "NAME", func(p *rpmfile.Package, v string) { p.Name = v }},
		{"arch", "ARCH", func(p *rpmfile.Package, v string) { p.Arch = v }},
		{"version", "VERSION", func(p *rpmfile.Package, v string) { p.Version = v }},
		{"release", "RELEASE", func(p *rpmfile.Package, v string) { p.Release = v }},
		{"summary", "SUMMARY", func(p *rpmfile.Package, v string) { p.Summary = v }},
		{"description", "DESCRIPTION", func(p *rpmfile.Package, v string) { p.Description = v }},
		{"url", "URL", func(p *rpmfile.Package, v string) { p.URL = v }},
		{"license", "LICENSE", func(p *rpmfile.Package, v string) { p.License = v }},
		{"vendor", "VENDOR", func(p *rpmfile.Package, v string) { p.Vendor = v }},
		{"group", "GROUP", func(p *rpmfile.Package, v string) { p.Group = v }},
		{"build host", "BUILDHOST", func(p *rpmfile.Package, v string) { p.BuildHost = v }},
		{"source rpm", "SOURCERPM", func(p *rpmfile.Package, v string) { p.SourceRPM = v }},
		{"packager", "PACKAGER", func(p *rpmfile.Package, v string) { p.Packager = v }},
		{"provides name", `provides entry "x`, func(p *rpmfile.Package, v string) { p.Provides[0].Name = fmt.Sprintf("x%s", v) }},
		{"requires name", `requires entry "x`, func(p *rpmfile.Package, v string) { p.Requires[0].Name = fmt.Sprintf("x%s", v) }},
		{"requires version", `requires entry "libfoo"`, func(p *rpmfile.Package, v string) { p.Requires[0].Version = fmt.Sprintf("1:2%s-3", v) }},
		{"requires release", `requires entry "libfoo"`, func(p *rpmfile.Package, v string) { p.Requires[0].Version = fmt.Sprintf("1:2-3%s", v) }},
		{"conflicts name", `conflicts entry "x`, func(p *rpmfile.Package, v string) { p.Conflicts = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"obsoletes name", `obsoletes entry "x`, func(p *rpmfile.Package, v string) { p.Obsoletes = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"suggests name", `suggests entry "x`, func(p *rpmfile.Package, v string) { p.Suggests = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"enhances name", `enhances entry "x`, func(p *rpmfile.Package, v string) { p.Enhances = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"recommends name", `recommends entry "x`, func(p *rpmfile.Package, v string) { p.Recommends = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"supplements name", `supplements entry "x`, func(p *rpmfile.Package, v string) { p.Supplements = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v)}} }},
		{"require moved to recommends", `recommends entry "x`, func(p *rpmfile.Package, v string) {
			p.Requires = []rpmfile.Dep{{Name: fmt.Sprintf("x%s", v), Flags: 1 << 19}}
		}},
		{"file path", "file 1", func(p *rpmfile.Package, v string) { p.Files[1].Path = fmt.Sprintf("/usr/share/doc/x%s", v) }},
		{"changelog author", "changelog entry 0 author", func(p *rpmfile.Package, v string) { p.Changelog[0].Author = fmt.Sprintf("A%s", v) }},
		{"changelog text", "changelog entry 0 text", func(p *rpmfile.Package, v string) { p.Changelog[0].Text = fmt.Sprintf("- x%s", v) }},
	}

	t.Run("control byte refused", func(t *testing.T) {
		for _, tt := range refused {
			for _, b := range []string{"\x01", "\x08", "\x0b", "\x1f"} {
				p := textPackage()
				tt.edit(&p, b)

				err := checkText(p)
				require.ErrorIs(t, err, rpmfile.ErrInvalidField, tt.name)
				assert.Contains(t, err.Error(), tt.field, tt.name)
				assert.Contains(t, err.Error(), "control", tt.name)
			}
		}
	})

	t.Run("control byte in a converted value refused", func(t *testing.T) {
		for _, tt := range refused {
			p := textPackage()
			tt.edit(&p, "\xe9\x01")

			err := checkText(p)
			require.ErrorIs(t, err, rpmfile.ErrInvalidField, tt.name)
			assert.Contains(t, err.Error(), tt.field, tt.name)
			assert.Contains(t, err.Error(), "control", tt.name)
		}
	})

	t.Run("text refused", func(t *testing.T) {
		for _, tt := range refused {
			p := textPackage()
			tt.edit(&p, "\xed\xa0\x80")

			err := checkText(p)
			require.ErrorIs(t, err, rpmfile.ErrInvalidField, tt.name)
			assert.Contains(t, err.Error(), tt.field, tt.name)
			assert.Contains(t, err.Error(), "UTF-8", tt.name)
		}
	})

	t.Run("Latin-1 passes", func(t *testing.T) {
		for _, tt := range refused {
			p := textPackage()
			tt.edit(&p, "\xe9")

			assert.NoError(t, checkText(p), tt.name)
		}
	})

	t.Run("control byte in the epoch refused", func(t *testing.T) {
		p := textPackage()
		p.Requires[0].Version = "\v1:2-3"

		err := checkText(p)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		assert.Contains(t, err.Error(), `requires entry "libfoo"`)
	})

	t.Run("control byte in a dependency that is not written refused", func(t *testing.T) {
		p := textPackage()
		p.Conflicts = []rpmfile.Dep{{Name: "", Flags: 8, Version: "1\x01"}, {Name: "y", Version: "1\x01"}}

		require.ErrorIs(t, checkText(p), rpmfile.ErrInvalidField)
	})

	t.Run("tab newline and carriage return pass", func(t *testing.T) {
		p := textPackage()
		p.Summary = "a\tb"
		p.Description = "line one\r\nline two\n"
		p.Changelog[0].Text = "- one\n\t- two"
		p.Requires[0].Name = "a\tb"

		assert.NoError(t, checkText(p))
	})

	t.Run("dropped require passes", func(t *testing.T) {
		p := textPackage()
		p.Requires = []rpmfile.Dep{{Name: "rpmlib(Foo\x01\xed\xa0\x80)", Flags: 8, Version: "1\x01"}}

		assert.NoError(t, checkText(p))
	})

	t.Run("text not written passes", func(t *testing.T) {
		p := textPackage()
		p.Conflicts = []rpmfile.Dep{{Name: "", Flags: 8, Version: "\xed\xa0\x80"}, {Name: "y", Version: "\xed\xa0\x80"}}

		assert.NoError(t, checkText(p))
	})

	t.Run("changelog entry past the limit passes", func(t *testing.T) {
		p := textPackage()
		p.Changelog = nil

		for i := range changelogLimit {
			p.Changelog = append(p.Changelog, rpmfile.ChangelogEntry{Time: uint32(100 - i), Author: "A", Text: "- x"})
		}

		p.Changelog = append(p.Changelog, rpmfile.ChangelogEntry{Time: 1, Author: "B\x01\xed\xa0\x80", Text: "- y\x01\xed\xa0\x80"})
		assert.NoError(t, checkText(p))

		p.Changelog[changelogLimit-1].Text = "- z\x01"
		err := checkText(p)
		require.ErrorIs(t, err, rpmfile.ErrInvalidField)
		assert.Contains(t, err.Error(), fmt.Sprintf("changelog entry %d text", changelogLimit-1))
	})
}

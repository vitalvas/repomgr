package rpmfile

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/rpmtest"
)

const (
	sigEntryOffset  int = 96 + 16
	sigDigestOffset int = 96 + 16 + 16
	sigDataSize     int = 65
)

func basePackage() rpmtest.Package {
	return rpmtest.Package{
		Name:    "pdns",
		Version: "5.1.0",
		Release: "1.el9",
		Arch:    "x86_64",
		Payload: []byte("payload bytes"),

		SourceRPM: "pdns-5.1.0-1.el9.src.rpm",
	}
}

func build(t *testing.T, p rpmtest.Package) []byte {
	t.Helper()

	data, err := rpmtest.Build(p)
	require.NoError(t, err)

	return data
}

// mainRange returns the offsets of the main header in a built package.
func mainRange(data []byte) (int, int) {
	sigLen := 16 + 16 + int(binary.BigEndian.Uint32(data[108:]))
	start := 96 + sigLen + (8-sigLen%8)%8
	entries := int(binary.BigEndian.Uint32(data[start+8:]))
	size := int(binary.BigEndian.Uint32(data[start+12:]))

	return start, start + 16 + entries*16 + size
}

func patched(data []byte, offset int, value ...byte) []byte {
	out := slices.Clone(data)
	copy(out[offset:], value)

	return out
}

func TestParseRoundTrip(t *testing.T) {
	zero := uint32(0)
	seven := uint32(7)

	tests := []struct {
		name string
		mut  func(*rpmtest.Package)
	}{
		{"minimal", func(*rpmtest.Package) {}},
		{"epoch zero", func(p *rpmtest.Package) { p.Epoch = &zero }},
		{"epoch and source rpm", func(p *rpmtest.Package) {
			p.Epoch = &seven
			p.SourceRPM = "pdns-5.1.0-1.el9.src.rpm"
		}},
		{"aarch64", func(p *rpmtest.Package) { p.Arch = "aarch64" }},
		{"noarch no payload", func(p *rpmtest.Package) {
			p.Arch = "noarch"
			p.Payload = nil
		}},
		{"extra tags", func(p *rpmtest.Package) {
			p.Tags = []rpmtest.Tag{
				{ID: 1005, Type: 6, Value: "summary"},
				{ID: 2047, Type: 8, Value: []string{"a", "b"}},
				{ID: 2048, Type: 4, Value: []uint32{1, 2, 3}},
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePackage()
			tt.mut(&p)
			data := build(t, p)

			got, err := Parse(bytes.NewReader(data))
			require.NoError(t, err)

			sum := sha256.Sum256(data)
			start, end := mainRange(data)

			assert.Equal(t, p.Name, got.Name)
			assert.Equal(t, p.Version, got.Version)
			assert.Equal(t, p.Release, got.Release)
			assert.Equal(t, p.Arch, got.Arch)
			assert.Equal(t, p.SourceRPM, got.SourceRPM)
			assert.Equal(t, p.Epoch, got.Epoch)
			assert.Equal(t, int64(start), got.HeaderStart)
			assert.Equal(t, int64(end), got.HeaderEnd)
			assert.Equal(t, int64(len(data)), got.Size)
			assert.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
		})
	}
}

func TestParseLeadErrors(t *testing.T) {
	good := build(t, basePackage())
	source := basePackage()
	source.Source = true

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "read lead"},
		{"short lead", good[:50], "read lead"},
		{"bad magic", patched(good, 0, 0), "not an rpm"},
		{"major 2", patched(good, 4, 2), "unsupported rpm major version 2"},
		{"major 5", patched(good, 4, 5), "unsupported rpm major version 5"},
		{"major 4", patched(good, 4, 4), ""},
		{"signature type 4", patched(good, 79, 4), "unsupported signature type 4"},
		{"source package", build(t, source), "source packages are not supported"},
		{"unknown type", patched(good, 7, 2), "unsupported package type 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(tt.data))
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}

			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestParseHeaderErrors(t *testing.T) {
	good := build(t, basePackage())
	start, _ := mainRange(good)
	entry1 := start + 16 + 16

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"signature magic", patched(good, 96, 0), "signature header"},
		{"main magic", patched(good, start, 0), "main header"},
		{"entry type 10", patched(good, entry1+4, 0, 0, 0, 10), "type 10"},
		{"entry offset negative", patched(good, entry1+8, 0xff, 0xff, 0xff, 0xff), "offset"},
		{"entry offset past data", patched(good, entry1+8, 0x7f, 0xff, 0xff, 0xff), "offset"},
		{"digest tag missing", patched(good, sigEntryOffset+3, 0x12), "no header digest"},
		{"digest wrong type", patched(good, sigEntryOffset+7, 7), "digest"},
		{"digest non hex", patched(good, sigDigestOffset, 'g'), "digest"},
		{"digest mismatch", patched(good, sigDigestOffset, flip(good[sigDigestOffset])), "does not match"},
		{"main header edited", bytes.Replace(good, []byte("5.1.0"), []byte("5.1.1"), 1), "does not match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(tt.data))
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestParseSHA1HeaderDigest(t *testing.T) {
	plain := build(t, basePackage())
	start, end := mainRange(plain)
	sum := sha1.Sum(plain[start:end])
	good := hex.EncodeToString(sum[:])

	// withSHA1 builds the package with SHA1HEADER (269) holding value. The
	// signature header then has two entries: 273 first, then 269, and the
	// SHA-1 string starts right after the 65-byte SHA-256 string.
	withSHA1 := func(t *testing.T, tag rpmtest.Tag) []byte {
		t.Helper()

		p := basePackage()
		p.SigTags = []rpmtest.Tag{tag}

		return build(t, p)
	}

	const (
		twoEntryData = 96 + 16 + 32
		sha1Data     = twoEntryData + 65
	)

	// dropSHA256 renames tag 273 to 274, which no reader looks at.
	dropSHA256 := func(data []byte) []byte {
		return patched(data, sigEntryOffset+3, 0x12)
	}

	valid := withSHA1(t, rpmtest.Tag{ID: 269, Type: 6, Value: good})

	t.Run("both digests", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(valid))
		assert.NoError(t, err)
	})

	t.Run("SHA-1 alone", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(dropSHA256(valid)))
		assert.NoError(t, err)
	})

	t.Run("SHA-1 alone in upper case", func(t *testing.T) {
		upper := withSHA1(t, rpmtest.Tag{ID: 269, Type: 6, Value: strings.ToUpper(good)})
		_, err := Parse(bytes.NewReader(dropSHA256(upper)))
		assert.NoError(t, err)
	})

	t.Run("SHA-1 alone mismatch", func(t *testing.T) {
		bad := patched(dropSHA256(valid), sha1Data, flip(valid[sha1Data]))
		_, err := Parse(bytes.NewReader(bad))
		assert.ErrorContains(t, err, "SHA-1")
		assert.ErrorContains(t, err, "does not match")
	})

	t.Run("SHA-1 mismatch with a good SHA-256", func(t *testing.T) {
		bad := patched(valid, sha1Data, flip(valid[sha1Data]))
		_, err := Parse(bytes.NewReader(bad))
		assert.ErrorContains(t, err, "SHA-1")
	})

	t.Run("SHA-256 mismatch with a good SHA-1", func(t *testing.T) {
		bad := patched(valid, twoEntryData, flip(valid[twoEntryData]))
		_, err := Parse(bytes.NewReader(bad))
		assert.ErrorContains(t, err, "SHA-256")
	})

	t.Run("SHA-1 not 40 hex digits", func(t *testing.T) {
		for _, value := range []string{good[:38], strings.Repeat("g", 40), fmt.Sprintf("%s00", good)} {
			bad := withSHA1(t, rpmtest.Tag{ID: 269, Type: 6, Value: value})
			_, err := Parse(bytes.NewReader(dropSHA256(bad)))
			require.ErrorIs(t, err, ErrInvalidField, value)
			assert.ErrorContains(t, err, "SHA-1 header digest", value)
		}
	})

	t.Run("SHA-1 wrong type", func(t *testing.T) {
		bad := withSHA1(t, rpmtest.Tag{ID: 269, Type: 7, Value: []byte(good)})
		_, err := Parse(bytes.NewReader(dropSHA256(bad)))
		assert.ErrorContains(t, err, "SHA-1 header digest")
	})
}

func TestParseUppercaseHeaderDigest(t *testing.T) {
	good := build(t, basePackage())
	upper := patched(good, sigDigestOffset, bytes.ToUpper(good[sigDigestOffset:sigDigestOffset+64])...)

	_, err := Parse(bytes.NewReader(upper))
	assert.NoError(t, err)
}

func flip(b byte) byte {
	if b == '0' {
		return '1'
	}

	return '0'
}

func TestParseLimits(t *testing.T) {
	good := build(t, basePackage())
	start, end := mainRange(good)
	mainData := end - start - 16 - int(binary.BigEndian.Uint32(good[start+8:]))*16

	sigEntries := binary.BigEndian.Uint32(good[96+8:])
	mainEntries := binary.BigEndian.Uint32(good[start+8:])
	exact := limits{
		signature: headerLimit{entries: sigEntries, data: uint32(sigDataSize)},
		main:      headerLimit{entries: mainEntries, data: uint32(mainData)},
	}

	t.Run("data and entries at the limit", func(t *testing.T) {
		_, err := parse(bytes.NewReader(good), exact)
		assert.NoError(t, err)
	})

	t.Run("signature data over the limit", func(t *testing.T) {
		lim := exact
		lim.signature.data--
		_, err := parse(bytes.NewReader(good), lim)
		assert.ErrorContains(t, err, "signature header data")
	})

	t.Run("signature entries one over the limit", func(t *testing.T) {
		lim := exact
		lim.signature.entries--
		_, err := parse(bytes.NewReader(good), lim)
		assert.ErrorContains(t, err, "signature header has")
	})

	t.Run("main data over the limit", func(t *testing.T) {
		lim := exact
		lim.main.data--
		_, err := parse(bytes.NewReader(good), lim)
		assert.ErrorContains(t, err, "main header data")
	})

	t.Run("main entries over the limit", func(t *testing.T) {
		lim := exact
		lim.main.entries--
		_, err := parse(bytes.NewReader(good), lim)
		assert.ErrorContains(t, err, "main header has")
	})

	t.Run("limits are rpm's", func(t *testing.T) {
		assert.Equal(t, headerLimit{entries: 32, data: 8192}, rpmLimits.signature)
		assert.Equal(t, headerLimit{entries: 0xffff, data: 0x0fffffff}, rpmLimits.main)
	})

	t.Run("signature limits", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(patched(good, 96+8, 0, 0, 0, 33)))
		assert.ErrorContains(t, err, "signature header has 33 entries, limit 32")

		_, err = Parse(bytes.NewReader(patched(good, 96+12, 0, 0, 0x20, 0x01)))
		assert.ErrorContains(t, err, "signature header data is 8193 bytes, limit 8192")

		_, err = Parse(bytes.NewReader(patched(good[:96+16], 96+12, 0, 0, 0x20, 0x00)))
		assert.ErrorContains(t, err, "read signature header")
		assert.NotContains(t, err.Error(), "limit")
	})

	t.Run("main data limit", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(patched(good[:start+16], start+12, 0x10, 0, 0, 0)))
		assert.ErrorContains(t, err, "main header data is 268435456 bytes, limit 268435455")

		_, err = Parse(bytes.NewReader(patched(good[:start+16], start+12, 0x0f, 0xff, 0xff, 0xff)))
		assert.ErrorContains(t, err, "read main header")
		assert.NotContains(t, err.Error(), "limit")
	})

	t.Run("data limit is checked before reading data", func(t *testing.T) {
		huge := patched(good[:start+16], start+12, 0xff, 0xff, 0xff, 0xff)
		_, err := Parse(bytes.NewReader(huge))
		assert.ErrorContains(t, err, "main header data")
	})

	entries := func(t *testing.T, total int) []byte {
		t.Helper()

		p := basePackage()
		base := int(binary.BigEndian.Uint32(good[start+8:]))

		for i := range total - base {
			p.Tags = append(p.Tags, rpmtest.Tag{ID: uint32(100000 + i), Type: 7, Value: []byte{0}})
		}

		return build(t, p)
	}

	t.Run("main entries at the limit", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(entries(t, 65535)))
		assert.NoError(t, err)
	})

	t.Run("main entries over rpm's limit", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(entries(t, 65536)))
		assert.ErrorContains(t, err, "65536 entries")
	})

	t.Run("signature entries over the limit", func(t *testing.T) {
		_, err := Parse(bytes.NewReader(patched(good, 96+8, 0, 1, 0, 0)))
		assert.ErrorContains(t, err, "signature header has 65536 entries")
	})
}

func TestParseTruncations(t *testing.T) {
	p := basePackage()
	p.Payload = nil
	data := build(t, p)

	for n := range data {
		_, err := Parse(bytes.NewReader(data[:n]))
		assert.Error(t, err, "prefix of %d bytes", n)
	}

	_, err := Parse(bytes.NewReader(data))
	assert.NoError(t, err)
}

func TestParseTruncatedPayloadIsNotInspected(t *testing.T) {
	data := build(t, basePackage())

	got, err := Parse(bytes.NewReader(data[:len(data)-3]))
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)-3), got.Size)
}

func TestParseReadError(t *testing.T) {
	boom := errors.New("boom")
	data := build(t, basePackage())

	_, err := Parse(io.MultiReader(bytes.NewReader(data), iotest.ErrReader(boom)))
	assert.ErrorIs(t, err, boom)
}

func TestParseValidation(t *testing.T) {
	tests := []struct {
		name  string
		field string
		mut   func(*rpmtest.Package)
	}{
		{"name empty", "NAME", func(p *rpmtest.Package) { p.Name = "" }},
		{"name leading dash", "NAME", func(p *rpmtest.Package) { p.Name = "-pdns" }},
		{"name space", "NAME", func(p *rpmtest.Package) { p.Name = "p dns" }},
		{"name slash", "NAME", func(p *rpmtest.Package) { p.Name = "a/b" }},
		{"version empty", "VERSION", func(p *rpmtest.Package) { p.Version = "" }},
		{"version colon", "VERSION", func(p *rpmtest.Package) { p.Version = "1:2" }},
		{"version dash", "VERSION", func(p *rpmtest.Package) { p.Version = "1-2" }},
		{"release empty", "RELEASE", func(p *rpmtest.Package) { p.Release = "" }},
		{"release dash", "RELEASE", func(p *rpmtest.Package) { p.Release = "1-el9" }},
		{"arch empty", "ARCH", func(p *rpmtest.Package) { p.Arch = "" }},
		{"arch i686", "ARCH", func(p *rpmtest.Package) { p.Arch = "i686" }},
		{"arch case", "ARCH", func(p *rpmtest.Package) { p.Arch = "X86_64" }},
		{"sourcerpm traversal", "SOURCERPM", func(p *rpmtest.Package) { p.SourceRPM = "../../x-1-1.src.rpm" }},
		{"sourcerpm slash", "SOURCERPM", func(p *rpmtest.Package) { p.SourceRPM = "a/b-1-1.src.rpm" }},
		{"sourcerpm one dash", "SOURCERPM", func(p *rpmtest.Package) { p.SourceRPM = "x-1.src.rpm" }},
		{"sourcerpm wrong suffix", "SOURCERPM", func(p *rpmtest.Package) { p.SourceRPM = "x-1-1.rpm" }},
		{"sourcerpm empty name", "SOURCERPM", func(p *rpmtest.Package) { p.SourceRPM = "-1-1.src.rpm" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePackage()
			tt.mut(&p)

			_, err := Parse(bytes.NewReader(build(t, p)))
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.field)
		})
	}

	t.Run("accepted values", func(t *testing.T) {
		p := basePackage()
		p.Name = "libfoo_bar+1.x-y"
		p.Version = "1.0~rc1^git2"
		p.Release = "0.1.el8_9"

		_, err := Parse(bytes.NewReader(build(t, p)))
		assert.NoError(t, err)
	})
}

// identityData holds the strings of validEntries: NAME, VERSION, RELEASE, ARCH,
// SOURCERPM, then 8 aligned bytes at offset 36 for the EPOCH cases.
var identityData = []byte("pdns\x001\x001\x00x86_64\x00pdns-1-1.src.rpm\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

func validEntries() [][4]int32 {
	return [][4]int32{
		{1000, 6, 0, 1},
		{1001, 6, 5, 1},
		{1002, 6, 7, 1},
		{1022, 6, 9, 1},
		{1044, 6, 16, 1},
	}
}

func identityOf(t *testing.T, entries [][4]int32) (Package, error) {
	t.Helper()

	h, err := readHeader(bytes.NewReader(rawHeader(entries, identityData)), "main", headerLimit{entries: rpmLimits.main.entries, data: 1024})
	require.NoError(t, err)

	return h.identity()
}

func TestIdentity(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		p, err := identityOf(t, validEntries())
		require.NoError(t, err)
		assert.Equal(t, "pdns", p.Name)
		assert.Equal(t, "pdns-1-1.src.rpm", p.SourceRPM)
		assert.Nil(t, p.Epoch)
	})

	t.Run("missing required tag", func(t *testing.T) {
		for i, field := range []string{"NAME", "VERSION", "RELEASE", "ARCH"} {
			entries := slices.Delete(validEntries(), i, i+1)

			_, err := identityOf(t, entries)
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, field)
			assert.ErrorContains(t, err, "missing")
		}
	})

	t.Run("no SOURCERPM is a source package", func(t *testing.T) {
		_, err := identityOf(t, validEntries()[:4])
		assert.EqualError(t, err, "source packages are not supported")
	})

	wrong := []struct {
		name  string
		field string
		entry [4]int32
		index int
	}{
		{"name wrong type", "NAME", [4]int32{1000, 4, 0, 1}, 0},
		{"sourcerpm wrong type", "SOURCERPM", [4]int32{1044, 7, 16, 1}, 4},
	}

	for _, tt := range wrong {
		t.Run(tt.name, func(t *testing.T) {
			entries := validEntries()
			entries[tt.index] = tt.entry

			_, err := identityOf(t, entries)
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.field)
		})
	}

	epochs := []struct {
		name  string
		entry [4]int32
	}{
		{"epoch wrong type", [4]int32{1003, 6, 36, 1}},
		{"epoch two values", [4]int32{1003, 4, 36, 2}},
	}

	for _, tt := range epochs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := identityOf(t, append(validEntries(), tt.entry))
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, "EPOCH")
		})
	}
}

func TestValidate(t *testing.T) {
	valid := Package{Name: "pdns", Version: "1.0~rc1", Release: "1.el9", Arch: "x86_64", SourceRPM: "pdns-1-1.src.rpm"}

	require.NoError(t, valid.Validate())

	nosrc := valid
	nosrc.SourceRPM = "pdns-1-1.nosrc.rpm"
	require.NoError(t, nosrc.Validate())

	tests := []struct {
		name  string
		field string
		edit  func(p *Package)
	}{
		{"empty name", "NAME", func(p *Package) { p.Name = "" }},
		{"bad name", "NAME", func(p *Package) { p.Name = "-x" }},
		{"bad version", "VERSION", func(p *Package) { p.Version = "1 2" }},
		{"empty release", "RELEASE", func(p *Package) { p.Release = "" }},
		{"bad arch", "ARCH", func(p *Package) { p.Arch = "i686" }},
		{"no srpm suffix", "SOURCERPM", func(p *Package) { p.SourceRPM = "pdns-1-1.rpm" }},
		{"bad srpm name", "SOURCERPM", func(p *Package) { p.SourceRPM = "pdns.src.rpm" }},
		{"bad nosrc name", "SOURCERPM", func(p *Package) { p.SourceRPM = "pdns.nosrc.rpm" }},
		{"other src suffix", "SOURCERPM", func(p *Package) { p.SourceRPM = "pdns-1-1.xsrc.rpm" }},
		{"empty srpm", "SOURCERPM", func(p *Package) { p.SourceRPM = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid
			tt.edit(&p)

			err := p.Validate()
			require.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.field)
		})
	}
}

func TestParseSourcePackageWithoutSourceRPM(t *testing.T) {
	p := basePackage()
	p.SourceRPM = ""
	p.NoSourceRPM = true
	data := build(t, p)
	require.Equal(t, byte(0), data[7], "lead says binary")

	_, err := Parse(bytes.NewReader(data))
	assert.EqualError(t, err, "source packages are not supported")
}

func TestParseSourcePackageTag(t *testing.T) {
	tests := []struct {
		name    string
		typ     uint32
		value   any
		refused bool
	}{
		{"int8 nonzero", 2, []byte{1}, true},
		{"int16 nonzero", 3, []uint16{1}, true},
		{"int32 nonzero", 4, []uint32{1}, true},
		{"int64 nonzero", 5, []uint64{1}, true},
		{"int32 high bit", 4, []uint32{1 << 31}, true},
		{"int32 first element only", 4, []uint32{0, 1}, false},
		{"int32 zero", 4, []uint32{0}, false},
		{"int8 zero", 2, []byte{0}, false},
		{"string", 6, "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePackage()
			p.Tags = []rpmtest.Tag{{ID: 1106, Type: tt.typ, Value: tt.value}}

			_, err := Parse(bytes.NewReader(build(t, p)))
			if tt.refused {
				assert.EqualError(t, err, "source packages are not supported")
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestParseDuplicateTags(t *testing.T) {
	good := build(t, basePackage())
	start, _ := mainRange(good)

	t.Run("main header", func(t *testing.T) {
		// Entry 2 is VERSION; give it the NAME tag.
		data := patched(good, start+16+16*2, 0, 0, 0x03, 0xe8)

		_, err := Parse(bytes.NewReader(data))
		assert.ErrorContains(t, err, "main header has duplicate tag 1000")
	})

	t.Run("signature header", func(t *testing.T) {
		raw := rawHeader([][4]int32{{273, 6, 0, 1}, {273, 6, 0, 1}}, []byte("a\x00"))

		_, err := readHeader(bytes.NewReader(raw), "signature", headerLimit{entries: rpmLimits.main.entries, data: 1024})
		assert.ErrorContains(t, err, "signature header has duplicate tag 273")
	})
}

func TestSourceName(t *testing.T) {
	tests := []struct {
		sourceRPM string
		want      string
	}{
		{"pdns-5.1.0-1.el9.src.rpm", "pdns"},
		{"foo-bar-1.0-1.src.rpm", "foo-bar"},
		{"pdns-5.1.0-1.el9.nosrc.rpm", "pdns"},
		{"foo-bar-1.0-1.nosrc.rpm", "foo-bar"},
		{"foo-bar-baz-1.0-1.el9.src.rpm", "foo-bar-baz"},
		{"../../x-1-1.src.rpm", "../../x"},
		{"a/b-1-1.src.rpm", "a/b"},
		{"-1-1.src.rpm", ""},
		{"x-1.src.rpm", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.sourceRPM), func(t *testing.T) {
			assert.Equal(t, tt.want, Package{SourceRPM: tt.sourceRPM}.SourceName())
		})
	}
}

func TestFileName(t *testing.T) {
	p := Package{Name: "pdns", Version: "5.1.0", Release: "1.el9", Arch: "x86_64"}
	assert.Equal(t, "pdns-5.1.0-1.el9.x86_64.rpm", p.FileName())
}

func BenchmarkParse(b *testing.B) {
	data, err := rpmtest.Build(basePackage())
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := Parse(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzParse(f *testing.F) {
	epoch := uint32(1)
	p := basePackage()
	p.Epoch = &epoch
	p.SourceRPM = "pdns-5.1.0-1.el9.src.rpm"
	p.Tags = depTags(1049, 1048, 1050, depSet{[]string{"libc.so.6", "pdns"}, []uint32{0, 8}, []string{"", "1:5.1.0-1"}})

	seed, err := rpmtest.Build(p)
	require.NoError(f, err)

	f.Add(seed)
	f.Add(seed[:120])
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}

		if got.Size != int64(len(data)) || got.HeaderStart < 96 || got.HeaderEnd < got.HeaderStart || got.HeaderEnd > got.Size {
			t.Fatalf("inconsistent result %+v for %d bytes", got, len(data))
		}
	})
}

// Package rpmfile reads the identity fields of a binary RPM package.
package rpmfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

const (
	leadSize    int    = 96
	srcSuffix   string = ".src.rpm"
	nosrcSuffix string = ".nosrc.rpm"

	leadTypeOffset int    = 6
	leadSigOffset  int    = 78
	signatureType  uint16 = 5
	typeBinary     uint16 = 0
	typeSource     uint16 = 1

	tagSHA1Header   uint32 = 269
	tagSHA256Header uint32 = 273
	tagPayload      uint32 = 5092
	tagName         uint32 = 1000
	tagVersion      uint32 = 1001
	tagRelease      uint32 = 1002
	tagEpoch        uint32 = 1003
	tagArch         uint32 = 1022
	tagSourceRPM    uint32 = 1044

	tagSourcePackage uint32 = 1106
)

var (
	ErrInvalidField = errors.New("invalid package field")

	// A package without SOURCERPM is a source package whatever its lead says.
	errSourcePackage = errors.New("source packages are not supported")

	leadMagic = []byte{0xed, 0xab, 0xee, 0xdb}

	// headerDigests are the signature header digests of the main header, as
	// rpm 4.14.3 (lib/rpmvs.c) verifies them: each one present must be a
	// STRING of exactly that many hex digits and match without regard to case.
	headerDigests = []headerDigest{
		{tag: tagSHA256Header, name: "SHA-256", digits: 64},
		{tag: tagSHA1Header, name: "SHA-1", digits: 40},
	}

	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._+~^]+$`)
	archRe    = regexp.MustCompile(`^(?:x86_64|aarch64|noarch)$`)
)

type Package struct {
	Name      string
	Version   string
	Release   string
	Arch      string
	SourceRPM string
	Epoch     *uint32

	Summary     string
	Description string
	URL         string
	Packager    string
	Vendor      string
	Group       string
	BuildHost   string
	License     string

	BuildTime     uint64
	InstalledSize uint64
	ArchiveSize   uint64

	Provides    []Dep
	Requires    []Dep
	Conflicts   []Dep
	Obsoletes   []Dep
	Recommends  []Dep
	Suggests    []Dep
	Supplements []Dep
	Enhances    []Dep
	OldSuggests []Dep
	OldEnhances []Dep

	Files []File

	// Changelog holds every entry in header order.
	Changelog []ChangelogEntry

	// HeaderStart and HeaderEnd bound the main header in the file, end exclusive.
	HeaderStart int64
	HeaderEnd   int64
	Size        int64
	SHA256      string
}

// headerLimit bounds the entry count and data size of one header.
type headerLimit struct {
	entries uint32
	data    uint32
}

type limits struct {
	signature headerLimit
	main      headerLimit
}

// headerDigest is one signature header tag that holds a hex digest of the
// main header.
type headerDigest struct {
	tag    uint32
	name   string
	digits int
	want   string
}

// readDigests returns the header digests present in the signature header. At
// least one must be present.
func readDigests(sig header) ([]headerDigest, error) {
	var found []headerDigest

	for _, d := range headerDigests {
		label := fmt.Sprintf("%s header digest", d.name)

		want, ok, err := sig.str(d.tag, label)
		if err != nil {
			return nil, err
		}

		if !ok {
			continue
		}

		if _, err := hex.DecodeString(want); err != nil || len(want) != d.digits {
			return nil, fmt.Errorf("%w: %s %q is not %d hex digits", ErrInvalidField, label, want, d.digits)
		}

		d.want = want
		found = append(found, d)
	}

	if len(found) == 0 {
		return nil, errors.New("signature header has no header digest (SHA-256 or SHA-1)")
	}

	return found, nil
}

// checkDigests compares every digest found with the main header.
func checkDigests(main header, wants []headerDigest) error {
	for _, d := range wants {
		got := main.sum
		if d.tag == tagSHA1Header {
			got = main.sha1
		}

		if !strings.EqualFold(got, d.want) {
			return fmt.Errorf("main header %s %s does not match the signature header digest %s", d.name, got, d.want)
		}
	}

	return nil
}

// rpmLimits are the hdrblobRead limits of rpm 4.14.3 (lib/header.c).
var rpmLimits = limits{
	signature: headerLimit{entries: 32, data: 8192},
	main:      headerLimit{entries: 0xffff, data: 0x0fffffff},
}

// counter tracks how many bytes have been read.
type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)

	return n, err
}

// Parse reads the whole input once and returns the package identity, the size
// and SHA-256 of the file, and the byte range of the main header.
func Parse(r io.Reader) (Package, error) {
	return parse(r, rpmLimits)
}

func parse(r io.Reader, lim limits) (Package, error) {
	fileSum := sha256.New()
	src := &counter{r: io.TeeReader(r, fileSum)}

	if err := readLead(src); err != nil {
		return Package{}, err
	}

	sig, err := readHeader(src, "signature", lim.signature)
	if err != nil {
		return Package{}, err
	}

	if _, err := io.CopyN(io.Discard, src, (8-sig.length%8)%8); err != nil {
		return Package{}, fmt.Errorf("read signature header padding: %w", err)
	}

	wants, err := readDigests(sig)
	if err != nil {
		return Package{}, err
	}

	start := src.n

	main, err := readHeader(src, "main", lim.main)
	if err != nil {
		return Package{}, err
	}

	if err := checkDigests(main, wants); err != nil {
		return Package{}, err
	}

	pkg, err := main.identity()
	if err != nil {
		return Package{}, err
	}

	if err := main.fields(sig, &pkg); err != nil {
		return Package{}, err
	}

	if err := main.dependencies(&pkg); err != nil {
		return Package{}, err
	}

	if err := main.files(&pkg); err != nil {
		return Package{}, err
	}

	if err := main.changelog(&pkg); err != nil {
		return Package{}, err
	}

	pkg.HeaderStart = start
	pkg.HeaderEnd = src.n

	payloadSum := sha256.New()
	if _, err := io.Copy(payloadSum, src); err != nil {
		return Package{}, fmt.Errorf("read payload: %w", err)
	}

	if err := main.verifyPayload(hex.EncodeToString(payloadSum.Sum(nil))); err != nil {
		return Package{}, err
	}

	pkg.Size = src.n
	pkg.SHA256 = hex.EncodeToString(fileSum.Sum(nil))

	return pkg, nil
}

func readLead(r io.Reader) error {
	lead := make([]byte, leadSize)
	if _, err := io.ReadFull(r, lead); err != nil {
		return fmt.Errorf("read lead: %w", err)
	}

	if !bytes.Equal(lead[:len(leadMagic)], leadMagic) {
		return errors.New("not an rpm: bad lead magic")
	}

	if major := lead[4]; major != 3 && major != 4 {
		return fmt.Errorf("unsupported rpm major version %d", major)
	}

	if sig := binary.BigEndian.Uint16(lead[leadSigOffset:]); sig != signatureType {
		return fmt.Errorf("unsupported signature type %d", sig)
	}

	switch typ := binary.BigEndian.Uint16(lead[leadTypeOffset:]); typ {
	case typeBinary:
		return nil
	case typeSource:
		return errSourcePackage
	default:
		return fmt.Errorf("unsupported package type %d", typ)
	}
}

// isSourcePackage reports a nonzero first element in an integer SOURCEPACKAGE
// tag. Other types and a zero value are ignored.
func (h header) isSourcePackage() bool {
	e, ok := h.entries[tagSourcePackage]
	if !ok || e.count < 1 || e.typ < typeInt8 || e.typ > typeInt64 {
		return false
	}

	end := e.offset + elementSize[e.typ]
	if end > len(h.data) {
		return false
	}

	return slices.ContainsFunc(h.data[e.offset:end], func(b byte) bool { return b != 0 })
}

func (h header) identity() (Package, error) {
	var p Package

	fields := []struct {
		tag  uint32
		name string
		dst  *string
	}{
		{tagName, "NAME", &p.Name},
		{tagVersion, "VERSION", &p.Version},
		{tagRelease, "RELEASE", &p.Release},
		{tagArch, "ARCH", &p.Arch},
		{tagSourceRPM, "SOURCERPM", &p.SourceRPM},
	}

	for _, f := range fields {
		value, ok, err := h.str(f.tag, f.name)
		if err != nil {
			return Package{}, err
		}

		if !ok {
			if f.tag == tagSourceRPM {
				return Package{}, errSourcePackage
			}

			return Package{}, fmt.Errorf("%w: %s is missing", ErrInvalidField, f.name)
		}

		*f.dst = value
	}

	if err := p.Validate(); err != nil {
		return Package{}, err
	}

	if h.isSourcePackage() {
		return Package{}, errSourcePackage
	}

	epoch, ok, err := h.int32(tagEpoch, "EPOCH")
	if err != nil {
		return Package{}, err
	}

	if ok {
		p.Epoch = &epoch
	}

	return p, nil
}

// Validate checks the NAME, VERSION, RELEASE, ARCH, and SOURCERPM fields.
func (p Package) Validate() error {
	fields := []struct {
		name  string
		value string
		re    *regexp.Regexp
	}{
		{"NAME", p.Name, nameRe},
		{"VERSION", p.Version, versionRe},
		{"RELEASE", p.Release, versionRe},
		{"ARCH", p.Arch, archRe},
	}

	for _, f := range fields {
		if !f.re.MatchString(f.value) {
			return fmt.Errorf("%w: %s %q", ErrInvalidField, f.name, f.value)
		}
	}

	if _, ok := sourceBase(p.SourceRPM); !ok || !nameRe.MatchString(p.SourceName()) {
		return fmt.Errorf("%w: SOURCERPM %q", ErrInvalidField, p.SourceRPM)
	}

	return nil
}

// sourceBase strips the .src.rpm or .nosrc.rpm suffix (rpm writes the latter
// for packages built from a spec with NoSource or NoPatch).
func sourceBase(sourceRPM string) (string, bool) {
	for _, suffix := range []string{srcSuffix, nosrcSuffix} {
		if base, ok := strings.CutSuffix(sourceRPM, suffix); ok {
			return base, true
		}
	}

	return sourceRPM, false
}

// SourceName returns the name part of SourceRPM. It is empty when SourceRPM
// has fewer than two dashes before the suffix, which Parse rejects.
func (p Package) SourceName() string {
	s, _ := sourceBase(p.SourceRPM)

	for range 2 {
		i := strings.LastIndexByte(s, '-')
		if i < 0 {
			return ""
		}

		s = s[:i]
	}

	return s
}

func (p Package) FileName() string {
	return fmt.Sprintf("%s-%s-%s.%s.rpm", p.Name, p.Version, p.Release, p.Arch)
}

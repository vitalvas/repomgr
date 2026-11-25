package rpmfile

import (
	"bytes"
	"fmt"
)

const (
	tagLongArchiveSize uint32 = 271
	tagSummary         uint32 = 1004
	tagDescription     uint32 = 1005
	tagBuildTime       uint32 = 1006
	tagBuildHost       uint32 = 1007
	tagSize            uint32 = 1009
	tagVendor          uint32 = 1011
	tagLicense         uint32 = 1014
	tagPackager        uint32 = 1015
	tagGroup           uint32 = 1016
	tagURL             uint32 = 1020
	tagArchiveSize     uint32 = 1046
	tagLongSize        uint32 = 5009

	// sigTagPayloadSize is RPMSIGTAG_PAYLOADSIZE, which rpm copies into the
	// main header as ARCHIVESIZE.
	sigTagPayloadSize uint32 = 1007
)

// sizeTag is one source of a size: an INT64 tag when wide, else an INT32 tag.
type sizeTag struct {
	h    header
	tag  uint32
	name string
	wide bool
}

// fields fills the descriptive fields and the sizes of p. sig is the signature
// header: rpm copies its tags into the main header when the main header lacks
// them (headerMergeLegacySigs), so it is a fallback source for the archive size.
func (h header) fields(sig header, p *Package) error {
	texts := []struct {
		tag  uint32
		name string
		dst  *string
		i18n bool
	}{
		{tagSummary, "SUMMARY", &p.Summary, true},
		{tagDescription, "DESCRIPTION", &p.Description, true},
		{tagBuildHost, "BUILDHOST", &p.BuildHost, false},
		{tagVendor, "VENDOR", &p.Vendor, false},
		{tagLicense, "LICENSE", &p.License, false},
		{tagPackager, "PACKAGER", &p.Packager, false},
		{tagGroup, "GROUP", &p.Group, true},
		{tagURL, "URL", &p.URL, false},
	}

	for _, f := range texts {
		var err error

		if f.i18n {
			*f.dst, err = h.text(f.tag, f.name)
		} else {
			*f.dst, _, err = h.str(f.tag, f.name)
		}

		if err != nil {
			return err
		}
	}

	buildTime, _, err := h.int32(tagBuildTime, "BUILDTIME")
	if err != nil {
		return err
	}

	p.BuildTime = uint64(buildTime)

	// rpm's get64 reads the 64-bit tag when present, else the 32-bit one.
	p.InstalledSize, err = firstSize([]sizeTag{
		{h, tagLongSize, "LONGSIZE", true},
		{h, tagSize, "SIZE", false},
	})
	if err != nil {
		return err
	}

	p.ArchiveSize, err = firstSize([]sizeTag{
		{h, tagLongArchiveSize, "LONGARCHIVESIZE", true},
		{sig, tagLongArchiveSize, "signature LONGARCHIVESIZE", true},
		{h, tagArchiveSize, "ARCHIVESIZE", false},
		{sig, sigTagPayloadSize, "signature PAYLOADSIZE", false},
	})

	return err
}

// firstSize returns the value of the first present tag, or 0 when none is.
func firstSize(tags []sizeTag) (uint64, error) {
	for _, t := range tags {
		var (
			v   uint64
			ok  bool
			err error
		)

		if t.wide {
			v, ok, err = t.h.int64(t.tag, t.name)
		} else {
			var v32 uint32
			v32, ok, err = t.h.int32(t.tag, t.name)
			v = uint64(v32)
		}

		if err != nil || ok {
			return v, err
		}
	}

	return 0, nil
}

// text reads a tag that is an I18NSTRING or a STRING and returns its first
// string, which for an I18NSTRING is the untranslated text. Absent gives "".
func (h header) text(tag uint32, name string) (string, error) {
	e, ok := h.entries[tag]
	if !ok || e.typ != typeI18NString {
		s, _, err := h.str(tag, name)

		return s, err
	}

	end := bytes.IndexByte(h.data[e.offset:], 0)
	if end < 0 {
		return "", fmt.Errorf("%w: %s has no NUL terminator", ErrInvalidField, name)
	}

	return string(h.data[e.offset : e.offset+end]), nil
}

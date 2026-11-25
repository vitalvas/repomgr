// Package rpmtest builds RPM packages in memory for tests.
package rpmtest

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
)

const (
	leadSize        int    = 96
	typeBin         uint32 = 7
	typeString      uint32 = 6
	typeInt32       uint32 = 4
	tagRegion       uint32 = 63
	tagDigest       uint32 = 273
	tagName         uint32 = 1000
	tagVersion      uint32 = 1001
	tagRelease      uint32 = 1002
	tagEpoch        uint32 = 1003
	tagArch         uint32 = 1022
	tagSourceRPM    uint32 = 1044
	regionTrailer   int    = 16
	leadTypeOffset  int    = 6
	leadSigOffset   int    = 78
	signatureHeader uint16 = 5
)

var (
	leadMagic   = []byte{0xed, 0xab, 0xee, 0xdb}
	headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
)

// Tag is an extra header entry. Value may be a string, []string, []uint16,
// []uint32, []int32, []uint64, or []byte.
type Tag struct {
	ID    uint32
	Type  uint32
	Value any
}

type Package struct {
	Name      string
	Version   string
	Release   string
	Arch      string
	SourceRPM string
	// NoSourceRPM leaves SOURCERPM out. Otherwise an empty SourceRPM becomes NAME-VERSION-RELEASE.src.rpm.
	NoSourceRPM bool
	Epoch       *uint32
	Source      bool
	Payload     []byte
	Tags        []Tag
	// SigTags are written to the signature header after the digest, in tag order.
	SigTags []Tag
}

// section collects the entries and data of one header.
type section struct {
	entries []byte
	data    []byte
	count   int
}

func (s *section) add(id, typ uint32, value any) error {
	var (
		raw   []byte
		count int
		align int
	)

	switch v := value.(type) {
	case string:
		raw = append([]byte(v), 0)
		count = 1
	case []string:
		for _, item := range v {
			raw = append(raw, item...)
			raw = append(raw, 0)
		}

		count = len(v)
	case []uint16:
		for _, item := range v {
			raw = binary.BigEndian.AppendUint16(raw, item)
		}

		count = len(v)
		align = 2
	case []uint32:
		for _, item := range v {
			raw = binary.BigEndian.AppendUint32(raw, item)
		}

		count = len(v)
		align = 4
	case []int32:
		for _, item := range v {
			raw = binary.BigEndian.AppendUint32(raw, uint32(item))
		}

		count = len(v)
		align = 4
	case []uint64:
		for _, item := range v {
			raw = binary.BigEndian.AppendUint64(raw, item)
		}

		count = len(v)
		align = 8
	case []byte:
		raw = v
		count = len(v)
	default:
		return fmt.Errorf("unsupported value %T for tag %d", value, id)
	}

	for align > 0 && len(s.data)%align != 0 {
		s.data = append(s.data, 0)
	}

	s.entry(id, typ, len(s.data), count)
	s.data = append(s.data, raw...)

	return nil
}

func (s *section) entry(id, typ uint32, offset, count int) {
	s.entries = binary.BigEndian.AppendUint32(s.entries, id)
	s.entries = binary.BigEndian.AppendUint32(s.entries, typ)
	s.entries = binary.BigEndian.AppendUint32(s.entries, uint32(int32(offset)))
	s.entries = binary.BigEndian.AppendUint32(s.entries, uint32(count))
	s.count++
}

func (s *section) bytes() []byte {
	out := append([]byte(nil), headerMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(s.count))
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.data)))
	out = append(out, s.entries...)

	return append(out, s.data...)
}

// Build returns an RPM with a lead, a signature header carrying the SHA-256
// header digest, a main header with an immutable region, and the payload.
func Build(p Package) ([]byte, error) {
	main := section{}
	// The region entry comes first and points at the trailer written last.
	main.entry(tagRegion, typeBin, 0, regionTrailer)

	fields := []struct {
		id    uint32
		value string
	}{
		{tagName, p.Name},
		{tagVersion, p.Version},
		{tagRelease, p.Release},
		{tagArch, p.Arch},
	}

	for _, f := range fields {
		if err := main.add(f.id, typeString, f.value); err != nil {
			return nil, err
		}
	}

	if p.Epoch != nil {
		if err := main.add(tagEpoch, typeInt32, []uint32{*p.Epoch}); err != nil {
			return nil, err
		}
	}

	sourceRPM := p.SourceRPM
	if sourceRPM == "" && !p.NoSourceRPM {
		sourceRPM = fmt.Sprintf("%s-%s-%s.src.rpm", p.Name, p.Version, p.Release)
	}

	if sourceRPM != "" {
		if err := main.add(tagSourceRPM, typeString, sourceRPM); err != nil {
			return nil, err
		}
	}

	for _, t := range p.Tags {
		if err := main.add(t.ID, t.Type, t.Value); err != nil {
			return nil, err
		}
	}

	trailerOffset := len(main.data)
	binary.BigEndian.PutUint32(main.entries[8:], uint32(trailerOffset))

	main.data = binary.BigEndian.AppendUint32(main.data, tagRegion)
	main.data = binary.BigEndian.AppendUint32(main.data, typeBin)
	main.data = binary.BigEndian.AppendUint32(main.data, uint32(int32(-main.count*16)))
	main.data = binary.BigEndian.AppendUint32(main.data, uint32(regionTrailer))

	mainBytes := main.bytes()
	sum := sha256.Sum256(mainBytes)

	sig := section{}
	if err := sig.add(tagDigest, typeString, hex.EncodeToString(sum[:])); err != nil {
		return nil, err
	}

	sigTags := slices.SortedFunc(slices.Values(p.SigTags), func(a, b Tag) int { return cmp.Compare(a.ID, b.ID) })
	for _, t := range sigTags {
		if err := sig.add(t.ID, t.Type, t.Value); err != nil {
			return nil, err
		}
	}

	lead := make([]byte, leadSize)
	copy(lead, leadMagic)
	lead[4] = 3

	if p.Source {
		binary.BigEndian.PutUint16(lead[leadTypeOffset:], 1)
	}

	binary.BigEndian.PutUint16(lead[leadSigOffset:], signatureHeader)

	out := slices.Concat(lead, sig.bytes())
	for len(out)%8 != 0 {
		out = append(out, 0)
	}

	out = append(out, mainBytes...)

	return append(out, p.Payload...), nil
}

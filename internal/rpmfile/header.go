package rpmfile

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // rpm's SHA1HEADER digest, checked as rpm checks it
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	introSize       int    = 16
	entrySize              = 16
	typeNull        uint32 = 0
	typeInt8        uint32 = 2
	typeInt16       uint32 = 3
	typeInt32       uint32 = 4
	typeInt64       uint32 = 5
	typeString      uint32 = 6
	typeBin         uint32 = 7
	typeStringArray uint32 = 8
	typeI18NString  uint32 = 9
	maxType         uint32 = 9

	tagRegionFirst uint32 = 61
	tagSigRegion   uint32 = 62
	tagRegionLast  uint32 = 63
)

// elementSize is the size of one value of each type, indexed by type. Strings
// and NULL have no fixed size.
var elementSize = [maxType + 1]int{0, 1, 1, 2, 4, 8, 0, 1, 0, 0}

var headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}

type entry struct {
	typ    uint32
	offset int
	count  int
}

type headerRegion struct {
	entries int
	trailer int
}

type header struct {
	entries map[uint32]entry
	data    []byte
	// length is the size of the intro, the entries, and the data.
	length int64
	// sum and sha1 are the hex SHA-256 and SHA-1 of the header bytes, magic
	// through the data.
	sum  string
	sha1 string
}

// readHeader reads one header. The entry count and data size are checked
// against lim before anything else is read, so a crafted size can't cost memory.
func readHeader(r io.Reader, name string, lim headerLimit) (header, error) {
	sum := sha256.New()
	sum1 := sha1.New()
	src := io.TeeReader(r, io.MultiWriter(sum, sum1))

	intro := make([]byte, introSize)
	if _, err := io.ReadFull(src, intro); err != nil {
		return header{}, fmt.Errorf("read %s header: %w", name, err)
	}

	if !bytes.Equal(intro[:len(headerMagic)], headerMagic) {
		return header{}, fmt.Errorf("bad %s header magic", name)
	}

	count := binary.BigEndian.Uint32(intro[8:])
	size := binary.BigEndian.Uint32(intro[12:])

	if count > lim.entries {
		return header{}, fmt.Errorf("%s header has %d entries, limit %d", name, count, lim.entries)
	}

	if size > lim.data {
		return header{}, fmt.Errorf("%s header data is %d bytes, limit %d", name, size, lim.data)
	}

	raw := make([]byte, int(count)*entrySize)
	if _, err := io.ReadFull(src, raw); err != nil {
		return header{}, fmt.Errorf("read %s header entries: %w", name, err)
	}

	data, err := io.ReadAll(io.LimitReader(src, int64(size)))
	if err != nil {
		return header{}, fmt.Errorf("read %s header data: %w", name, err)
	}

	if len(data) != int(size) {
		return header{}, fmt.Errorf("read %s header data: %w", name, io.ErrUnexpectedEOF)
	}

	region, err := readRegion(raw, data, name == "main")
	if err != nil {
		return header{}, fmt.Errorf("%s header: %w", name, err)
	}

	entries := make(map[uint32]entry, count)

	var end int64

	for i := range int(count) {
		e := raw[i*entrySize:]
		tag := binary.BigEndian.Uint32(e)
		typ := binary.BigEndian.Uint32(e[4:])
		offset := int32(binary.BigEndian.Uint32(e[8:]))
		n := int32(binary.BigEndian.Uint32(e[12:]))

		if _, dup := entries[tag]; dup {
			return header{}, fmt.Errorf("%s header has duplicate tag %d", name, tag)
		}

		switch {
		case typ > maxType:
			return header{}, fmt.Errorf("%s header entry %d has type %d", name, i, typ)
		case offset < 0 || int(offset) >= len(data):
			return header{}, fmt.Errorf("%s header entry %d has offset %d outside %d bytes of data", name, i, offset, len(data))
		case n < 0:
			return header{}, fmt.Errorf("%s header entry %d has count %d", name, i, n)
		}

		ent := entry{typ: typ, offset: int(offset), count: int(n)}
		entries[tag] = ent
		if i == 0 && region.entries != 0 {
			continue
		}

		section := data
		switch {
		case i < region.entries:
			section = data[:region.trailer]
			if ent.offset >= len(section) {
				return header{}, fmt.Errorf("%s header tag %d starts outside the region data", name, tag)
			}
		case i == region.entries && region.entries != 0:
			end = int64(region.trailer + entrySize)
		}

		end, err = checkEntry(ent, end, section)
		if err != nil {
			return header{}, fmt.Errorf("%s header tag %d %w", name, tag, err)
		}
	}

	return header{
		entries: entries,
		data:    data,
		length:  int64(introSize) + int64(len(raw)) + int64(len(data)),
		sum:     hex.EncodeToString(sum.Sum(nil)),
		sha1:    hex.EncodeToString(sum1.Sum(nil)),
	}, nil
}

// readRegion validates the trailer of a header that has a region. The main
// header's region spans the whole header. A signature header can have entries
// added after its region, and older signatures can use a tag 61 trailer.
func readRegion(raw, data []byte, exact bool) (headerRegion, error) {
	if len(raw) == 0 {
		return headerRegion{}, errors.New("no tags")
	}

	tag := binary.BigEndian.Uint32(raw)
	if tag < tagRegionFirst || tag > tagRegionLast {
		return headerRegion{}, nil
	}

	trailer := int64(binary.BigEndian.Uint32(raw[8:]))
	if trailer+entrySize > int64(len(data)) {
		return headerRegion{}, errors.New("region trailer is outside the header data")
	}

	if binary.BigEndian.Uint32(raw[4:]) != typeBin || binary.BigEndian.Uint32(raw[12:]) != entrySize {
		return headerRegion{}, errors.New("invalid region tag type or count")
	}

	t := data[trailer : trailer+entrySize]
	trailerTag := binary.BigEndian.Uint32(t)
	if tag == tagSigRegion && trailerTag == tagRegionFirst {
		trailerTag = tag
	}

	if trailerTag != tag || binary.BigEndian.Uint32(t[4:]) != typeBin || binary.BigEndian.Uint32(t[12:]) != entrySize {
		return headerRegion{}, errors.New("invalid region trailer tag, type, or count")
	}

	indexSize := -int64(int32(binary.BigEndian.Uint32(t[8:])))
	if indexSize < entrySize || indexSize > int64(len(raw)) || indexSize%entrySize != 0 {
		return headerRegion{}, errors.New("invalid region trailer index size")
	}

	if exact && (indexSize != int64(len(raw)) || trailer+entrySize != int64(len(data))) {
		return headerRegion{}, errors.New("region does not cover the main header")
	}

	return headerRegion{entries: int(indexSize) / entrySize, trailer: int(trailer)}, nil
}

// checkEntry applies rpm 4.14.3's layout rule, given the end of the previous
// entry's data: data may not overlap or go backwards, 16-, 32- and 64-bit
// values are aligned to their size, and every entry has data that lies inside
// the data section. It returns the end of this entry.
func checkEntry(e entry, end int64, data []byte) (int64, error) {
	rest := data[e.offset:]

	if int64(e.offset) < end {
		return 0, errors.New("has data overlapping or before the previous entry")
	}

	if align := elementSize[e.typ]; align > 1 && e.offset%align != 0 {
		return 0, fmt.Errorf("has offset %d, not aligned to %d", e.offset, align)
	}

	var size int64

	switch e.typ {
	case typeString, typeStringArray, typeI18NString:
		n := e.count
		if e.typ == typeString {
			if e.count != 1 {
				return 0, fmt.Errorf("is a string with count %d, want 1", e.count)
			}

			n = 1
		}

		for range n {
			nul := bytes.IndexByte(rest[size:], 0)
			if nul < 0 {
				return 0, fmt.Errorf("has data outside the %d bytes of data", len(data))
			}

			size += int64(nul) + 1
		}
	default:
		size = int64(e.count) * int64(elementSize[e.typ])
	}

	if size <= 0 {
		return 0, errors.New("has no data")
	}

	if size > int64(len(rest)) {
		return 0, fmt.Errorf("has data outside the %d bytes of data", len(data))
	}

	return int64(e.offset) + size, nil
}

// find returns the entry for tag. It reports false when the tag is absent and
// fails when the tag is present with another type or a count other than one.
func (h header) find(tag uint32, name string, typ uint32) (entry, bool, error) {
	e, ok := h.entries[tag]
	if !ok {
		return entry{}, false, nil
	}

	if e.typ != typ || e.count != 1 {
		return entry{}, false, fmt.Errorf("%w: %s has type %d and count %d, want type %d and count 1", ErrInvalidField, name, e.typ, e.count, typ)
	}

	return e, true, nil
}

// findArray is find for array tags: any count is accepted.
func (h header) findArray(tag uint32, name string, typ uint32) (entry, bool, error) {
	e, ok := h.entries[tag]
	if !ok {
		return entry{}, false, nil
	}

	if e.typ != typ {
		return entry{}, false, fmt.Errorf("%w: %s has type %d, want type %d", ErrInvalidField, name, e.typ, typ)
	}

	return e, true, nil
}

// strings reads a STRING_ARRAY tag. The count is checked against the bytes
// left in the data before the result is allocated, as every string needs at
// least its terminator.
func (h header) strings(tag uint32, name string) ([]string, bool, error) {
	e, ok, err := h.findArray(tag, name, typeStringArray)
	if !ok || err != nil {
		return nil, false, err
	}

	rest := h.data[e.offset:]
	if e.count > len(rest) {
		return nil, false, fmt.Errorf("%w: %s has count %d but only %d bytes of data", ErrInvalidField, name, e.count, len(rest))
	}

	out := make([]string, 0, e.count)

	for range e.count {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, false, fmt.Errorf("%w: %s has no NUL terminator", ErrInvalidField, name)
		}

		out = append(out, string(rest[:end]))
		rest = rest[end+1:]
	}

	return out, true, nil
}

// int32s reads an INT32 array tag.
func (h header) int32s(tag uint32, name string) ([]uint32, bool, error) {
	e, ok, err := h.findArray(tag, name, typeInt32)
	if !ok || err != nil {
		return nil, false, err
	}

	if int64(e.offset)+4*int64(e.count) > int64(len(h.data)) {
		return nil, false, fmt.Errorf("%w: %s lies outside the data", ErrInvalidField, name)
	}

	out := make([]uint32, e.count)

	for i := range out {
		out[i] = binary.BigEndian.Uint32(h.data[e.offset+4*i:])
	}

	return out, true, nil
}

// int16s reads an INT16 array tag.
func (h header) int16s(tag uint32, name string) ([]uint16, bool, error) {
	e, ok, err := h.findArray(tag, name, typeInt16)
	if !ok || err != nil {
		return nil, false, err
	}

	if int64(e.offset)+2*int64(e.count) > int64(len(h.data)) {
		return nil, false, fmt.Errorf("%w: %s lies outside the data", ErrInvalidField, name)
	}

	out := make([]uint16, e.count)

	for i := range out {
		out[i] = binary.BigEndian.Uint16(h.data[e.offset+2*i:])
	}

	return out, true, nil
}

func (h header) str(tag uint32, name string) (string, bool, error) {
	e, ok, err := h.find(tag, name, typeString)
	if !ok || err != nil {
		return "", false, err
	}

	end := bytes.IndexByte(h.data[e.offset:], 0)
	if end < 0 {
		return "", false, fmt.Errorf("%w: %s has no NUL terminator", ErrInvalidField, name)
	}

	return string(h.data[e.offset : e.offset+end]), true, nil
}

func (h header) int32(tag uint32, name string) (uint32, bool, error) {
	e, ok, err := h.find(tag, name, typeInt32)
	if !ok || err != nil {
		return 0, false, err
	}

	if e.offset+4 > len(h.data) {
		return 0, false, fmt.Errorf("%w: %s lies outside the data", ErrInvalidField, name)
	}

	return binary.BigEndian.Uint32(h.data[e.offset:]), true, nil
}

func (h header) int64(tag uint32, name string) (uint64, bool, error) {
	e, ok, err := h.find(tag, name, typeInt64)
	if !ok || err != nil {
		return 0, false, err
	}

	if e.offset+8 > len(h.data) {
		return 0, false, fmt.Errorf("%w: %s lies outside the data", ErrInvalidField, name)
	}

	return binary.BigEndian.Uint64(h.data[e.offset:]), true, nil
}

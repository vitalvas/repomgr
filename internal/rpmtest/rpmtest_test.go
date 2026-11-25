package rpmtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entryAt returns the tag, type, offset, and count of index entry i.
func entryAt(entries []byte, i int) []uint32 {
	e := entries[i*16:]

	return []uint32{binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:]), binary.BigEndian.Uint32(e[12:])}
}

func TestBuild(t *testing.T) {
	base := Package{Name: "pdns", Version: "5.1.0", Release: "1.el9", Arch: "x86_64", Payload: []byte("payload")}

	t.Run("layout", func(t *testing.T) {
		data, err := Build(base)
		require.NoError(t, err)

		assert.Equal(t, []byte{0xed, 0xab, 0xee, 0xdb}, data[:4])
		assert.Equal(t, byte(3), data[4])
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(data[6:]))
		assert.Equal(t, uint16(5), binary.BigEndian.Uint16(data[78:]))
		assert.Equal(t, headerMagic, data[96:104])
		assert.True(t, bytes.HasSuffix(data, base.Payload))
	})

	t.Run("signature header is padded and carries the digest", func(t *testing.T) {
		data, err := Build(base)
		require.NoError(t, err)

		sigEntries := binary.BigEndian.Uint32(data[104:])
		sigData := binary.BigEndian.Uint32(data[108:])
		require.Equal(t, uint32(1), sigEntries)
		require.Equal(t, uint32(65), sigData)

		sigEnd := 96 + 16 + 16 + int(sigData)
		mainStart := sigEnd + (8-sigEnd%8)%8
		assert.Equal(t, 0, mainStart%8)
		assert.Equal(t, headerMagic, data[mainStart:mainStart+8])

		mainData := binary.BigEndian.Uint32(data[mainStart+12:])
		mainEntries := binary.BigEndian.Uint32(data[mainStart+8:])
		mainEnd := mainStart + 16 + int(mainEntries)*16 + int(mainData)
		sum := sha256.Sum256(data[mainStart:mainEnd])

		assert.Equal(t, hex.EncodeToString(sum[:]), string(data[96+16+16:96+16+16+64]))
		assert.Equal(t, base.Payload, data[mainEnd:])
	})

	t.Run("region trailer", func(t *testing.T) {
		data, err := Build(Package{Name: "a", Version: "1", Release: "1", Arch: "noarch"})
		require.NoError(t, err)

		trailer := data[len(data)-16:]
		assert.Equal(t, uint32(63), binary.BigEndian.Uint32(trailer))
		assert.Equal(t, uint32(7), binary.BigEndian.Uint32(trailer[4:]))
		assert.Equal(t, int32(-6*16), int32(binary.BigEndian.Uint32(trailer[8:])))
		assert.Equal(t, uint32(16), binary.BigEndian.Uint32(trailer[12:]))
	})

	t.Run("source package", func(t *testing.T) {
		p := base
		p.Source = true
		data, err := Build(p)
		require.NoError(t, err)
		assert.Equal(t, uint16(1), binary.BigEndian.Uint16(data[6:]))
	})

	t.Run("source rpm default and omission", func(t *testing.T) {
		withDefault, err := Build(base)
		require.NoError(t, err)
		assert.Contains(t, string(withDefault), fmt.Sprintf("%s-%s-%s.src.rpm", base.Name, base.Version, base.Release))

		p := base
		p.NoSourceRPM = true
		omitted, err := Build(p)
		require.NoError(t, err)
		assert.NotContains(t, string(omitted), ".src.rpm")
	})

	t.Run("optional tags", func(t *testing.T) {
		epoch := uint32(2)
		p := base
		p.Epoch = &epoch
		p.SourceRPM = "pdns-5.1.0-1.el9.src.rpm"
		data, err := Build(p)
		require.NoError(t, err)

		plain, err := Build(base)
		require.NoError(t, err)

		assert.Greater(t, len(data), len(plain))
		assert.Contains(t, string(data), p.SourceRPM)
	})

	t.Run("extra tag values", func(t *testing.T) {
		tags := []Tag{
			{ID: 2000, Type: 6, Value: "text"},
			{ID: 2001, Type: 8, Value: []string{"a", "bc"}},
			{ID: 2002, Type: 4, Value: []uint32{1, 2}},
			{ID: 2003, Type: 4, Value: []int32{-1}},
			{ID: 2004, Type: 7, Value: []byte{9, 9}},
		}
		p := base
		p.Tags = tags
		data, err := Build(p)
		require.NoError(t, err)

		plain, err := Build(base)
		require.NoError(t, err)

		assert.Contains(t, string(data), "text\x00")
		assert.Contains(t, string(data), "a\x00bc\x00")
		assert.Greater(t, len(data), len(plain))
	})

	t.Run("int16 values are aligned to two bytes", func(t *testing.T) {
		p := base
		p.Tags = []Tag{
			{ID: 2000, Type: 7, Value: []byte{7, 7}},
			{ID: 2001, Type: 3, Value: []uint16{1, 0x0203}},
		}
		data, err := Build(p)
		require.NoError(t, err)

		i := bytes.Index(data, []byte{0, 1, 2, 3})
		require.Positive(t, i)
		assert.Equal(t, []byte{7, 7, 0, 0, 1, 2, 3}, data[i-3:i+4])
	})

	t.Run("int64 values are aligned to eight bytes", func(t *testing.T) {
		p := base
		p.Tags = []Tag{
			{ID: 2000, Type: 7, Value: []byte{7, 7}},
			{ID: 2001, Type: 5, Value: []uint64{0x0102030405060708}},
		}
		data, err := Build(p)
		require.NoError(t, err)

		i := bytes.Index(data, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		require.Positive(t, i)
		// The main data holds 49 bytes of strings before the two bytes.
		assert.Equal(t, []byte{7, 7, 0, 0, 0, 0, 0, 1, 2}, data[i-7:i+2])
	})

	t.Run("signature tags follow the digest in tag order", func(t *testing.T) {
		p := base
		p.SigTags = []Tag{
			{ID: 1007, Type: 4, Value: []uint32{0x0a0b0c0d}},
			{ID: 271, Type: 5, Value: []uint64{0x0102030405060708}},
		}
		data, err := Build(p)
		require.NoError(t, err)

		require.Equal(t, uint32(3), binary.BigEndian.Uint32(data[104:]))
		require.Equal(t, uint32(65+7+8+4), binary.BigEndian.Uint32(data[108:]))

		entries := data[112:]
		assert.Equal(t, []uint32{273, 6, 0, 1}, entryAt(entries, 0))
		assert.Equal(t, []uint32{271, 5, 72, 1}, entryAt(entries, 1))
		assert.Equal(t, []uint32{1007, 4, 80, 1}, entryAt(entries, 2))

		sigData := data[112+3*16:]
		assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x0a, 0x0b, 0x0c, 0x0d}, sigData[72:84])

		sigEnd := 112 + 3*16 + 84
		mainStart := sigEnd + (8-sigEnd%8)%8
		assert.Equal(t, headerMagic, data[mainStart:mainStart+8])
	})

	t.Run("unsupported signature tag value", func(t *testing.T) {
		p := base
		p.SigTags = []Tag{{ID: 1007, Type: 4, Value: 1.5}}
		_, err := Build(p)
		assert.ErrorContains(t, err, "unsupported value")
	})

	t.Run("unsupported tag value", func(t *testing.T) {
		p := base
		p.Tags = []Tag{{ID: 2000, Type: 6, Value: 1.5}}
		_, err := Build(p)
		assert.ErrorContains(t, err, "unsupported value")
	})
}

package rpmfile

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rawHeader(entries [][4]int32, data []byte) []byte {
	out := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
	out = binary.BigEndian.AppendUint32(out, uint32(len(entries)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))

	for _, e := range entries {
		for _, v := range e {
			out = binary.BigEndian.AppendUint32(out, uint32(v))
		}
	}

	return append(out, data...)
}

func TestReadHeader(t *testing.T) {
	entry := [][4]int32{{1000, 6, 0, 1}}
	region := func(tag, trailerTag, trailerIndexSize int32) []byte {
		data := []byte("a\x00\x00\x00")
		for _, value := range []int32{trailerTag, 7, trailerIndexSize, 16} {
			data = binary.BigEndian.AppendUint32(data, uint32(value))
		}
		return rawHeader([][4]int32{{tag, 7, 4, 16}, {1000, 6, 0, 1}}, data)
	}

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"valid", rawHeader(entry, []byte("a\x00")), ""},
		{"empty", nil, "read main header"},
		{"short entries", rawHeader(entry, []byte("a\x00"))[:20], "entries"},
		{"short data", rawHeader(entry, []byte("a\x00"))[:33], "data"},
		{"type 9", rawHeader([][4]int32{{1000, 9, 0, 1}}, []byte("a\x00")), ""},
		{"type 10", rawHeader([][4]int32{{1000, 10, 0, 1}}, []byte("a\x00")), "type 10"},
		{"negative type", rawHeader([][4]int32{{1000, -1, 0, 1}}, []byte("a\x00")), "type"},
		{"offset equals length", rawHeader([][4]int32{{1000, 6, 2, 1}}, []byte("a\x00")), "offset 2"},
		{"entry without data", rawHeader(entry, nil), "offset 0"},
		{"negative count", rawHeader([][4]int32{{1000, 6, 0, -1}}, []byte("a\x00")), "count"},

		{"adjacent entries", rawHeader([][4]int32{{1000, 6, 0, 1}, {1001, 6, 2, 1}}, []byte("a\x00b\x00")), ""},
		{"gap between entries", rawHeader([][4]int32{{1000, 6, 0, 1}, {1001, 6, 4, 1}}, []byte("a\x00\x00\x00b\x00")), ""},
		{"aligned int16, int32, int64", rawHeader([][4]int32{{1000, 3, 0, 1}, {1001, 4, 4, 1}, {1002, 5, 8, 1}}, make([]byte, 16)), ""},
		{"strings and bytes", rawHeader([][4]int32{{1000, 8, 0, 2}, {1001, 7, 4, 3}, {1002, 9, 7, 1}}, []byte("a\x00b\x00xyzi\x00")), ""},
		{"immutable region", region(63, 63, -32), ""},
		{"signature region", region(62, 62, -32), ""},
		{"legacy signature region trailer", region(62, 61, -32), ""},
		{"image region", region(61, 61, -32), ""},
		{"wrong trailer tag", region(63, 0, -32), "invalid region trailer tag"},
		{"trailer index size is not aligned", region(63, 63, -31), "invalid region trailer index size"},
		{"trailer index size is too large", region(63, 63, -48), "invalid region trailer index size"},
		{"main region has trailing entries", region(63, 63, -16), "region does not cover"},
		{"data starts in the trailer", patched(region(63, 63, -32), 16+16+11, 4), "outside the region"},
		{"region data past the data", rawHeader([][4]int32{{63, 7, 8, 16}, {1000, 6, 0, 1}}, append([]byte("a\x00\x00\x00"), make([]byte, 16)...)), "outside"},
		{"region tag after entry 0 is walked", rawHeader([][4]int32{{1000, 6, 0, 1}, {63, 7, 0, 2}}, []byte("a\x00")), "overlap"},

		{"same bytes twice", rawHeader([][4]int32{{1000, 6, 0, 1}, {1001, 6, 0, 1}}, []byte("a\x00")), "overlap"},
		{"second range starts inside the first", rawHeader([][4]int32{{1000, 7, 0, 4}, {1001, 7, 2, 1}}, make([]byte, 4)), "overlap"},
		{"entries out of offset order", rawHeader([][4]int32{{1000, 6, 2, 1}, {1001, 6, 0, 1}}, []byte("a\x00b\x00")), "overlap"},
		{"misaligned int16", rawHeader([][4]int32{{1000, 3, 1, 1}}, make([]byte, 4)), "aligned to 2"},
		{"misaligned int32", rawHeader([][4]int32{{1000, 4, 2, 1}}, make([]byte, 8)), "aligned to 4"},
		{"misaligned int64", rawHeader([][4]int32{{1000, 5, 4, 1}}, make([]byte, 16)), "aligned to 8"},
		{"range past the data", rawHeader([][4]int32{{1000, 7, 0, 10}}, []byte("ab")), "outside"},
		{"int32 range past the data", rawHeader([][4]int32{{1000, 4, 0, 2}}, make([]byte, 4)), "outside"},
		{"int64 count overflows 32 bits", rawHeader([][4]int32{{1000, 5, 0, math.MaxInt32}}, make([]byte, 8)), "outside"},
		{"string without terminator", rawHeader([][4]int32{{1000, 6, 0, 1}}, []byte("ab")), "outside"},
		{"string array past its own strings", rawHeader([][4]int32{{1000, 8, 0, 3}}, []byte("ab\x00cd\x00")), "outside"},
		{"string array count beyond the data", rawHeader([][4]int32{{1000, 8, 0, math.MaxInt32}}, []byte("ab\x00")), "outside"},
		{"string with count 0", rawHeader([][4]int32{{1000, 6, 0, 0}}, []byte("a\x00")), "count 0"},
		{"string with count 2", rawHeader([][4]int32{{1000, 6, 0, 2}}, []byte("a\x00b\x00")), "count 2"},
		{"null entry has no data", rawHeader([][4]int32{{1000, 0, 0, 0}}, []byte("a\x00")), "no data"},
		{"empty array has no data", rawHeader([][4]int32{{1000, 8, 0, 0}}, []byte("a\x00")), "no data"},
		{"empty bin has no data", rawHeader([][4]int32{{1000, 7, 0, 0}}, []byte("a\x00")), "no data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readHeader(bytes.NewReader(tt.raw), "main", headerLimit{entries: rpmLimits.main.entries, data: 1024})
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}

			assert.ErrorContains(t, err, tt.want)
		})
	}
}

// Every entry points at the start of the data. The walk rejects the second
// entry, so the cost does not grow with the number of entries.
func TestReadHeaderManyOverlappingEntries(t *testing.T) {
	const size = 4 << 20

	entries := make([][4]int32, 65535)
	for i := range entries {
		entries[i] = [4]int32{int32(1000 + i), 8, 0, size / 2}
	}

	_, err := readHeader(bytes.NewReader(rawHeader(entries, make([]byte, size))), "main", headerLimit{entries: rpmLimits.main.entries, data: size})
	assert.ErrorContains(t, err, "overlap")
}

func TestHeaderArrays(t *testing.T) {
	h := header{
		entries: map[uint32]entry{
			1:  {typ: typeStringArray, offset: 0, count: 2},
			3:  {typ: typeStringArray, offset: 0, count: 100},
			4:  {typ: typeStringArray, offset: 5, count: 0},
			6:  {typ: typeInt32, offset: 8, count: 2},
			7:  {typ: typeInt32, offset: 4, count: math.MaxInt32},
			8:  {typ: typeString, offset: 0, count: 1},
			9:  {typ: typeInt16, offset: 10, count: 3},
			10: {typ: typeInt16, offset: 10, count: 4},
			11: {typ: typeInt16, offset: 4, count: math.MaxInt32},
		},
		data: []byte("ab\x00cd\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02"),
	}

	t.Run("string array", func(t *testing.T) {
		got, ok, err := h.strings(1, "X")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []string{"ab", "cd"}, got)
	})

	t.Run("empty string array", func(t *testing.T) {
		got, ok, err := h.strings(4, "X")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, got)
	})

	t.Run("string array terminator outside the data", func(t *testing.T) {
		short := header{entries: map[uint32]entry{1: {typ: typeStringArray, offset: 0, count: 2}}, data: []byte("ab\x00cd")}
		_, _, err := short.strings(1, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "terminator")
	})

	t.Run("string array count past the strings", func(t *testing.T) {
		_, _, err := h.strings(3, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "count 100")
	})

	t.Run("wrong string array type", func(t *testing.T) {
		_, _, err := h.strings(8, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
	})

	t.Run("int32 array", func(t *testing.T) {
		got, ok, err := h.int32s(6, "X")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []uint32{1, 2}, got)
	})

	t.Run("int32 array past the data", func(t *testing.T) {
		past := header{entries: map[uint32]entry{1: {typ: typeInt32, offset: 4, count: 2}}, data: make([]byte, 11)}
		_, _, err := past.int32s(1, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "outside")
	})

	t.Run("int32 array offset overflow", func(t *testing.T) {
		_, _, err := h.int32s(7, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
	})

	t.Run("wrong int32 array type", func(t *testing.T) {
		_, _, err := h.int32s(1, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
	})

	t.Run("int16 array", func(t *testing.T) {
		got, ok, err := h.int16s(9, "X")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []uint16{1, 0, 2}, got)
	})

	t.Run("int16 array absent", func(t *testing.T) {
		got, ok, err := h.int16s(99, "X")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, got)
	})

	t.Run("int16 array past the data", func(t *testing.T) {
		_, _, err := h.int16s(10, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "outside")
	})

	t.Run("int16 array offset overflow", func(t *testing.T) {
		_, _, err := h.int16s(11, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
	})

	t.Run("wrong int16 array type", func(t *testing.T) {
		_, _, err := h.int16s(6, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
	})
}

func TestHeaderValues(t *testing.T) {
	h := header{
		entries: map[uint32]entry{
			1: {typ: typeString, offset: 0, count: 1},
			4: {typ: typeInt32, offset: 0, count: 1},
			5: {typ: typeInt64, offset: 0, count: 1},
		},
		data: []byte("abc"),
	}

	t.Run("missing terminator", func(t *testing.T) {
		_, _, err := h.str(1, "X")
		assert.ErrorContains(t, err, "terminator")
	})

	t.Run("int32 past the data", func(t *testing.T) {
		_, _, err := h.int32(4, "X")
		assert.ErrorContains(t, err, "outside")
	})

	t.Run("int64 past the data", func(t *testing.T) {
		_, _, err := h.int64(5, "X")
		assert.ErrorIs(t, err, ErrInvalidField)
		assert.ErrorContains(t, err, "X lies outside")
	})

	t.Run("int64", func(t *testing.T) {
		wide := header{entries: map[uint32]entry{5: {typ: typeInt64, offset: 8, count: 1}}, data: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x01")}
		got, ok, err := wide.int64(5, "X")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, uint64(0xff00000000000001), got)
	})

	t.Run("int64 wrong type and count", func(t *testing.T) {
		for _, e := range []entry{{typ: typeInt32, count: 1}, {typ: typeInt64, count: 2}} {
			bad := header{entries: map[uint32]entry{5: e}, data: make([]byte, 16)}
			_, _, err := bad.int64(5, "X")
			assert.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, "X has type")
		}
	})

	t.Run("absent array tags", func(t *testing.T) {
		got, ok, err := h.strings(99, "X")
		assert.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, got)

		nums, ok, err := h.int32s(99, "X")
		assert.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, nums)
	})

	t.Run("absent tag", func(t *testing.T) {
		_, ok, err := h.int32(99, "X")
		assert.NoError(t, err)
		assert.False(t, ok)
	})
}

package debfile

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

const xzBlockStart int = 12

func xzStream(t testing.TB, cfg xz.WriterConfig, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := cfg.NewWriter(&buf)
	require.NoError(t, err)

	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

// patchBlockHeader sets byte off of the block header at start and fixes the
// header CRC32, so the decoder itself would accept the header.
func patchBlockHeader(t testing.TB, s []byte, start, off int, b byte) {
	t.Helper()

	size := (int(s[start]) + 1) * 4
	require.Less(t, off, size-4)

	s[start+off] = b
	binary.LittleEndian.PutUint32(s[start+size-4:], crc32.ChecksumIEEE(s[start:start+size-4]))
}

// xzBlocks returns the bytes between the stream header and the index of a
// stream, using the backward size in its footer.
func xzBlocks(s []byte) []byte {
	indexSize := (int(binary.LittleEndian.Uint32(s[len(s)-8:])) + 1) * 4

	return s[xzBlockStart : len(s)-xzHeaderSize-indexSize]
}

func TestCheckXZ(t *testing.T) {
	payload := bytes.Repeat([]byte("control data "), 4096)
	single := xzStream(t, xz.WriterConfig{}, payload)

	t.Run("default stream passes", func(t *testing.T) {
		require.NoError(t, checkXZ(single))
	})

	t.Run("multi-block stream passes and decodes", func(t *testing.T) {
		multi := xzStream(t, xz.WriterConfig{BlockSize: 4096}, payload)
		require.NoError(t, checkXZ(multi))

		r, err := xz.ReaderConfig{SingleStream: true}.NewReader(bytes.NewReader(multi))
		require.NoError(t, err)

		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("dictionary limit", func(t *testing.T) {
		for dict, ok := range map[byte]bool{28: true, 29: false, 40: false} {
			s := slices.Clone(single)
			patchBlockHeader(t, s, xzBlockStart, 4, dict)

			err := checkXZ(s)
			if ok {
				require.NoError(t, err, "dict byte %d", dict)

				continue
			}

			require.ErrorContains(t, err, "exceeds 67108864", "dict byte %d", dict)
		}
	})

	t.Run("huge dictionary in a later block is found", func(t *testing.T) {
		huge := slices.Clone(single)
		patchBlockHeader(t, huge, xzBlockStart, 4, 40)

		s := slices.Concat(single[:xzBlockStart], xzBlocks(single), xzBlocks(huge), []byte{0})
		require.ErrorContains(t, checkXZ(s), "xz dictionary of 4294967295 bytes exceeds 67108864")
	})

	errCases := map[string]struct {
		off  int
		b    byte
		want string
	}{
		"bad magic":               {off: 0, b: 0, want: "stream header"},
		"unsupported check":       {off: 7, b: 2, want: "check"},
		"two filters":             {off: xzBlockStart + 1, b: 1, want: "one filter"},
		"reserved block flag":     {off: xzBlockStart + 1, b: 0x04, want: "reserved"},
		"not LZMA2":               {off: xzBlockStart + 2, b: 0x03, want: "LZMA2"},
		"bad LZMA2 chunk control": {off: xzBlockStart + 12, b: 0x03, want: "LZMA2 chunk"},
	}

	for name, tc := range errCases {
		t.Run(name, func(t *testing.T) {
			s := slices.Clone(single)
			s[tc.off] = tc.b

			require.ErrorContains(t, checkXZ(s), tc.want)
		})
	}

	t.Run("every truncation fails without panic", func(t *testing.T) {
		end := len(single) - xzHeaderSize - (int(binary.LittleEndian.Uint32(single[len(single)-8:]))+1)*4

		for n := range end {
			assert.Error(t, checkXZ(single[:n]), "cut at %d", n)
		}
	})
}

func TestParseXZ(t *testing.T) {
	ctrl := func(t *testing.T) []byte {
		t.Helper()

		return xzStream(t, xz.WriterConfig{}, controlArchive(t, "", 0, 0))
	}

	t.Run("huge dictionary fails before decoding", func(t *testing.T) {
		s := ctrl(t)
		patchBlockHeader(t, s, xzBlockStart, 4, 40)

		_, err := Parse(bytes.NewReader(buildAr("debian-binary", "2.0\n", controlXz, s)))
		require.ErrorContains(t, err, "check xz of control.tar.xz: xz dictionary of 4294967295 bytes exceeds 67108864")
	})

	t.Run("data after the stream fails", func(t *testing.T) {
		s := append(ctrl(t), 0, 0, 0, 0)

		_, err := Parse(bytes.NewReader(buildAr("debian-binary", "2.0\n", controlXz, s)))
		require.ErrorContains(t, err, "control.tar.xz")
	})

	t.Run("compressed member over the limit fails before reading", func(t *testing.T) {
		_, err := readControl(bytes.NewReader(nil), arMember{name: controlXz, size: 1 << 20}, 1<<10)
		require.ErrorContains(t, err, "control archive control.tar.xz exceeds 1024 bytes")
	})
}

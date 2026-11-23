package debfile

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	xzHeaderSize int    = 12
	xzMagic      string = "\xfd7zXZ\x00"
	xzLZMA2      uint64 = 0x21
	// maxXZDictSize is the largest dictionary of the standard xz presets (-9).
	maxXZDictSize uint64 = 64 << 20
)

var errXZTruncated = errors.New("truncated xz stream")

// xzCheckSizes holds the check sizes of the check types the decoder supports.
var xzCheckSizes = map[byte]int{0x00: 0, 0x01: 4, 0x04: 8, 0x0a: 32}

// checkXZ walks the blocks of one xz stream in the order the decoder reads
// them and fails on any block whose LZMA2 dictionary is over maxXZDictSize.
// The decoder allocates the dictionary named in each block header before it
// decodes anything, so the size must be checked first. Block ends come from
// the LZMA2 chunk sizes, not from the index, because the decoder reads the
// index only after the last block.
func checkXZ(data []byte) error {
	if len(data) < xzHeaderSize || string(data[:len(xzMagic)]) != xzMagic || data[6] != 0 {
		return errors.New("bad xz stream header")
	}

	checkSize, ok := xzCheckSizes[data[7]]
	if !ok {
		return fmt.Errorf("unsupported xz check type %d", data[7])
	}

	pos := xzHeaderSize

	for {
		if pos >= len(data) {
			return errXZTruncated
		}

		// A zero byte is the index indicator: the stream has no more blocks.
		if data[pos] == 0 {
			return nil
		}

		headerSize := (int(data[pos]) + 1) * 4
		if pos+headerSize > len(data) {
			return errXZTruncated
		}

		if err := checkXZBlockHeader(data[pos+1 : pos+headerSize-4]); err != nil {
			return err
		}

		start := pos + headerSize

		end, err := skipLZMA2(data, start)
		if err != nil {
			return err
		}

		pos = end + (4-(end-start)%4)%4 + checkSize
	}
}

// checkXZBlockHeader checks a block header without its size byte and CRC32.
func checkXZBlockHeader(h []byte) error {
	flags := h[0]

	if flags&0x3c != 0 {
		return errors.New("reserved xz block flags set")
	}

	if flags&0x03 != 0 {
		return errors.New("xz block must use exactly one filter")
	}

	h = h[1:]

	for _, present := range []byte{0x40, 0x80} {
		if flags&present == 0 {
			continue
		}

		var err error

		if _, h, err = xzVarint(h); err != nil {
			return err
		}
	}

	id, h, err := xzVarint(h)
	if err != nil {
		return err
	}

	propsSize, h, err := xzVarint(h)
	if err != nil {
		return err
	}

	if id != xzLZMA2 || propsSize != 1 || len(h) == 0 {
		return errors.New("xz filter is not LZMA2")
	}

	if h[0] > 40 {
		return errors.New("bad xz LZMA2 dictionary size")
	}

	dict := uint64(0xffffffff)
	if h[0] < 40 {
		dict = (2 | uint64(h[0]&1)) << (h[0]/2 + 11)
	}

	if dict > maxXZDictSize {
		return fmt.Errorf("xz dictionary of %d bytes exceeds %d", dict, maxXZDictSize)
	}

	return nil
}

func xzVarint(b []byte) (uint64, []byte, error) {
	var v uint64

	for i := 0; i < len(b) && i < 9; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)

		if b[i]&0x80 == 0 {
			return v, b[i+1:], nil
		}
	}

	return 0, nil, errors.New("bad xz block header")
}

// skipLZMA2 returns the position after the LZMA2 end marker of the data that
// starts at pos, using the size each chunk header gives.
func skipLZMA2(data []byte, pos int) (int, error) {
	for {
		if pos >= len(data) {
			return 0, errXZTruncated
		}

		control := data[pos]

		var headerSize, sizeAt int

		switch {
		case control == 0x00:
			return pos + 1, nil
		case control == 0x01 || control == 0x02:
			headerSize, sizeAt = 3, 1
		case control >= 0xc0:
			headerSize, sizeAt = 6, 3
		case control >= 0x80:
			headerSize, sizeAt = 5, 3
		default:
			return 0, fmt.Errorf("bad LZMA2 chunk control byte 0x%02x", control)
		}

		if pos+headerSize > len(data) {
			return 0, errXZTruncated
		}

		pos += headerSize + int(binary.BigEndian.Uint16(data[pos+sizeAt:])) + 1
	}
}

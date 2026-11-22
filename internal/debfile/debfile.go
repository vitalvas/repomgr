package debfile

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const (
	arMagic        string = "!<arch>\n"
	arHeaderSize   int    = 60
	arNameEnd      int    = 16
	arSizeStart    int    = 48
	arSizeEnd      int    = 58
	arEndMarker    string = "`\n"
	binaryName     string = "debian-binary"
	controlPrefix  string = "control.tar"
	controlPlain   string = "control.tar"
	controlGzip    string = "control.tar.gz"
	controlXz      string = "control.tar.xz"
	controlZstd    string = "control.tar.zst"
	binaryVersion  string = "2."
	maxControlSize int64  = 16 << 20
)

type Control struct {
	Raw    string
	Fields map[string]string
}

type arMember struct {
	name string
	size int64
}

func Parse(r io.Reader) (Control, error) {
	magic := make([]byte, len(arMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != arMagic {
		return Control{}, errors.New("not an ar archive")
	}

	first, err := readHeader(r)
	if err != nil {
		return Control{}, fmt.Errorf("read %s: %w", binaryName, err)
	}

	if err := checkBinary(r, first); err != nil {
		return Control{}, err
	}

	m, err := nextRequiredMember(r)
	if err != nil {
		return Control{}, fmt.Errorf("read control archive: %w", err)
	}

	if !strings.HasPrefix(m.name, controlPrefix) {
		return Control{}, fmt.Errorf("expected control archive, found %s", m.name)
	}

	return readControl(r, m)
}

func nextRequiredMember(r io.Reader) (arMember, error) {
	for {
		m, err := readHeader(r)
		if err != nil || !strings.HasPrefix(m.name, "_") {
			return m, err
		}

		if err := skip(r, m.size); err != nil {
			return arMember{}, fmt.Errorf("skip member %s: %w", m.name, err)
		}
	}
}

func readHeader(r io.Reader) (arMember, error) {
	hdr := make([]byte, arHeaderSize)

	if _, err := io.ReadFull(r, hdr); err != nil {
		if errors.Is(err, io.EOF) {
			return arMember{}, io.EOF
		}

		return arMember{}, fmt.Errorf("read ar member header: %w", err)
	}

	if string(hdr[arSizeEnd:]) != arEndMarker {
		return arMember{}, errors.New("bad ar member header magic")
	}

	size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[arSizeStart:arSizeEnd])), 10, 64)
	if err != nil || size < 0 {
		return arMember{}, errors.New("bad ar member size")
	}

	name := strings.TrimRight(string(hdr[:arNameEnd]), " ")
	name = strings.TrimSuffix(name, "/")

	return arMember{name: name, size: size}, nil
}

// skip consumes a member's data plus the padding byte that follows odd sizes.
func skip(r io.Reader, size int64) error {
	if _, err := io.CopyN(io.Discard, r, size); err != nil {
		return err
	}

	if size%2 == 1 {
		if _, err := io.CopyN(io.Discard, r, 1); err != nil {
			return err
		}
	}

	return nil
}

func checkBinary(r io.Reader, m arMember) error {
	if m.name != binaryName {
		return fmt.Errorf("first ar member is %q, want %s", m.name, binaryName)
	}

	var prefix [len(binaryVersion)]byte
	if m.size < int64(len(prefix)) {
		return fmt.Errorf("unsupported %s version", binaryName)
	}

	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return fmt.Errorf("read %s: %w", binaryName, err)
	}

	if string(prefix[:]) != binaryVersion {
		return fmt.Errorf("unsupported %s version", binaryName)
	}

	// The prefix is two bytes, so the remaining size has the same padding.
	if err := skip(r, m.size-int64(len(prefix))); err != nil {
		return fmt.Errorf("read %s: %w", binaryName, err)
	}

	return nil
}

func readControl(r io.Reader, m arMember) (Control, error) {
	member := &io.LimitedReader{R: r, N: m.size}

	var src io.Reader

	switch m.name {
	case controlPlain:
		src = member
	case controlGzip:
		zr, err := gzip.NewReader(member)
		if err != nil {
			return Control{}, fmt.Errorf("open gzip of %s: %w", m.name, err)
		}

		defer zr.Close()

		src = zr
	case controlXz:
		xr, err := xz.NewReader(member)
		if err != nil {
			return Control{}, fmt.Errorf("open xz of %s: %w", m.name, err)
		}

		src = xr
	case controlZstd:
		zr, err := zstd.NewReader(member, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
		if err != nil {
			return Control{}, fmt.Errorf("open zstd of %s: %w", m.name, err)
		}

		defer zr.Close()

		src = zr
	default:
		return Control{}, fmt.Errorf("unsupported control archive %s", m.name)
	}

	control, err := readControlTar(src, m.name)
	if err != nil {
		return Control{}, err
	}

	// Reading to the end verifies the compression trailer.
	if _, err := io.Copy(io.Discard, src); err != nil {
		return Control{}, fmt.Errorf("finish %s: %w", m.name, err)
	}

	if member.N != 0 {
		return Control{}, fmt.Errorf("read member %s: %w", m.name, io.ErrUnexpectedEOF)
	}

	if _, err := io.CopyN(io.Discard, r, m.size%2); err != nil {
		return Control{}, fmt.Errorf("read member %s padding: %w", m.name, err)
	}

	return control, nil
}

func readControlTar(src io.Reader, name string) (Control, error) {
	tr := tar.NewReader(src)
	var content []byte

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return Control{}, fmt.Errorf("read tar of %s: %w", name, err)
		}

		if hdr.Name != "./control" && hdr.Name != "control" {
			continue
		}

		if content != nil || hdr.Typeflag != tar.TypeReg {
			return Control{}, fmt.Errorf("%s must contain exactly one regular control file", name)
		}

		if hdr.Size > maxControlSize {
			return Control{}, fmt.Errorf("control file of %s exceeds %d bytes", name, maxControlSize)
		}

		content, err = io.ReadAll(tr)
		if err != nil {
			return Control{}, fmt.Errorf("read control file of %s: %w", name, err)
		}
	}

	if content == nil {
		return Control{}, fmt.Errorf("%s has no control file", name)
	}

	control, err := ParseControl(strings.TrimRight(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n"))
	if err != nil {
		return Control{}, fmt.Errorf("parse control file of %s: %w", name, err)
	}

	return control, nil
}

// ParseControl parses a normalized binary package control paragraph.
func ParseControl(raw string) (Control, error) {
	if !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\x00") {
		return Control{}, fmt.Errorf("%w: invalid control text", ErrInvalidField)
	}

	fields := make(map[string]string)
	seen := make(map[string]bool)
	var (
		last  string
		value strings.Builder
	)

	for line := range strings.SplitSeq(raw, "\n") {
		if strings.Trim(line, " \t") == "" {
			return Control{}, fmt.Errorf("%w: empty line in control paragraph", ErrInvalidField)
		}

		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return Control{}, fmt.Errorf("%w: continuation without a field", ErrInvalidField)
			}

			value.WriteByte('\n')
			value.WriteString(line)
			continue
		}

		if last != "" {
			fields[last] = value.String()
			value.Reset()
		}

		name, data, ok := strings.Cut(line, ":")
		if !ok || !validFieldName(name) {
			return Control{}, fmt.Errorf("%w: malformed field name %q", ErrInvalidField, name)
		}

		lower := strings.ToLower(name)
		if seen[lower] {
			return Control{}, fmt.Errorf("%w: duplicate field %s", ErrInvalidField, name)
		}

		seen[lower] = true
		last = lower

		value.WriteString(strings.Trim(data, " \t"))
	}

	fields[last] = value.String()

	return Control{Raw: raw, Fields: fields}, nil
}

func validFieldName(name string) bool {
	if name == "" || name[0] == '#' || name[0] == '-' {
		return false
	}

	for _, c := range name {
		if c < '!' || c > '~' {
			return false
		}
	}

	return true
}

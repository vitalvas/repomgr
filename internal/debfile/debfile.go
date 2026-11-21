package debfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const (
	arMagic       string = "!<arch>\n"
	arHeaderSize  int    = 60
	arNameEnd     int    = 16
	arSizeStart   int    = 48
	arSizeEnd     int    = 58
	arEndMarker   string = "`\n"
	binaryName    string = "debian-binary"
	controlPrefix string = "control.tar"
	controlPlain  string = "control.tar"
	controlGzip   string = "control.tar.gz"
	controlXz     string = "control.tar.xz"
	controlZstd   string = "control.tar.zst"
	binaryVersion string = "2."
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

	first := true

	for {
		m, err := readHeader(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return Control{}, errors.New("no control archive found")
			}

			return Control{}, err
		}

		if first {
			first = false

			if err := checkBinary(r, m); err != nil {
				return Control{}, err
			}

			continue
		}

		if strings.HasPrefix(m.name, controlPrefix) {
			return readControl(r, m)
		}

		if err := skip(r, m.size); err != nil {
			return Control{}, fmt.Errorf("skip member %s: %w", m.name, err)
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

// readData reads a member's data and consumes its padding byte.
func readData(r io.Reader, m arMember) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, m.size))
	if err != nil {
		return nil, fmt.Errorf("read member %s: %w", m.name, err)
	}

	if int64(len(data)) != m.size {
		return nil, fmt.Errorf("read member %s: %w", m.name, io.ErrUnexpectedEOF)
	}

	if m.size%2 == 1 {
		if _, err := io.CopyN(io.Discard, r, 1); err != nil {
			return nil, fmt.Errorf("read member %s padding: %w", m.name, err)
		}
	}

	return data, nil
}

func checkBinary(r io.Reader, m arMember) error {
	if m.name != binaryName {
		return fmt.Errorf("first ar member is %q, want %s", m.name, binaryName)
	}

	data, err := readData(r, m)
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(data, []byte(binaryVersion)) {
		return fmt.Errorf("unsupported %s version %q", binaryName, strings.TrimSpace(string(data)))
	}

	return nil
}

func readControl(r io.Reader, m arMember) (Control, error) {
	data, err := readData(r, m)
	if err != nil {
		return Control{}, err
	}

	var src io.Reader

	switch m.name {
	case controlPlain:
		src = bytes.NewReader(data)
	case controlGzip:
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return Control{}, fmt.Errorf("open gzip of %s: %w", m.name, err)
		}

		src = zr
	case controlXz:
		xr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return Control{}, fmt.Errorf("open xz of %s: %w", m.name, err)
		}

		src = xr
	case controlZstd:
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return Control{}, fmt.Errorf("open zstd of %s: %w", m.name, err)
		}

		defer zr.Close()

		src = zr
	default:
		return Control{}, fmt.Errorf("unsupported control archive %s", m.name)
	}

	tr := tar.NewReader(src)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return Control{}, fmt.Errorf("%s has no control file", m.name)
		}

		if err != nil {
			return Control{}, fmt.Errorf("read tar of %s: %w", m.name, err)
		}

		if hdr.Name != "./control" && hdr.Name != "control" {
			continue
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			return Control{}, fmt.Errorf("read control file of %s: %w", m.name, err)
		}

		raw := strings.TrimRight(string(content), "\n")

		for line := range strings.SplitSeq(raw, "\n") {
			if strings.TrimSpace(line) == "" {
				return Control{}, fmt.Errorf("%w: %s control file has more than one paragraph", ErrInvalidField, m.name)
			}
		}

		return Control{Raw: raw, Fields: parseFields(raw)}, nil
	}
}

func parseFields(raw string) map[string]string {
	fields := make(map[string]string)
	last := ""

	for line := range strings.SplitSeq(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			break
		}

		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				fields[last] = fmt.Sprintf("%s\n%s", fields[last], line)
			}

			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		last = name
		fields[name] = strings.TrimSpace(value)
	}

	return fields
}

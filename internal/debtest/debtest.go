package debtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func Build(control string) ([]byte, error) {
	return BuildWith(control, ".gz")
}

// BuildWith names the control member control.tar<ext>; ext is "", ".gz", ".xz" or ".zst".
func BuildWith(control, ext string) ([]byte, error) {
	controlTar, err := archive(control, ext)
	if err != nil {
		return nil, fmt.Errorf("build control archive: %w", err)
	}

	dataTar, err := archive("", ".gz")
	if err != nil {
		return nil, fmt.Errorf("build data archive: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	writeMember(&buf, "debian-binary", []byte("2.0\n"))
	writeMember(&buf, fmt.Sprintf("control.tar%s", ext), controlTar)
	writeMember(&buf, "data.tar.gz", dataTar)

	return buf.Bytes(), nil
}

func writeMember(buf *bytes.Buffer, name string, data []byte) {
	fmt.Fprintf(buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
	buf.Write(data)

	if len(data)%2 == 1 {
		buf.WriteByte('\n')
	}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// archive returns an empty tar when control is empty, otherwise one with ./control.
func archive(control, ext string) ([]byte, error) {
	var buf bytes.Buffer

	var w io.WriteCloser

	switch ext {
	case "":
		w = nopCloser{&buf}
	case ".gz":
		w = gzip.NewWriter(&buf)
	case ".xz":
		xw, err := xz.NewWriter(&buf)
		if err != nil {
			return nil, fmt.Errorf("new xz writer: %w", err)
		}

		w = xw
	case ".zst":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, fmt.Errorf("new zstd writer: %w", err)
		}

		w = zw
	default:
		return nil, fmt.Errorf("unsupported compression %q", ext)
	}

	tw := tar.NewWriter(w)

	if control != "" {
		hdr := &tar.Header{
			Name:     "./control",
			Mode:     0o644,
			Size:     int64(len(control)),
			Typeflag: tar.TypeReg,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header: %w", err)
		}

		if _, err := tw.Write([]byte(control)); err != nil {
			return nil, fmt.Errorf("write tar content: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close compressor: %w", err)
	}

	return buf.Bytes(), nil
}

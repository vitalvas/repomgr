package debfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/debtest"
)

const sampleControl string = "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nDescription: short line\n long line one\n .\n long line two\n\n\n"

const multiParagraph string = "Package: a\nVersion: 1\nArchitecture: amd64\n\nPackage: evil\nVersion: 2\n"

func writeAr(buf *bytes.Buffer, name string, size int, data []byte) {
	fmt.Fprintf(buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", size)
	buf.Write(data)

	if len(data)%2 == 1 {
		buf.WriteByte('\n')
	}
}

func gzTar(t testing.TB, name string, content string) []byte {
	t.Helper()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	if name != "" {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))

		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())

	return buf.Bytes()
}

func buildAr(first string, firstData string, ctrlName string, ctrl []byte) []byte {
	var buf bytes.Buffer

	buf.WriteString("!<arch>\n")
	writeAr(&buf, first, len(firstData), []byte(firstData))

	if ctrlName != "" {
		writeAr(&buf, ctrlName, len(ctrl), ctrl)
	}

	return buf.Bytes()
}

func TestParse(t *testing.T) {
	t.Run("valid deb", func(t *testing.T) {
		deb, err := debtest.Build(sampleControl)
		require.NoError(t, err)

		c, err := Parse(bytes.NewReader(deb))
		require.NoError(t, err)

		assert.Equal(t, "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nDescription: short line\n long line one\n .\n long line two", c.Raw)
		assert.Equal(t, map[string]string{
			"package":      "hello",
			"version":      "1.0-1",
			"architecture": "amd64",
			"description":  "short line\n long line one\n .\n long line two",
		}, c.Fields)
	})

	t.Run("same control for every compression", func(t *testing.T) {
		want, err := debtest.BuildWith(sampleControl, ".gz")
		require.NoError(t, err)

		wantControl, err := Parse(bytes.NewReader(want))
		require.NoError(t, err)

		for _, ext := range []string{"", ".gz", ".xz", ".zst"} {
			deb, err := debtest.BuildWith(sampleControl, ext)
			require.NoError(t, err)

			c, err := Parse(bytes.NewReader(deb))
			require.NoError(t, err, "ext %q", ext)
			assert.Equal(t, wantControl, c, "ext %q", ext)
		}
	})

	t.Run("control without dot prefix and gnu names", func(t *testing.T) {
		deb := buildAr("debian-binary/", "2.0\n", "control.tar.gz/", gzTar(t, "control", "Package: x\n"))

		c, err := Parse(bytes.NewReader(deb))
		require.NoError(t, err)
		assert.Equal(t, "x", c.Fields["package"])
	})

	t.Run("skips members before control archive", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("!<arch>\n")
		writeAr(&buf, "debian-binary", 4, []byte("2.0\n"))
		writeAr(&buf, "_gpgorigin", 3, []byte("abc"))
		ctrl := gzTar(t, "./control", "Package: x\n")
		writeAr(&buf, "control.tar.gz", len(ctrl), ctrl)

		c, err := Parse(&buf)
		require.NoError(t, err)
		assert.Equal(t, "x", c.Fields["package"])
	})

	t.Run("trailing newlines only", func(t *testing.T) {
		deb := buildAr("debian-binary", "2.0\n", "control.tar.gz", gzTar(t, "./control", "Package: x\n\n\n"))

		c, err := Parse(bytes.NewReader(deb))
		require.NoError(t, err)
		assert.Equal(t, "Package: x", c.Raw)
	})

	for name, content := range map[string]string{
		"second paragraph":     multiParagraph,
		"whitespace-only line": "Package: a\n  \nVersion: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			deb := buildAr("debian-binary", "2.0\n", "control.tar.gz", gzTar(t, "./control", content))

			_, err := Parse(bytes.NewReader(deb))
			require.ErrorIs(t, err, ErrInvalidField)
			assert.Contains(t, err.Error(), "control.tar.gz")
		})
	}

	ctrl := gzTar(t, "./control", "Package: x\n")

	errCases := []struct {
		name string
		data []byte
		want string
	}{
		{"non-ar input", []byte("hello world, definitely not an ar archive"), "not an ar archive"},
		{"empty input", nil, "not an ar archive"},
		{"first member not debian-binary", buildAr("other", "2.0\n", "control.tar.gz", ctrl), "debian-binary"},
		{"bad debian-binary version", buildAr("debian-binary", "1.0\n", "control.tar.gz", ctrl), "version"},
		{"no control archive", buildAr("debian-binary", "2.0\n", "data.tar.gz", ctrl), "control archive"},
		{"only debian-binary", buildAr("debian-binary", "2.0\n", "", nil), "control archive"},
		{"bz2 control archive", buildAr("debian-binary", "2.0\n", "control.tar.bz2", []byte("xx")), "unsupported control archive control.tar.bz2"},
		{"bad xz", buildAr("debian-binary", "2.0\n", "control.tar.xz", []byte("not xz data")), "control.tar.xz"},
		{"bad zstd", buildAr("debian-binary", "2.0\n", "control.tar.zst", []byte("not zstd data")), "control.tar.zst"},
		{"bad plain tar", buildAr("debian-binary", "2.0\n", "control.tar", bytes.Repeat([]byte("x"), 600)), "control.tar"},
		{"no control entry", buildAr("debian-binary", "2.0\n", "control.tar.gz", gzTar(t, "./other", "x")), "has no control file"},
		{"empty control tar", buildAr("debian-binary", "2.0\n", "control.tar.gz", gzTar(t, "", "")), "has no control file"},
		{"huge size header over short data", []byte(fmt.Sprintf("!<arch>\n%-16s%-12d%-6d%-6d%-8s%-10d`\n2.0", "debian-binary", 0, 0, 0, "100644", 9999999999)), "EOF"},
		{"huge skipped member over short data", append(buildAr("debian-binary", "2.0\n", "", nil), []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\nabc", "_extra", 0, 0, 0, "100644", 9999999999))...), "skip member _extra"},
		{"bad gzip", buildAr("debian-binary", "2.0\n", "control.tar.gz", []byte("not gzip")), "gzip"},
		{"bad member header magic", append([]byte("!<arch>\n"), bytes.Repeat([]byte("x"), 60)...), "magic"},
		{"bad member size", []byte(fmt.Sprintf("!<arch>\n%-16s%-12d%-6d%-6d%-8s%-10s`\n", "debian-binary", 0, 0, 0, "100644", "zz")), "size"},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(tc.data))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("truncated archive", func(t *testing.T) {
		deb, err := debtest.Build(sampleControl)
		require.NoError(t, err)

		for _, n := range []int{4, 20, 70, 100, len(deb) / 2} {
			_, err := Parse(bytes.NewReader(deb[:n]))
			assert.Error(t, err, "cut at %d", n)
		}
	})
}

func TestSkip(t *testing.T) {
	t.Run("odd size consumes padding", func(t *testing.T) {
		r := bytes.NewReader([]byte("abc\nZ"))
		require.NoError(t, skip(r, 3))
		assert.Equal(t, 1, r.Len())
	})

	t.Run("huge odd size errors", func(t *testing.T) {
		require.Error(t, skip(bytes.NewReader([]byte("abc")), math.MaxInt64))
	})

	t.Run("missing padding errors", func(t *testing.T) {
		require.Error(t, skip(bytes.NewReader([]byte("abc")), 3))
	})
}

func TestParseControl(t *testing.T) {
	control, err := ParseControl("pAcKaGe:   one  \nVersion: 1\nB: two\n\tmore")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"package": "one", "version": "1", "b": "two\n\tmore"}, control.Fields)

	control, err = ParseControl("package: p\nVERSION: 2\narchitecture: all\nFilename: x")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"package": "p", "version": "2", "architecture": "all", "filename": "x"}, control.Fields)
	assert.Equal(t, "package: p\nVERSION: 2\narchitecture: all\nFilename: x", control.Raw)

	for _, raw := range []string{"A: one\n\nB: two", " orphan\nA: one", "A: one\nno colon", "Field Name: x", "A: one\na: two", "Package: x\npackage: y"} {
		_, err := ParseControl(raw)
		assert.ErrorIs(t, err, ErrInvalidField, "%q", raw)
	}
}

func TestParseControlArchiveIntegrity(t *testing.T) {
	t.Run("gzip checksum", func(t *testing.T) {
		ctrl := gzTar(t, "./control", "Package: example\n")
		ctrl[len(ctrl)-8] ^= 1
		_, err := Parse(bytes.NewReader(buildAr("debian-binary", "2.0\n", "control.tar.gz", ctrl)))
		require.ErrorIs(t, err, gzip.ErrChecksum)
	})

	t.Run("CRLF", func(t *testing.T) {
		ctrl := gzTar(t, "./control", "Package: example\r\nDescription: example\r\n long\r\n")
		control, err := Parse(bytes.NewReader(buildAr("debian-binary", "2.0\n", "control.tar.gz", ctrl)))
		require.NoError(t, err)
		assert.Equal(t, "Package: example\nDescription: example\n long", control.Raw)
	})
}

// controlArchive returns a control tar for ext holding an ignored entry of
// ignored zero bytes and ./control, followed by trailing zero bytes after the
// tar end.
func controlArchive(t testing.TB, ext string, ignored, trailing int) []byte {
	t.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	entries := []struct {
		name string
		data []byte
	}{
		{"./ignored", make([]byte, ignored)},
		{"./control", []byte("Package: x\n")},
	}

	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}))

		_, err := tw.Write(e.data)
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	buf.Write(make([]byte, trailing))

	data, err := debtest.Compress(ext, buf.Bytes())
	require.NoError(t, err)

	return data
}

// readArchive runs readControl on data as the member name, with the ar
// padding byte after it.
func readArchive(name string, data []byte, limit int64) (Control, error) {
	return readControl(bytes.NewReader(append(slices.Clone(data), '\n')), arMember{name: name, size: int64(len(data))}, limit)
}

func TestControlArchiveLimit(t *testing.T) {
	const limit int64 = 64 << 10

	tests := map[string]struct {
		ignored  int
		trailing int
		ok       bool
	}{
		"under the limit":           {ignored: 32 << 10, ok: true},
		"large ignored entry":       {ignored: 1 << 20},
		"large data after the tar":  {trailing: 1 << 20},
		"limit hit inside an entry": {ignored: int(limit)},
	}

	for _, ext := range []string{"", ".gz", ".xz", ".zst"} {
		name := fmt.Sprintf("control.tar%s", ext)

		for desc, tc := range tests {
			t.Run(fmt.Sprintf("%s %s", name, desc), func(t *testing.T) {
				c, err := readArchive(name, controlArchive(t, ext, tc.ignored, tc.trailing), limit)
				if tc.ok {
					require.NoError(t, err)
					assert.Equal(t, "x", c.Fields["package"])

					return
				}

				require.ErrorContains(t, err, fmt.Sprintf("control archive %s exceeds %d bytes uncompressed", name, limit))
			})
		}
	}

	t.Run("exact limit passes and one byte less fails", func(t *testing.T) {
		data := controlArchive(t, "", 0, 0)

		_, err := readArchive(controlPlain, data, int64(len(data)))
		require.NoError(t, err)

		_, err = readArchive(controlPlain, data, int64(len(data)-1))
		require.ErrorContains(t, err, "exceeds")
	})

	t.Run("parse applies the 64 MiB limit", func(t *testing.T) {
		ctrl := controlArchive(t, "", int(maxControlArchiveSize), 0)

		_, err := Parse(bytes.NewReader(buildAr("debian-binary", "2.0\n", controlPlain, ctrl)))
		require.ErrorContains(t, err, "control archive control.tar exceeds 67108864 bytes uncompressed")
	})
}

func FuzzParse(f *testing.F) {
	deb, err := debtest.Build(sampleControl)
	require.NoError(f, err)

	f.Add(deb)

	for _, ext := range []string{"", ".xz", ".zst"} {
		seed, err := debtest.BuildWith(sampleControl, ext)
		require.NoError(f, err)

		f.Add(seed)
	}

	multi, err := debtest.Build(multiParagraph)
	require.NoError(f, err)

	f.Add(multi)
	f.Add([]byte("!<arch>\n"))
	f.Add([]byte(""))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse(bytes.NewReader(data))
	})
}

func BenchmarkParse(b *testing.B) {
	deb, err := debtest.Build(sampleControl)
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := Parse(bytes.NewReader(deb)); err != nil {
			b.Fatal(err)
		}
	}
}

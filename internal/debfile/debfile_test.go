package debfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"math"
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
			"Package":      "hello",
			"Version":      "1.0-1",
			"Architecture": "amd64",
			"Description":  "short line\n long line one\n .\n long line two",
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
		assert.Equal(t, "x", c.Fields["Package"])
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
		assert.Equal(t, "x", c.Fields["Package"])
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
		{"huge size header over short data", []byte(fmt.Sprintf("!<arch>\n%-16s%-12d%-6d%-6d%-8s%-10d`\nabc", "debian-binary", 0, 0, 0, "100644", 9999999999)), "unexpected EOF"},
		{"huge skipped member over short data", append(buildAr("debian-binary", "2.0\n", "", nil), []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\nabc", "data.tar.gz", 0, 0, 0, "100644", 9999999999))...), "skip member data.tar.gz"},
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

func TestParseFields(t *testing.T) {
	t.Run("stops at blank line and trims values", func(t *testing.T) {
		f := parseFields("A:   one  \nB: two\n\nC: three")
		assert.Equal(t, map[string]string{"A": "one", "B": "two"}, f)
	})

	t.Run("tab continuation and stray lines", func(t *testing.T) {
		f := parseFields(" orphan\nnocolon\nA: x\n\ty")
		assert.Equal(t, map[string]string{"A": "x\n\ty"}, f)
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

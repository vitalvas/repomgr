package debtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type member struct {
	name string
	data []byte
}

func readAr(t *testing.T, b []byte) []member {
	t.Helper()

	require.True(t, bytes.HasPrefix(b, []byte("!<arch>\n")))
	b = b[8:]

	var out []member

	for len(b) > 0 {
		require.GreaterOrEqual(t, len(b), 60)
		require.Equal(t, "`\n", string(b[58:60]))

		size, err := strconv.Atoi(strings.TrimSpace(string(b[48:58])))
		require.NoError(t, err)

		out = append(out, member{
			name: strings.TrimSpace(string(b[:16])),
			data: b[60 : 60+size],
		})

		b = b[60+size+size%2:]
	}

	return out
}

func untar(t *testing.T, gz []byte) *tar.Reader {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(gz))
	require.NoError(t, err)

	return tar.NewReader(zr)
}

func TestBuild(t *testing.T) {
	const control string = "Package: hello\nVersion: 1.0\n"

	deb, err := Build(control)
	require.NoError(t, err)

	members := readAr(t, deb)
	require.Len(t, members, 3)

	t.Run("debian-binary", func(t *testing.T) {
		assert.Equal(t, "debian-binary", members[0].name)
		assert.Equal(t, "2.0\n", string(members[0].data))
	})

	t.Run("control archive", func(t *testing.T) {
		assert.Equal(t, "control.tar.gz", members[1].name)

		tr := untar(t, members[1].data)
		hdr, err := tr.Next()
		require.NoError(t, err)
		assert.Equal(t, "./control", hdr.Name)
		assert.Equal(t, byte(tar.TypeReg), hdr.Typeflag)

		content, err := io.ReadAll(tr)
		require.NoError(t, err)
		assert.Equal(t, control, string(content))

		_, err = tr.Next()
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("data archive is empty", func(t *testing.T) {
		assert.Equal(t, "data.tar.gz", members[2].name)

		_, err := untar(t, members[2].data).Next()
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("odd size member is padded", func(t *testing.T) {
		var buf bytes.Buffer

		writeMember(&buf, "x", []byte("abc"))

		assert.Equal(t, 60+3+1, buf.Len())
		assert.Equal(t, "abc\n", buf.String()[60:])
	})
}

func TestBuildWith(t *testing.T) {
	for _, ext := range []string{"", ".gz", ".xz", ".zst"} {
		t.Run(fmt.Sprintf("ext %q", ext), func(t *testing.T) {
			deb, err := BuildWith("Package: x\n", ext)
			require.NoError(t, err)

			members := readAr(t, deb)
			require.Len(t, members, 3)
			assert.Equal(t, fmt.Sprintf("control.tar%s", ext), members[1].name)
			assert.Equal(t, "data.tar.gz", members[2].name)
		})
	}

	t.Run("unknown ext", func(t *testing.T) {
		_, err := BuildWith("Package: x\n", ".bz2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), ".bz2")
	})
}

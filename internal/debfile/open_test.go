package debfile

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/debtest"
)

func writeDeb(t testing.TB, control string) (string, []byte) {
	t.Helper()

	data, err := debtest.Build(control)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "test.deb")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path, data
}

func controlOf(pkg, version, arch string) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nDescription: d\n", pkg, version, arch)
}

func TestOpen(t *testing.T) {
	t.Run("checksums and size", func(t *testing.T) {
		control := controlOf("hello", "1.0-1", "amd64")
		path, data := writeDeb(t, control)

		pkg, err := Open(path)
		require.NoError(t, err)

		md := md5.Sum(data)
		s1 := sha1.Sum(data)
		s256 := sha256.Sum256(data)

		assert.Equal(t, int64(len(data)), pkg.Size)
		assert.Equal(t, hex.EncodeToString(md[:]), pkg.MD5)
		assert.Equal(t, hex.EncodeToString(s1[:]), pkg.SHA1)
		assert.Equal(t, hex.EncodeToString(s256[:]), pkg.SHA256)
		assert.Equal(t, "hello", pkg.Control.Fields["Package"])
		assert.Equal(t, "amd64", pkg.Control.Fields["Architecture"])
		assert.Equal(t, control[:len(control)-1], pkg.Control.Raw)
	})

	t.Run("valid edge cases", func(t *testing.T) {
		cases := [][3]string{
			{"zabbix-release", "1:2.0-1~bookworm", "all"},
			{"ab", "6.0-10+ubuntu24.04", "arm64"},
			{"libc6", "2.36", "armhf"},
			{"libc6", "2.36", "armel"},
			{"libc6", "2.36", "i386"},
		}

		for _, c := range cases {
			t.Run(fmt.Sprintf("%s_%s_%s", c[0], c[1], c[2]), func(t *testing.T) {
				path, _ := writeDeb(t, controlOf(c[0], c[1], c[2]))

				pkg, err := Open(path)
				require.NoError(t, err)
				assert.Equal(t, c[0], pkg.Control.Fields["Package"])
			})
		}
	})

	t.Run("invalid fields", func(t *testing.T) {
		cases := map[string]string{
			"package uppercase":    controlOf("Hello", "1.0", "amd64"),
			"package one char":     controlOf("a", "1.0", "amd64"),
			"package slash":        controlOf("a/b", "1.0", "amd64"),
			"version letter":       controlOf("hello", "v1.0", "amd64"),
			"version slash":        controlOf("hello", "1.0/x", "amd64"),
			"invalid epoch":        controlOf("hello", "1.0:2.0", "amd64"),
			"empty upstream":       controlOf("hello", "1:", "amd64"),
			"empty revision":       controlOf("hello", "1.0-", "amd64"),
			"arch riscv64":         controlOf("hello", "1.0", "riscv64"),
			"missing package":      "Version: 1.0\nArchitecture: amd64\n",
			"missing version":      "Package: hello\nArchitecture: amd64\n",
			"missing arch":         "Package: hello\nVersion: 1.0\n",
			"empty architecture":   "Package: hello\nVersion: 1.0\nArchitecture:\n",
			"version continuation": "Package: hello\nVersion: 1.0\n x\nArchitecture: amd64\n",
		}

		for name, control := range cases {
			t.Run(name, func(t *testing.T) {
				path, _ := writeDeb(t, control)

				_, err := Open(path)
				require.ErrorIs(t, err, ErrInvalidField)
			})
		}
	})

	t.Run("error names field and value", func(t *testing.T) {
		path, _ := writeDeb(t, controlOf("hello", "1.0", "riscv64"))

		_, err := Open(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Architecture")
		assert.Contains(t, err.Error(), "riscv64")
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := Open(filepath.Join(t.TempDir(), "none.deb"))
		require.Error(t, err)
	})

	t.Run("not a deb", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.deb")
		require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o600))

		_, err := Open(path)
		require.Error(t, err)
	})
}

func TestOpenRequiresCompleteDataMember(t *testing.T) {
	raw := controlOf("hello", "1.0", "amd64")
	path, valid := writeDeb(t, raw)
	missing := buildAr("debian-binary", "2.0\n", "control.tar.gz", gzTar(t, "./control", raw))

	for _, tc := range []struct {
		data []byte
		want string
	}{{missing, "data archive"}, {valid[:len(valid)-2], "data.tar.gz"}} {
		require.NoError(t, os.WriteFile(path, tc.data, 0o600))
		_, err := Open(path)
		require.ErrorContains(t, err, tc.want)
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(controlOf("hello", "1.0-1", "amd64"))
	f.Add(controlOf("Hello", "1.0", "amd64"))
	f.Add(controlOf("hello", "1.0", "riscv64"))
	f.Add("Package: hello\n")

	f.Fuzz(func(t *testing.T, control string) {
		data, err := debtest.Build(control)
		if err != nil {
			t.Skip()
		}

		path := filepath.Join(t.TempDir(), "fuzz.deb")
		require.NoError(t, os.WriteFile(path, data, 0o600))

		pkg, err := Open(path)
		if err != nil {
			return
		}

		sum := sha256.Sum256(data)

		assert.Equal(t, hex.EncodeToString(sum[:]), pkg.SHA256)
		assert.Equal(t, int64(len(data)), pkg.Size)
	})
}

func BenchmarkOpen(b *testing.B) {
	path, _ := writeDeb(b, controlOf("hello", "1.0-1", "amd64"))

	b.ReportAllocs()

	for b.Loop() {
		if _, err := Open(path); err != nil {
			b.Fatal(err)
		}
	}
}

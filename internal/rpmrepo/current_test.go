package rpmrepo

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.vitalvas.com/repomgr/internal/pgpsign"
)

// publishSigned writes md as the signed repomd.xml of repodata.
func publishSigned(t *testing.T, repodata string, key []byte, md repomd) {
	t.Helper()

	data, err := marshalXML(md)
	require.NoError(t, err)

	signed, err := pgpsign.Sign(key, data)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(repodata, "repomd.xml"), data, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repodata, "repomd.xml.asc"), signed.Detached, 0o644))
}

func TestRepoCurrent(t *testing.T) {
	key := readSigningKey(t, initWorkdir(t))
	now := time.Unix(1800000000, 0)

	public, err := pgpsign.PublicKey(key)
	require.NoError(t, err)

	other, err := pgpsign.GenerateKey("Other", "other@example.com")
	require.NoError(t, err)

	rendered, files, err := renderRepo([]repoPackage{samplePackage()}, key, now)
	require.NoError(t, err)

	changed := samplePackage()
	changed.pkg.Name = "changed"

	changedRendered, _, err := renderRepo([]repoPackage{changed}, key, now)
	require.NoError(t, err)

	type testCase struct {
		rendered repomd
		public   []byte
		mutate   func(t *testing.T, repodata string)
		want     bool
	}

	cases := map[string]testCase{
		"unchanged": {rendered, public, nil, true},
		"later revision": {
			func() repomd { r := rendered; r.Revision++; return r }(),
			public, nil, true,
		},
		"different content": {changedRendered, public, nil, false},
		"other key":         {rendered, other.Public, nil, false},
		"missing repomd": {rendered, public, func(t *testing.T, repodata string) {
			require.NoError(t, os.Remove(filepath.Join(repodata, "repomd.xml")))
		}, false},
		"unparseable repomd": {rendered, public, func(t *testing.T, repodata string) {
			require.NoError(t, os.WriteFile(filepath.Join(repodata, "repomd.xml"), []byte("<repomd"), 0o644))
		}, false},
		"missing signature": {rendered, public, func(t *testing.T, repodata string) {
			require.NoError(t, os.Remove(filepath.Join(repodata, "repomd.xml.asc")))
		}, false},
		"signed extra entry": {rendered, public, func(t *testing.T, repodata string) {
			md := rendered
			md.Data = append(slices.Clone(rendered.Data), rendered.Data[0])
			publishSigned(t, repodata, key, md)
		}, false},
		"signed duplicate type": {rendered, public, func(t *testing.T, repodata string) {
			md := rendered
			md.Data = slices.Clone(rendered.Data)
			md.Data[2] = rendered.Data[1]
			publishSigned(t, repodata, key, md)
		}, false},
		"signed missing type": {rendered, public, func(t *testing.T, repodata string) {
			md := rendered
			md.Data = slices.Clone(rendered.Data[:2])
			publishSigned(t, repodata, key, md)
		}, false},
	}

	for i, typ := range []string{"primary", "filelists", "other"} {
		cases[fmt.Sprintf("only %s differs", typ)] = testCase{
			func() repomd {
				r := rendered
				r.Data = slices.Clone(rendered.Data)
				r.Data[i].OpenChecksum.Value = "0"

				return r
			}(),
			public, nil, false,
		}

		cases[fmt.Sprintf("missing %s file", typ)] = testCase{rendered, public, func(t *testing.T, repodata string) {
			require.NoError(t, os.Remove(filepath.Join(repodata, files[i].name)))
		}, false}

		cases[fmt.Sprintf("%s file is a directory", typ)] = testCase{rendered, public, func(t *testing.T, repodata string) {
			name := filepath.Join(repodata, files[i].name)
			require.NoError(t, os.Remove(name))
			require.NoError(t, os.Mkdir(name, 0o755))
		}, false}

		cases[fmt.Sprintf("%s file has other bytes", typ)] = testCase{rendered, public, func(t *testing.T, repodata string) {
			require.NoError(t, os.WriteFile(filepath.Join(repodata, files[i].name), []byte("other"), 0o644))
		}, false}
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			repodata := filepath.Join(dir, "repodata")
			require.NoError(t, os.Mkdir(repodata, 0o755))

			for _, f := range files {
				require.NoError(t, os.WriteFile(filepath.Join(repodata, f.name), f.data, 0o644))
			}

			if tc.mutate != nil {
				tc.mutate(t, repodata)
			}

			assert.Equal(t, tc.want, repoCurrent(dir, tc.rendered, tc.public))
		})
	}
}

package rpmrepo

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
)

var errNotRegular = errors.New("not a regular file")

// repoCurrent returns the verified repomd.xml when its metadata agrees with
// the rendered repository.
func repoCurrent(dir string, rendered repomd, publicKey []byte) (repomd, bool) {
	repodata := filepath.Join(dir, "repodata")

	data, err := readRegular(filepath.Join(repodata, "repomd.xml"))
	if err != nil {
		return repomd{}, false
	}

	// The signature comes first: the hrefs are only trusted once it verifies.
	asc, err := readRegular(filepath.Join(repodata, "repomd.xml.asc"))
	if err != nil || pgpsign.VerifyDetached(publicKey, data, asc) != nil {
		return repomd{}, false
	}

	var published repomd

	err = xml.Unmarshal(data, &published)
	if err != nil || published.XMLName.Space != nsRepo || len(published.Data) != len(rendered.Data) {
		return repomd{}, false
	}

	for i, d := range published.Data {
		if !metadataCurrent(repodata, d, rendered.Data[i]) {
			return repomd{}, false
		}
	}

	return published, true
}

func metadataCurrent(repodata string, d, want repomdData) bool {
	name := fmt.Sprintf("%s-%s.xml.gz", d.Checksum.Value, d.Type)
	if d.Type != want.Type || d.OpenChecksum != want.OpenChecksum || d.OpenSize != want.OpenSize ||
		d.Checksum.Type != want.Checksum.Type || !metadataName.MatchString(name) || d.Location.Href != path.Join("repodata", name) {
		return false
	}

	file := filepath.Join(repodata, name)
	sum, size, err := repofs.FileSHA256(file)
	if err != nil || sum != d.Checksum.Value || size != int64(d.Size) {
		return false
	}

	// A different gzip encoder can produce different compressed bytes.
	return sum == want.Checksum.Value || matchesOpenChecksum(file, want)
}

func matchesOpenChecksum(file string, want repomdData) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer r.Close()

	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(r, int64(want.OpenSize)+1))

	return err == nil && n == int64(want.OpenSize) && hex.EncodeToString(sum.Sum(nil)) == want.OpenChecksum.Value
}

func readRegular(file string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", file, errNotRegular)
	}

	return os.ReadFile(file)
}

func isRegularWith(file, sum string) bool {
	got, _, err := repofs.FileSHA256(file)

	return err == nil && got == sum
}

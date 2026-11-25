package rpmrepo

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
)

// repoCurrent reports whether the repository in dir already holds what rendered
// describes: the published repomd.xml parses, its primary, filelists, and other
// entries have the rendered open checksums, repomd.xml.asc verifies over it
// with publicKey, and every file it lists exists.
func repoCurrent(dir string, rendered repomd, publicKey []byte) bool {
	repodata := filepath.Join(dir, "repodata")

	data, err := os.ReadFile(filepath.Join(repodata, "repomd.xml"))
	if err != nil {
		return false
	}

	// The signature comes first: the hrefs are only trusted once it verifies.
	asc, err := os.ReadFile(filepath.Join(repodata, "repomd.xml.asc"))
	if err != nil || pgpsign.VerifyDetached(publicKey, data, asc) != nil {
		return false
	}

	var published repomd

	err = xml.Unmarshal(data, &published)
	if err != nil || len(published.Data) != len(rendered.Data) {
		return false
	}

	for i, d := range published.Data {
		want := rendered.Data[i]
		if d.Type != want.Type || d.OpenChecksum.Value != want.OpenChecksum.Value {
			return false
		}

		if !isRegularWith(filepath.Join(dir, filepath.FromSlash(d.Location.Href)), d.Checksum.Value) {
			return false
		}
	}

	return true
}

// isRegularWith reports whether file is a regular file (not a link) whose
// SHA-256 is sum.
func isRegularWith(file, sum string) bool {
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}

	data, err := os.ReadFile(file)

	return err == nil && hexSHA256(data) == sum
}

package rpmrepo

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"

	"go.vitalvas.com/repomgr/internal/rpmfile"
)

const (
	cacheVersion int = 2
	sha256Len    int = 64
)

// cacheEntry holds the gob encoding of a package, which keeps every text byte
// as it is; JSON would turn invalid UTF-8 into U+FFFD. Gob drops a zero epoch
// pointer (&0 decodes as nil), which does not change the output: a missing
// epoch is written as 0.
type cacheEntry struct {
	Version int    `json:"version"`
	Size    int64  `json:"size"`
	MTime   int64  `json:"mtime"`
	Package []byte `json:"package"`
}

func newCacheEntry(info os.FileInfo, pkg rpmfile.Package) (cacheEntry, error) {
	var buf bytes.Buffer

	err := gob.NewEncoder(&buf).Encode(pkg)
	if err != nil {
		return cacheEntry{}, fmt.Errorf("encode cache entry: %w", err)
	}

	return cacheEntry{
		Version: cacheVersion,
		Size:    info.Size(),
		MTime:   info.ModTime().UnixNano(),
		Package: buf.Bytes(),
	}, nil
}

// matches reports whether the entry describes the file at info and holds a
// valid package, and returns that package.
func (e cacheEntry) matches(info os.FileInfo) (rpmfile.Package, bool) {
	if e.Version != cacheVersion || e.Size != info.Size() || e.MTime != info.ModTime().UnixNano() {
		return rpmfile.Package{}, false
	}

	var pkg rpmfile.Package

	err := gob.NewDecoder(bytes.NewReader(e.Package)).Decode(&pkg)
	if err != nil || pkg.Size != e.Size || len(pkg.SHA256) != sha256Len {
		return rpmfile.Package{}, false
	}

	_, err = hex.DecodeString(pkg.SHA256)
	if err != nil || pkg.Validate() != nil {
		return rpmfile.Package{}, false
	}

	return pkg, true
}

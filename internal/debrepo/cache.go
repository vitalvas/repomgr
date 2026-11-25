package debrepo

import (
	"encoding/hex"
	"maps"
	"os"

	"go.vitalvas.com/repomgr/internal/debfile"
)

const cacheVersion int = 1

type cacheEntry struct {
	Version int               `json:"version"`
	Size    int64             `json:"size"`
	MTime   int64             `json:"mtime"`
	Control string            `json:"control"`
	Fields  map[string]string `json:"fields"`
	MD5     string            `json:"md5"`
	SHA1    string            `json:"sha1"`
	SHA256  string            `json:"sha256"`
}

func newCacheEntry(info os.FileInfo, pkg debfile.Package) cacheEntry {
	return cacheEntry{
		Version: cacheVersion,
		Size:    info.Size(),
		MTime:   info.ModTime().UnixNano(),
		Control: pkg.Control.Raw,
		Fields:  pkg.Control.Fields,
		MD5:     pkg.MD5,
		SHA1:    pkg.SHA1,
		SHA256:  pkg.SHA256,
	}
}

func (e cacheEntry) matches(info os.FileInfo) bool {
	if e.Version != cacheVersion || e.Size != info.Size() || e.MTime != info.ModTime().UnixNano() ||
		!validChecksum(e.MD5, 32) || !validChecksum(e.SHA1, 40) || !validChecksum(e.SHA256, 64) {
		return false
	}

	control, err := debfile.ParseControl(e.Control)

	return err == nil && control.Validate() == nil && maps.Equal(e.Fields, control.Fields)
}

func validChecksum(sum string, size int) bool {
	if len(sum) != size {
		return false
	}

	_, err := hex.DecodeString(sum)

	return err == nil
}

func (e cacheEntry) pkg() debfile.Package {
	return debfile.Package{
		Control: debfile.Control{Raw: e.Control, Fields: e.Fields},
		Size:    e.Size,
		MD5:     e.MD5,
		SHA1:    e.SHA1,
		SHA256:  e.SHA256,
	}
}

package rpmfile

import "fmt"

const (
	tagFileModes  uint32 = 1030
	tagFileFlags  uint32 = 1037
	tagDirIndexes uint32 = 1116
	tagBaseNames  uint32 = 1117
	tagDirNames   uint32 = 1118
	fileTypeMask  uint16 = 0o170000
	fileTypeDir   uint16 = 0o040000
	fileFlagGhost uint32 = 1 << 6
)

// File is one entry of the package file list.
type File struct {
	Path  string
	Mode  uint16
	Flags uint32
}

func (f File) IsDir() bool {
	return f.Mode&fileTypeMask == fileTypeDir
}

// IsGhost is RPMFILE_GHOST from rpm 4.14.3 lib/rpmfiles.h.
func (f File) IsGhost() bool {
	return f.Flags&fileFlagGhost != 0
}

// files fills the file list of p. A package without BASENAMES has no files;
// one with BASENAMES needs the other four tags, and four of them share a count.
func (h header) files(p *Package) error {
	base, ok := h.entries[tagBaseNames]
	if !ok {
		return nil
	}

	for _, t := range []struct {
		tag  uint32
		name string
	}{{tagDirNames, "DIRNAMES"}, {tagDirIndexes, "DIRINDEXES"}, {tagFileModes, "FILEMODES"}, {tagFileFlags, "FILEFLAGS"}} {
		e, ok := h.entries[t.tag]
		if !ok {
			return fmt.Errorf("%w: %s is missing", ErrInvalidField, t.name)
		}

		// Comparing the counts first means a mismatched header allocates nothing.
		if t.tag != tagDirNames && e.count != base.count {
			return fmt.Errorf("%w: %s has count %d, BASENAMES has %d", ErrInvalidField, t.name, e.count, base.count)
		}
	}

	basenames, _, err := h.strings(tagBaseNames, "BASENAMES")
	if err != nil {
		return err
	}

	dirnames, _, err := h.strings(tagDirNames, "DIRNAMES")
	if err != nil {
		return err
	}

	indexes, _, err := h.int32s(tagDirIndexes, "DIRINDEXES")
	if err != nil {
		return err
	}

	modes, _, err := h.int16s(tagFileModes, "FILEMODES")
	if err != nil {
		return err
	}

	flags, _, err := h.int32s(tagFileFlags, "FILEFLAGS")
	if err != nil {
		return err
	}

	files := make([]File, len(basenames))

	for i := range basenames {
		if uint64(indexes[i]) >= uint64(len(dirnames)) {
			return fmt.Errorf("%w: DIRINDEXES entry %d is %d, DIRNAMES has %d", ErrInvalidField, i, indexes[i], len(dirnames))
		}

		files[i] = File{Path: fmt.Sprintf("%s%s", dirnames[indexes[i]], basenames[i]), Mode: modes[i], Flags: flags[i]}
	}

	p.Files = files

	return nil
}

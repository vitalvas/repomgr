package debfile

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalidField = errors.New("invalid control field")

	packageRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionRe  = regexp.MustCompile(`^(?:[0-9]+:[0-9][A-Za-z0-9.+~:-]*|[0-9][A-Za-z0-9.+~-]*)$`)
	revisionRe = regexp.MustCompile(`^[A-Za-z0-9+.~]+$`)

	Architectures = []string{"all", "amd64", "arm64", "armel", "armhf", "i386"}
)

type Package struct {
	Control Control
	Size    int64
	MD5     string
	SHA1    string
	SHA256  string
}

func Open(path string) (Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return Package{}, fmt.Errorf("open deb: %w", err)
	}
	defer f.Close()

	md := md5.New()
	s1 := sha1.New()
	s256 := sha256.New()

	tee := io.TeeReader(f, io.MultiWriter(md, s1, s256))

	control, err := Parse(tee)
	if err != nil {
		return Package{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if err := readPayload(tee); err != nil {
		return Package{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if _, err := io.Copy(io.Discard, tee); err != nil {
		return Package{}, fmt.Errorf("read %s: %w", path, err)
	}

	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return Package{}, fmt.Errorf("position %s: %w", path, err)
	}

	if err := control.Validate(); err != nil {
		return Package{}, err
	}

	return Package{
		Control: control,
		Size:    size,
		MD5:     hex.EncodeToString(md.Sum(nil)),
		SHA1:    hex.EncodeToString(s1.Sum(nil)),
		SHA256:  hex.EncodeToString(s256.Sum(nil)),
	}, nil
}

// Validate checks the control fields used to identify a binary package.
func (c Control) Validate() error {
	pkg := c.Fields["package"]
	if !packageRe.MatchString(pkg) {
		return fmt.Errorf("%w: Package %q", ErrInvalidField, pkg)
	}

	version := c.Fields["version"]
	dash := strings.LastIndexByte(version, '-')
	if !versionRe.MatchString(version) || (dash >= 0 && !revisionRe.MatchString(version[dash+1:])) {
		return fmt.Errorf("%w: Version %q", ErrInvalidField, version)
	}

	arch := c.Fields["architecture"]
	if !slices.Contains(Architectures, arch) {
		return fmt.Errorf("%w: Architecture %q", ErrInvalidField, arch)
	}

	return nil
}

// readPayload verifies the required data member's envelope without unpacking it.
func readPayload(r io.Reader) error {
	m, err := nextRequiredMember(r)
	if err != nil {
		return fmt.Errorf("read data archive: %w", err)
	}

	switch m.name {
	case "data.tar", "data.tar.gz", "data.tar.xz", "data.tar.zst", "data.tar.bz2", "data.tar.lzma":
	default:
		return fmt.Errorf("expected data archive, found %s", m.name)
	}

	if m.size == 0 {
		return fmt.Errorf("empty data archive %s", m.name)
	}

	if err := skip(r, m.size); err != nil {
		return fmt.Errorf("read %s: %w", m.name, err)
	}

	return nil
}

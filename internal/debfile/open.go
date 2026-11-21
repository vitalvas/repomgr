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
)

var (
	ErrInvalidField = errors.New("invalid control field")

	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)

	architectures = []string{"all", "amd64", "arm64", "armel", "armhf", "i386"}
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

	if _, err := io.Copy(io.Discard, tee); err != nil {
		return Package{}, fmt.Errorf("read %s: %w", path, err)
	}

	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return Package{}, fmt.Errorf("position %s: %w", path, err)
	}

	if err := validate(control.Fields); err != nil {
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

func validate(fields map[string]string) error {
	pkg := fields["Package"]
	if !packageRe.MatchString(pkg) {
		return fmt.Errorf("%w: Package %q", ErrInvalidField, pkg)
	}

	version := fields["Version"]
	if !versionRe.MatchString(version) {
		return fmt.Errorf("%w: Version %q", ErrInvalidField, version)
	}

	arch := fields["Architecture"]
	if !slices.Contains(architectures, arch) {
		return fmt.Errorf("%w: Architecture %q", ErrInvalidField, arch)
	}

	return nil
}

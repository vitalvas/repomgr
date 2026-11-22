package debrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/klauspost/compress/zstd"
	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/pgpsign"
)

var ErrMirrorFailed = errors.New("some packages failed to mirror")

type MirrorOptions struct {
	SourceRepo      string
	SourceSuite     string
	SourceComponent string
	TargetSuite     string
	TargetComponent string

	// SourceKey is the upstream public key (armored or binary); empty skips the InRelease signature check.
	SourceKey []byte

	// Force replaces a target pool file whose SHA256 differs from upstream.
	Force bool

	// Each pattern must match the whole control field value (Package, Version,
	// Architecture). An empty pattern means no filter.
	Name                string
	NameExclude         string
	Version             string
	VersionExclude      string
	Architecture        string
	ArchitectureExclude string
}

type mirrorFilters struct {
	name, version, architecture filterPair
}

type filterPair struct {
	include, exclude *regexp.Regexp
}

func (p filterPair) selected(value string) bool {
	if p.include != nil && !p.include.MatchString(value) {
		return false
	}

	return p.exclude == nil || !p.exclude.MatchString(value)
}

func (f mirrorFilters) wants(fields map[string]string) bool {
	return f.name.selected(fields["package"]) &&
		f.version.selected(fields["version"]) &&
		f.architecture.selected(fields["architecture"])
}

// compileFilter anchors the pattern so it matches the whole value. It first
// compiles the raw pattern, because a pattern such as "a)|(b" is invalid alone
// but compiles once wrapped, and would then not anchor.
func compileFilter(flag, pattern string) (*regexp.Regexp, error) {
	_, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid --%s %q: %w", flag, pattern, err)
	}

	return regexp.Compile(fmt.Sprintf("^(?:%s)$", pattern))
}

func (o MirrorOptions) compileFilters() (mirrorFilters, error) {
	var (
		f   mirrorFilters
		err error
	)

	for _, c := range []struct {
		flag, pattern string
		dst           **regexp.Regexp
	}{
		{"filter-name", o.Name, &f.name.include},
		{"filter-name-exclude", o.NameExclude, &f.name.exclude},
		{"filter-version", o.Version, &f.version.include},
		{"filter-version-exclude", o.VersionExclude, &f.version.exclude},
		{"filter-architecture", o.Architecture, &f.architecture.include},
		{"filter-architecture-exclude", o.ArchitectureExclude, &f.architecture.exclude},
	} {
		// An empty pattern means no filter.
		if c.pattern == "" {
			continue
		}

		*c.dst, err = compileFilter(c.flag, c.pattern)
		if err != nil {
			return mirrorFilters{}, err
		}
	}

	return f, nil
}

type MirrorResult struct {
	Added     int
	Replaced  int
	Unchanged int
	Failed    int
}

type releaseFile struct {
	sha256 string
	size   int64
}

type mirrorEntry struct {
	filename string
	size     int64
	sha256   string
	fields   map[string]string
}

// Mirror downloads the packages listed in the source Packages indexes into
// the pool. A package that fails any check is counted and skipped.
func Mirror(ctx context.Context, workdir string, opts MirrorOptions) (MirrorResult, error) {
	err := checkInitialized(workdir, "mirror")
	if err != nil {
		return MirrorResult{}, err
	}

	err = checkNames(opts.TargetSuite, opts.TargetComponent)
	if err != nil {
		return MirrorResult{}, err
	}

	filters, err := opts.compileFilters()
	if err != nil {
		return MirrorResult{}, err
	}

	repo := strings.TrimSuffix(opts.SourceRepo, "/")

	distBase := fmt.Sprintf("%s/dists/%s", repo, opts.SourceSuite)

	entries, err := fetchEntries(ctx, distBase, opts.SourceComponent, opts.SourceKey)
	if err != nil {
		return MirrorResult{}, err
	}

	var res MirrorResult

	for _, e := range entries {
		if !filters.wants(e.fields) {
			continue
		}

		add, replaced, err := mirrorPackage(ctx, workdir, repo, opts, e)
		if err != nil {
			res.Failed++

			slog.ErrorContext(ctx, "mirror failed", "filename", e.filename, "error", err)

			continue
		}

		if !add.Added {
			res.Unchanged++

			continue
		}

		if replaced {
			res.Replaced++

			slog.InfoContext(ctx, "replaced", "path", path.Join("public", add.Path))

			continue
		}

		res.Added++

		slog.InfoContext(ctx, "added", "path", path.Join("public", add.Path))
	}

	if res.Failed > 0 {
		return res, ErrMirrorFailed
	}

	return res, nil
}

func getOK(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}

	// Raw bytes keep the Release hash check valid for .gz and .zst indexes.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()

		return nil, fmt.Errorf("get %s: %s", url, resp.Status)
	}

	return resp, nil
}

func getBytes(ctx context.Context, url string) ([]byte, error) {
	resp, err := getOK(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}

	return data, nil
}

// fetchEntries reads InRelease and, for every supported architecture, the
// Packages index (zst, gz, then plain, the first one Release lists). It
// returns the packages deduplicated by Filename.
func fetchEntries(ctx context.Context, distBase, component string, sourceKey []byte) ([]mirrorEntry, error) {
	body, err := getBytes(ctx, fmt.Sprintf("%s/InRelease", distBase))
	if err != nil {
		return nil, err
	}

	var plaintext []byte

	if len(sourceKey) > 0 {
		plaintext, err = pgpsign.VerifyClear(sourceKey, body)
		if err != nil {
			return nil, fmt.Errorf("verify InRelease: %w", err)
		}
	} else {
		block, _ := clearsign.Decode(body)
		if block == nil {
			return nil, errors.New("InRelease is not clearsigned")
		}

		plaintext = block.Plaintext
	}

	release, err := debfile.ParseControl(strings.TrimRight(string(plaintext), "\n"))
	if err != nil {
		return nil, fmt.Errorf("parse InRelease: %w", err)
	}

	if !slices.Contains(strings.Fields(release.Fields["components"]), component) {
		return nil, fmt.Errorf("source has no component %q", component)
	}

	var archs []string

	listed := strings.Fields(release.Fields["architectures"])
	for _, arch := range debfile.Architectures {
		if slices.Contains(listed, arch) {
			archs = append(archs, arch)
		}
	}

	if len(archs) == 0 {
		return nil, errors.New("source has no supported architecture")
	}

	files, err := parseReleaseHashes(release.Fields["sha256"])
	if err != nil {
		return nil, err
	}

	var entries []mirrorEntry

	seen := map[string]bool{}

	for _, arch := range archs {
		indexPath := fmt.Sprintf("%s/binary-%s/Packages", component, arch)

		found, err := fetchIndex(ctx, distBase, indexPath, files)
		if err != nil {
			return nil, err
		}

		for _, e := range found {
			if !seen[e.filename] {
				seen[e.filename] = true
				entries = append(entries, e)
			}
		}
	}

	return entries, nil
}

func parseReleaseHashes(field string) (map[string]releaseFile, error) {
	files := map[string]releaseFile{}

	for line := range strings.SplitSeq(field, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		if len(parts) != 3 {
			return nil, fmt.Errorf("malformed Release SHA256 line %q", line)
		}

		size, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("malformed Release SHA256 size in %q", line)
		}

		files[parts[2]] = releaseFile{sha256: parts[0], size: size}
	}

	return files, nil
}

func fetchIndex(ctx context.Context, distBase, indexPath string, files map[string]releaseFile) ([]mirrorEntry, error) {
	var (
		suffix string
		want   releaseFile
		ok     bool
	)

	for _, suffix = range []string{".zst", ".gz", ""} {
		want, ok = files[indexPath+suffix]
		if ok {
			break
		}
	}

	if !ok {
		return nil, fmt.Errorf("source Release does not list %s", indexPath)
	}

	indexPath += suffix

	data, err := getBytes(ctx, fmt.Sprintf("%s/%s", distBase, indexPath))
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	if int64(len(data)) != want.size || hex.EncodeToString(sum[:]) != want.sha256 {
		return nil, fmt.Errorf("%s: size or SHA256 mismatch with Release", indexPath)
	}

	text, err := decompressIndex(data, suffix)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", indexPath, err)
	}

	var entries []mirrorEntry

	var paragraph []string

	// Under deb822 any run of empty or whitespace-only lines separates paragraphs.
	for line := range strings.SplitSeq(fmt.Sprintf("%s\n", text), "\n") {
		if strings.Trim(line, " \t") != "" {
			paragraph = append(paragraph, line)

			continue
		}

		if len(paragraph) == 0 {
			continue
		}

		e, err := parseIndexEntry(strings.Join(paragraph, "\n"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", indexPath, err)
		}

		entries = append(entries, e)
		paragraph = nil
	}

	return entries, nil
}

func decompressIndex(data []byte, suffix string) ([]byte, error) {
	switch suffix {
	case ".gz":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()

		return io.ReadAll(zr)
	case ".zst":
		zr, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
		if err != nil {
			return nil, err
		}
		defer zr.Close()

		return io.ReadAll(zr)
	}

	return data, nil
}

func parseIndexEntry(paragraph string) (mirrorEntry, error) {
	control, err := debfile.ParseControl(paragraph)
	if err != nil {
		return mirrorEntry{}, err
	}

	f := control.Fields

	for _, name := range []string{"Filename", "Size", "SHA256"} {
		if f[strings.ToLower(name)] == "" {
			return mirrorEntry{}, fmt.Errorf("package %q lacks %s", f["package"], name)
		}
	}

	size, err := strconv.ParseInt(f["size"], 10, 64)
	if err != nil || size < 0 {
		return mirrorEntry{}, fmt.Errorf("package %q has invalid Size %q", f["package"], f["size"])
	}

	return mirrorEntry{filename: f["filename"], size: size, sha256: f["sha256"], fields: f}, nil
}

// mirrorPackage adds one package. A zero AddResult means the pool already
// holds the same bytes and nothing was requested; replaced reports that a
// differing file was overwritten (only with Force).
func mirrorPackage(ctx context.Context, workdir, repo string, opts MirrorOptions, e mirrorEntry) (AddResult, bool, error) {
	rel, err := poolPath(opts.TargetSuite, opts.TargetComponent, e.fields)
	if err != nil {
		return AddResult{}, false, err
	}

	existing, err := fileSHA256(filepath.Join(workdir, "public", filepath.FromSlash(rel)))
	if err == nil && existing == e.sha256 {
		return AddResult{}, false, nil
	}

	differs := err == nil
	if differs && !opts.Force {
		return AddResult{}, false, fmt.Errorf("mirror %s: %w", rel, ErrConflict)
	}

	cacheDir := filepath.Join(workdir, "cache")

	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return AddResult{}, false, fmt.Errorf("create %s: %w", cacheDir, err)
	}

	tmp, err := os.CreateTemp(cacheDir, ".mirror-*.deb")
	if err != nil {
		return AddResult{}, false, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	err = download(ctx, fmt.Sprintf("%s/%s", repo, e.filename), tmp, e)
	if err != nil {
		return AddResult{}, false, err
	}

	res, err := Add(workdir, opts.TargetSuite, opts.TargetComponent, tmp.Name(), opts.Force)
	if err != nil {
		return AddResult{}, false, err
	}

	return res, differs, nil
}

// download streams url into tmp, closes it, and checks size and SHA256.
func download(ctx context.Context, url string, tmp *os.File, e mirrorEntry) error {
	resp, err := getOK(ctx, url)
	if err != nil {
		tmp.Close()

		return err
	}
	defer resp.Body.Close()

	h := sha256.New()

	n, copyErr := io.Copy(io.MultiWriter(tmp, h), resp.Body)

	err = errors.Join(copyErr, tmp.Close())
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}

	if n != e.size || hex.EncodeToString(h.Sum(nil)) != e.sha256 {
		return fmt.Errorf("download %s: size or SHA256 mismatch with index", url)
	}

	return nil
}

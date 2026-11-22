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
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
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
	if p.include != nil && !matchesWhole(p.include, value) {
		return false
	}

	return p.exclude == nil || !matchesWhole(p.exclude, value)
}

func matchesWhole(re *regexp.Regexp, value string) bool {
	match := re.FindStringIndex(value)

	return match != nil && match[0] == 0 && match[1] == len(value)
}

func (f mirrorFilters) wants(fields map[string]string) bool {
	return f.name.selected(fields["package"]) &&
		f.version.selected(fields["version"]) &&
		f.architecture.selected(fields["architecture"])
}

func compileFilter(flag, pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid --%s %q: %w", flag, pattern, err)
	}

	// Try the longest alternative at the first match position so a shorter
	// alternative cannot hide a match that spans the whole field.
	re.Longest()

	return re, nil
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

	repo, err := url.Parse(opts.SourceRepo)
	if err != nil || repo.Hostname() == "" || (repo.Scheme != "http" && repo.Scheme != "https") || repo.Fragment != "" {
		return MirrorResult{}, errors.New("source repository must be an HTTP or HTTPS base URL")
	}

	if !validRepoPath(opts.SourceSuite) || !validRepoPath(opts.SourceComponent) {
		return MirrorResult{}, errors.New("source suite and component must be relative repository paths")
	}

	distBase := repoPath(repo, fmt.Sprintf("dists/%s", opts.SourceSuite))

	entries, err := fetchEntries(ctx, distBase, opts.SourceComponent, opts.SourceKey)
	if err != nil {
		return MirrorResult{}, err
	}

	var res MirrorResult

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		if !filters.wants(e.fields) {
			continue
		}

		add, err := mirrorPackage(ctx, workdir, repo, opts, e)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}

			res.Failed++

			slog.ErrorContext(ctx, "mirror failed", "filename", e.filename, "error", err)

			continue
		}

		if !add.Added {
			res.Unchanged++

			continue
		}

		if add.Replaced {
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

func validRepoPath(name string) bool {
	return name != "." && fs.ValidPath(name) && !strings.ContainsAny(name, "\\\n\r\t\x00")
}

// repoPath appends name to base without cleaning, because URL.JoinPath would
// collapse "//" in a base path that the upstream expects verbatim.
func repoPath(base *url.URL, name string) *url.URL {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}

	u := *base
	u.Path = fmt.Sprintf("%s/%s", strings.TrimSuffix(base.Path, "/"), name)
	u.RawPath = fmt.Sprintf("%s/%s", strings.TrimSuffix(base.EscapedPath(), "/"), strings.Join(parts, "/"))

	return &u
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

// fetchEntries reads InRelease and the listed Packages indexes for supported
// architectures. It returns the packages deduplicated by Filename.
func fetchEntries(ctx context.Context, distBase *url.URL, component string, sourceKey []byte) ([]mirrorEntry, error) {
	body, err := getBytes(ctx, repoPath(distBase, "InRelease").String())
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

	seen := map[string]mirrorEntry{}

	indexes := 0

	for _, arch := range archs {
		indexPath := fmt.Sprintf("%s/binary-%s/Packages", component, arch)

		found, err := fetchIndex(ctx, distBase, indexPath, files)
		if err != nil {
			return nil, err
		}

		if found == nil {
			continue
		}

		indexes++

		for _, e := range found {
			if previous, ok := seen[e.filename]; ok {
				if previous.size != e.size || previous.sha256 != e.sha256 || checkIndexControl(previous.fields, e.fields) != nil {
					return nil, fmt.Errorf("conflicting index entries for %s", e.filename)
				}

				continue
			}

			seen[e.filename] = e
			entries = append(entries, e)
		}
	}

	if indexes == 0 {
		return nil, fmt.Errorf("source Release does not list a supported Packages index for %s", component)
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

		if !validChecksum(parts[0], sha256.Size*2) {
			return nil, fmt.Errorf("malformed Release SHA256 checksum in %q", line)
		}

		size, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("malformed Release SHA256 size in %q", line)
		}

		entry := releaseFile{sha256: strings.ToLower(parts[0]), size: size}
		if previous, ok := files[parts[2]]; ok && previous != entry {
			return nil, fmt.Errorf("conflicting Release SHA256 entries for %s", parts[2])
		}

		files[parts[2]] = entry
	}

	return files, nil
}

func fetchIndex(ctx context.Context, distBase *url.URL, indexPath string, files map[string]releaseFile) ([]mirrorEntry, error) {
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
		return nil, nil
	}

	indexPath += suffix

	resp, err := getOK(ctx, repoPath(distBase, indexPath).String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data bytes.Buffer

	err = copySized(&data, resp.Body, want.size)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", indexPath, err)
	}

	sum := sha256.Sum256(data.Bytes())
	if hex.EncodeToString(sum[:]) != want.sha256 {
		return nil, fmt.Errorf("%s: SHA256 mismatch with Release", indexPath)
	}

	index, err := decompressIndex(data.Bytes(), suffix)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", indexPath, err)
	}

	return parseIndex(index, indexPath)
}

func parseIndex(text []byte, indexPath string) ([]mirrorEntry, error) {
	entries := []mirrorEntry{}

	var paragraph []string

	// Under deb822 any run of empty or whitespace-only lines separates paragraphs.
	for line := range strings.SplitSeq(fmt.Sprintf("%s\n", text), "\n") {
		line = strings.TrimSuffix(line, "\r")
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

	filename := strings.TrimPrefix(f["filename"], "./")
	if !validRepoPath(filename) {
		return mirrorEntry{}, fmt.Errorf("package %q has invalid Filename %q", f["package"], f["filename"])
	}

	return mirrorEntry{filename: filename, size: size, sha256: strings.ToLower(f["sha256"]), fields: f}, nil
}

func mirrorPackage(ctx context.Context, workdir string, repo *url.URL, opts MirrorOptions, e mirrorEntry) (AddResult, error) {
	rel, err := poolPath(opts.TargetSuite, opts.TargetComponent, e.fields)
	if err != nil {
		return AddResult{}, err
	}

	target := filepath.Join(workdir, "public", filepath.FromSlash(rel))
	existing, size, err := fileSHA256(target)
	if err == nil && existing == e.sha256 {
		if size != e.size {
			return AddResult{}, fmt.Errorf("%s: size mismatch with index", rel)
		}

		if err := checkExistingControl(target, e.fields); err != nil {
			return AddResult{}, fmt.Errorf("%s: %w", rel, err)
		}

		return AddResult{Path: rel}, nil
	}

	if err == nil && !opts.Force {
		return AddResult{}, fmt.Errorf("mirror %s: %w", rel, ErrConflict)
	}

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return AddResult{}, fmt.Errorf("hash %s: %w", target, err)
	}

	cacheDir := filepath.Join(workdir, "cache")

	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return AddResult{}, fmt.Errorf("create %s: %w", cacheDir, err)
	}

	tmp, err := os.CreateTemp(cacheDir, ".mirror-*.deb")
	if err != nil {
		return AddResult{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	err = download(ctx, repoPath(repo, e.filename).String(), tmp, e)
	if err != nil {
		return AddResult{}, err
	}

	return addPackage(workdir, opts.TargetSuite, opts.TargetComponent, tmp.Name(), placementOptions{
		replace:  opts.Force,
		expected: e.fields,
	})
}

func checkExistingControl(target string, expected map[string]string) error {
	f, err := os.Open(target)
	if err != nil {
		return err
	}
	defer f.Close()

	control, err := debfile.Parse(f)
	if err != nil {
		return err
	}

	return checkIndexControl(control.Fields, expected)
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

	copyErr := copySized(io.MultiWriter(tmp, h), resp.Body, e.size)

	err = errors.Join(copyErr, tmp.Close())
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}

	if hex.EncodeToString(h.Sum(nil)) != e.sha256 {
		return fmt.Errorf("download %s: SHA256 mismatch with index", url)
	}

	return nil
}

// copySized limits the write to the declared size and reads one more byte to
// distinguish an exact response from one with trailing data.
func copySized(dst io.Writer, src io.Reader, size int64) error {
	n, err := io.Copy(dst, io.LimitReader(src, size))
	if err != nil {
		return err
	}

	if n != size {
		return fmt.Errorf("size mismatch: got %d bytes, expected %d", n, size)
	}

	var trailing [1]byte

	_, err = io.ReadFull(src, trailing[:])
	if err == nil {
		return fmt.Errorf("size mismatch: response exceeds %d bytes", size)
	}

	if errors.Is(err, io.EOF) {
		return nil
	}

	return err
}

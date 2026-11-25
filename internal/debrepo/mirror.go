package debrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/klauspost/compress/zstd"
	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
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

	// Now is the clock for the Release freshness checks; zero means time.Now().
	Now time.Time

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

	// limits is zero outside tests, which means defaultMirrorLimits.
	limits mirrorLimits
}

const (
	// mirrorStallTimeout cancels a request that receives no data for this long,
	// from connecting through the last body byte.
	mirrorStallTimeout time.Duration = time.Minute
	maxInReleaseSize   int64         = 16 << 20
	// maxIndexSize caps a Packages index both as downloaded and decompressed.
	maxIndexSize int64 = 256 << 20
	// minFreeSpace is what a download must leave free on the workdir filesystem.
	minFreeSpace uint64 = 1 << 30
)

type mirrorLimits struct {
	stall   time.Duration
	release int64
	index   int64
	reserve uint64
}

func defaultMirrorLimits() mirrorLimits {
	return mirrorLimits{stall: mirrorStallTimeout, release: maxInReleaseSize, index: maxIndexSize, reserve: minFreeSpace}
}

// checkFreeSpace fails when a package of size bytes, held twice while it moves
// from cache/ to the pool, would leave less than reserve bytes free in dir.
func checkFreeSpace(dir string, size int64, reserve uint64) error {
	var st syscall.Statfs_t

	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}

	free := st.Bavail * uint64(st.Bsize)
	need := 2 * uint64(size)

	if free < reserve || free-reserve < need {
		return fmt.Errorf("not enough free space: need %d bytes and %d spare, %d free", need, reserve, free)
	}

	return nil
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
	err := repofs.CheckInitialized(workdir, "mirror")
	if err != nil {
		return MirrorResult{}, err
	}

	err = repofs.RefuseMarkers(workdir, "mirror", rpmMarkers, ErrRPMWorkdir)
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

	if opts.limits == (mirrorLimits{}) {
		opts.limits = defaultMirrorLimits()
	}

	repo, err := url.Parse(opts.SourceRepo)
	if err != nil || repo.Hostname() == "" || (repo.Scheme != "http" && repo.Scheme != "https") || repo.Fragment != "" {
		return MirrorResult{}, errors.New("source repository must be an HTTP or HTTPS base URL")
	}

	if !validRepoPath(opts.SourceSuite) || !validRepoPath(opts.SourceComponent) {
		return MirrorResult{}, errors.New("source suite and component must be relative repository paths")
	}

	distBase := repoPath(repo, fmt.Sprintf("dists/%s", opts.SourceSuite))

	entries, date, err := fetchEntries(ctx, workdir, distBase, opts)
	if err != nil {
		return MirrorResult{}, err
	}

	err = saveMirrorState(workdir, mirrorStateKey(opts), date)
	if err != nil {
		return MirrorResult{}, err
	}

	cache, err := repofs.LoadCache[cacheEntry](workdir)
	if err != nil {
		return MirrorResult{}, err
	}

	run := mirrorRun{workdir: workdir, repo: repo, opts: opts, cache: cache}

	var res MirrorResult

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		if !filters.wants(e.fields) {
			continue
		}

		add, err := run.mirrorPackage(ctx, e)
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

// StripUserinfo returns rawURL without its user:password@ part, so the URL can
// be logged, put in an error, or stored without credentials. The username goes
// too, because it can be the token. A URL without userinfo comes back
// unchanged; one that doesn't parse comes back empty.
func StripUserinfo(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	if u.User == nil {
		return rawURL
	}

	u.User = nil

	return u.String()
}

// urlCause drops the *url.Error wrapper, whose text repeats the request URL
// with its username.
func urlCause(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}

	return err
}

// stallBody restarts the stall timer on every read that returns data and
// reports a fired timer as stalled rather than as a canceled context.
type stallBody struct {
	io.ReadCloser
	timer   *time.Timer
	stall   time.Duration
	cause   func() error
	stalled error
	cancel  context.CancelCauseFunc
}

func (b *stallBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.timer.Reset(b.stall)
	}

	if err != nil && errors.Is(b.cause(), b.stalled) {
		err = b.stalled
	}

	return n, err
}

func (b *stallBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel(nil)

	return err
}

// getOK returns the body of a 200 response. The request is canceled once it
// receives no data for stall, so an upstream can't hold the run forever.
func getOK(ctx context.Context, u *url.URL, stall time.Duration) (*http.Response, error) {
	shown := StripUserinfo(u.String())
	stalled := fmt.Errorf("no data for %s", stall)

	ctx, cancel := context.WithCancelCause(ctx)
	timer := time.AfterFunc(stall, func() { cancel(stalled) })

	fail := func(err error) (*http.Response, error) {
		timer.Stop()
		cancel(nil)

		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail(fmt.Errorf("request %s: %w", shown, urlCause(err)))
	}

	// Raw bytes keep the Release hash check valid for .gz and .zst indexes.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(context.Cause(ctx), stalled) {
			err = stalled
		}

		return fail(fmt.Errorf("get %s: %w", shown, urlCause(err)))
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()

		return fail(fmt.Errorf("get %s: %s", shown, resp.Status))
	}

	resp.Body = &stallBody{
		ReadCloser: resp.Body,
		timer:      timer,
		stall:      stall,
		cause:      func() error { return context.Cause(ctx) },
		stalled:    stalled,
		cancel:     cancel,
	}

	return resp, nil
}

// getBytes reads a response of at most limit bytes.
func getBytes(ctx context.Context, u *url.URL, stall time.Duration, limit int64) ([]byte, error) {
	resp, err := getOK(ctx, u, stall)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", StripUserinfo(u.String()), err)
	}

	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path.Base(u.Path), limit)
	}

	return data, nil
}

// fetchEntries reads InRelease and the listed Packages indexes for supported
// architectures. It returns the packages deduplicated by Filename and the
// accepted Release date.
func fetchEntries(ctx context.Context, workdir string, distBase *url.URL, opts MirrorOptions) ([]mirrorEntry, time.Time, error) {
	body, err := getBytes(ctx, repoPath(distBase, "InRelease"), opts.limits.stall, opts.limits.release)
	if err != nil {
		return nil, time.Time{}, err
	}

	var plaintext []byte

	if len(opts.SourceKey) > 0 {
		plaintext, err = pgpsign.VerifyClear(opts.SourceKey, body)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("verify InRelease: %w", err)
		}
	} else {
		block, _ := clearsign.Decode(body)
		if block == nil {
			return nil, time.Time{}, errors.New("InRelease is not clearsigned")
		}

		plaintext = block.Plaintext
	}

	release, err := debfile.ParseControl(strings.TrimRight(string(plaintext), "\n"))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse InRelease: %w", err)
	}

	date, err := checkRelease(workdir, opts, release.Fields)
	if err != nil {
		return nil, time.Time{}, err
	}

	if !slices.Contains(strings.Fields(release.Fields["components"]), opts.SourceComponent) {
		return nil, time.Time{}, fmt.Errorf("source has no component %q", opts.SourceComponent)
	}

	var archs []string

	listed := strings.Fields(release.Fields["architectures"])
	for _, arch := range debfile.Architectures {
		if slices.Contains(listed, arch) {
			archs = append(archs, arch)
		}
	}

	if len(archs) == 0 {
		return nil, time.Time{}, errors.New("source has no supported architecture")
	}

	files, err := parseReleaseHashes(release.Fields["sha256"])
	if err != nil {
		return nil, time.Time{}, err
	}

	var entries []mirrorEntry

	seen := map[string]mirrorEntry{}

	indexes := 0

	for _, arch := range archs {
		indexPath := fmt.Sprintf("%s/binary-%s/Packages", opts.SourceComponent, arch)

		found, err := fetchIndex(ctx, distBase, indexPath, files, opts.limits)
		if err != nil {
			return nil, time.Time{}, err
		}

		if found == nil {
			continue
		}

		indexes++

		for _, e := range found {
			if previous, ok := seen[e.filename]; ok {
				if previous.size != e.size || previous.sha256 != e.sha256 || checkIndexControl(previous.fields, e.fields) != nil {
					return nil, time.Time{}, fmt.Errorf("conflicting index entries for %s", e.filename)
				}

				continue
			}

			seen[e.filename] = e
			entries = append(entries, e)
		}
	}

	if indexes == 0 {
		return nil, time.Time{}, fmt.Errorf("source Release does not list a supported Packages index for %s", opts.SourceComponent)
	}

	return entries, date, nil
}

const releaseClockSkew time.Duration = 5 * time.Minute

// parseReleaseTime reads a Debian Release date, which is RFC 1123 with either a
// zone name or a numeric offset.
func parseReleaseTime(field, value string) (time.Time, error) {
	for _, layout := range []string{"Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"} {
		t, err := time.Parse(layout, value)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("InRelease has an invalid %s %q", field, value)
}

// checkRelease rejects a Release for another suite, a stale or future one, and
// one older than the last accepted. It returns the Release date.
func checkRelease(workdir string, opts MirrorOptions, fields map[string]string) (time.Time, error) {
	if fields["suite"] != opts.SourceSuite {
		if fields["codename"] != opts.SourceSuite {
			return time.Time{}, fmt.Errorf("InRelease is for suite %q and codename %q, not %q", fields["suite"], fields["codename"], opts.SourceSuite)
		}

		// Pockets such as noble-updates share the codename of the release they extend.
		if strings.HasPrefix(fields["suite"], fmt.Sprintf("%s-", opts.SourceSuite)) {
			return time.Time{}, fmt.Errorf("InRelease is for suite %q (codename %q), a pocket of %q", fields["suite"], fields["codename"], opts.SourceSuite)
		}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	if fields["date"] == "" {
		return time.Time{}, errors.New("InRelease has no Date")
	}

	date, err := parseReleaseTime("Date", fields["date"])
	if err != nil {
		return time.Time{}, err
	}

	if date.After(now.Add(releaseClockSkew)) {
		return time.Time{}, fmt.Errorf("InRelease Date %s is in the future", fields["date"])
	}

	if fields["valid-until"] != "" {
		until, err := parseReleaseTime("Valid-Until", fields["valid-until"])
		if err != nil {
			return time.Time{}, err
		}

		if until.Before(now) {
			return time.Time{}, fmt.Errorf("InRelease expired at %s", fields["valid-until"])
		}
	}

	state, err := loadMirrorState(workdir)
	if err != nil {
		return time.Time{}, err
	}

	stored, ok := state[mirrorStateKey(opts)]
	if !ok {
		return date, nil
	}

	last, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date %q in cache/mirror-state.json: %w", stored, err)
	}

	if date.Before(last) {
		return time.Time{}, fmt.Errorf("InRelease Date %s is older than the last accepted %s",
			date.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
	}

	return date, nil
}

func mirrorStateKey(opts MirrorOptions) string {
	return fmt.Sprintf("%s %s", StripUserinfo(opts.SourceRepo), opts.SourceSuite)
}

// loadMirrorState maps a source repository and suite to the last accepted
// Release date. A missing file is empty; a corrupt one is an error so the
// rollback protection is never silently reset.
func loadMirrorState(workdir string) (map[string]string, error) {
	file := filepath.Join(workdir, "cache", "mirror-state.json")

	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}

	var state map[string]string

	err = json.Unmarshal(data, &state)
	if err != nil || state == nil {
		return nil, fmt.Errorf("corrupt %s (%v): delete it to reset the rollback protection", file, err)
	}

	return state, nil
}

// ponytail: concurrent mirror runs on one workdir are not coordinated and can lower the stored date, a lock file is the upgrade path.
func saveMirrorState(workdir, key string, date time.Time) error {
	state, err := loadMirrorState(workdir)
	if err != nil {
		return err
	}

	state[key] = date.UTC().Format(time.RFC3339)

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode mirror state: %w", err)
	}

	return repofs.WriteAtomic(filepath.Join(workdir, "cache", "mirror-state.json"), bytes.NewReader(data), 0o644, nil)
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

func fetchIndex(ctx context.Context, distBase *url.URL, indexPath string, files map[string]releaseFile, limits mirrorLimits) ([]mirrorEntry, error) {
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

	if want.size > limits.index {
		return nil, fmt.Errorf("%s: Release lists %d bytes, over the %d byte limit", indexPath, want.size, limits.index)
	}

	resp, err := getOK(ctx, repoPath(distBase, indexPath), limits.stall)
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

	index, err := decompressIndex(data.Bytes(), suffix, limits.index)
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

// decompressIndex returns the index text, failing once it passes limit bytes.
func decompressIndex(data []byte, suffix string, limit int64) ([]byte, error) {
	var src io.Reader

	switch suffix {
	case ".gz":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()

		src = zr
	case ".zst":
		zr, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
		if err != nil {
			return nil, err
		}
		defer zr.Close()

		src = zr
	default:
		return data, nil
	}

	text, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(text)) > limit {
		return nil, fmt.Errorf("index exceeds %d bytes", limit)
	}

	return text, nil
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

// mirrorRun holds what every package of one mirror run shares. cache is the
// build cache as loaded at the start of the run.
type mirrorRun struct {
	workdir string
	repo    *url.URL
	opts    MirrorOptions
	cache   map[string]cacheEntry
}

// cachedUnchanged reports whether the build cache already vouches for the pool
// file at rel: same size and mtime as on disk, and the SHA256, size, and
// control fields the index lists. The file itself is not read.
func (m mirrorRun) cachedUnchanged(rel, target string, e mirrorEntry) bool {
	entry, ok := m.cache[rel]
	if !ok {
		return false
	}

	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || !entry.matches(info) {
		return false
	}

	return entry.SHA256 == e.sha256 && entry.Size == e.size && checkIndexControl(entry.Fields, e.fields) == nil
}

func (m mirrorRun) mirrorPackage(ctx context.Context, e mirrorEntry) (AddResult, error) {
	workdir, repo, opts := m.workdir, m.repo, m.opts

	rel, err := poolPath(opts.TargetSuite, opts.TargetComponent, e.fields)
	if err != nil {
		return AddResult{}, err
	}

	target := filepath.Join(workdir, "public", filepath.FromSlash(rel))

	// --force exists to repair a damaged pool file, so it always reads the file.
	if !opts.Force && m.cachedUnchanged(rel, target, e) {
		return AddResult{Path: rel}, nil
	}

	existing, size, err := repofs.FileSHA256(target)
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

	err = checkFreeSpace(cacheDir, e.size, opts.limits.reserve)
	if err != nil {
		return AddResult{}, fmt.Errorf("mirror %s: %w", rel, err)
	}

	tmp, err := os.CreateTemp(cacheDir, ".mirror-*.deb")
	if err != nil {
		return AddResult{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	err = download(ctx, repoPath(repo, e.filename), tmp, e, opts.limits.stall)
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

// download streams u into tmp, closes it, and checks size and SHA256.
func download(ctx context.Context, u *url.URL, tmp *os.File, e mirrorEntry, stall time.Duration) error {
	resp, err := getOK(ctx, u, stall)
	if err != nil {
		tmp.Close()

		return err
	}
	defer resp.Body.Close()

	h := sha256.New()

	copyErr := copySized(io.MultiWriter(tmp, h), resp.Body, e.size)

	err = errors.Join(copyErr, tmp.Close())
	if err != nil {
		return fmt.Errorf("download %s: %w", StripUserinfo(u.String()), err)
	}

	if hex.EncodeToString(h.Sum(nil)) != e.sha256 {
		return fmt.Errorf("download %s: SHA256 mismatch with index", StripUserinfo(u.String()))
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

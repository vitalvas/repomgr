package debrepo

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"go.vitalvas.com/repomgr/internal/debfile"
	"go.vitalvas.com/repomgr/internal/pgpsign"
)

const indexVariants int = 3

type SuiteSummary struct {
	Suite         string
	Packages      int
	Architectures []string
}

type indexKey struct {
	suite     string
	component string
	arch      string
}

type indexEntry struct {
	name     string
	filename string
	stanza   string
}

type releaseLine struct {
	md5    string
	sha1   string
	sha256 string
	size   int
	path   string
}

type suiteInfo struct {
	packages   int
	archs      map[string]bool
	components map[string]bool
	files      []releaseLine
}

type sumSeen struct {
	sha256   string
	filename string
}

type outputFile struct {
	path string
	data []byte
}

func Build(ctx context.Context, workdir string, now time.Time) ([]SuiteSummary, error) {
	configPath := filepath.Join(workdir, "config", "repo.yaml")

	_, err := os.Stat(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("build %s: %w", workdir, ErrNotInitialized)
	}

	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", configPath, err)
	}

	cfg, err := loadRepoConfig(configPath)
	if err != nil {
		return nil, err
	}

	keyPath := filepath.Join(workdir, "config", "signing.asc")

	privateKey, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("build %s: %w", workdir, ErrNotInitialized)
	}

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyPath, err)
	}

	publicKey, err := pgpsign.PublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key from %s: %w", keyPath, err)
	}

	publicFiles, err := publicKeyFiles(workdir, publicKey)
	if err != nil {
		return nil, err
	}

	rejected, err := processUploads(ctx, workdir)
	if err != nil {
		return nil, err
	}

	public := filepath.Join(workdir, "public")

	cache, err := loadCache(workdir)
	if err != nil {
		return nil, err
	}

	indexes, fresh, err := scanPool(ctx, workdir, cache)
	if err != nil {
		return nil, err
	}

	err = saveCache(workdir, fresh)
	if err != nil {
		return nil, err
	}

	for _, name := range slices.Sorted(maps.Keys(cache)) {
		_, ok := fresh[name]
		if !ok {
			slog.InfoContext(ctx, "cache dropped", "path", path.Join("public", name))
		}
	}

	suites := make(map[string]*suiteInfo)

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, fmt.Errorf("create zstd encoder: %w", err)
	}

	defer encoder.Close()

	var (
		byHashFiles  []outputFile
		packageFiles []outputFile
	)

	for _, key := range slices.SortedFunc(maps.Keys(indexes), compareKeys) {
		info := suites[key.suite]
		if info == nil {
			info = &suiteInfo{archs: map[string]bool{}, components: map[string]bool{}}
			suites[key.suite] = info
		}

		rel := path.Join(key.component, fmt.Sprintf("binary-%s", key.arch), "Packages")
		data := renderPackages(indexes[key])

		info.packages += len(indexes[key])
		info.archs[key.arch] = true
		info.components[key.component] = true

		gz, err := gzipBytes(data)
		if err != nil {
			return nil, fmt.Errorf("compress %s: %w", rel, err)
		}

		indexFiles := []outputFile{
			{path: rel, data: data},
			{path: fmt.Sprintf("%s.gz", rel), data: gz},
			{path: fmt.Sprintf("%s.zst", rel), data: encoder.EncodeAll(data, nil)},
		}

		record := func(v outputFile) releaseLine {
			md5Sum := md5.Sum(v.data)
			sha1Sum := sha1.Sum(v.data)
			sha256Sum := sha256.Sum256(v.data)

			line := releaseLine{
				md5:    hex.EncodeToString(md5Sum[:]),
				sha1:   hex.EncodeToString(sha1Sum[:]),
				sha256: hex.EncodeToString(sha256Sum[:]),
				size:   len(v.data),
				path:   v.path,
			}

			info.files = append(info.files, line)

			packageFiles = append(packageFiles, outputFile{
				path: filepath.Join(public, "dists", key.suite, filepath.FromSlash(v.path)),
				data: v.data,
			})

			return line
		}

		for _, v := range indexFiles {
			line := record(v)
			hashDir := filepath.Join(public, "dists", key.suite, filepath.FromSlash(path.Dir(v.path)), "by-hash")

			byHashFiles = append(byHashFiles,
				outputFile{path: filepath.Join(hashDir, "MD5Sum", line.md5), data: v.data},
				outputFile{path: filepath.Join(hashDir, "SHA1", line.sha1), data: v.data},
				outputFile{path: filepath.Join(hashDir, "SHA256", line.sha256), data: v.data},
			)
		}

		record(outputFile{path: path.Join(path.Dir(rel), "Release"), data: renderArchRelease(key, cfg)})
	}

	var (
		summaries  []SuiteSummary
		suiteFiles []outputFile
	)

	for _, suite := range slices.Sorted(maps.Keys(suites)) {
		info := suites[suite]
		release := renderRelease(suite, cfg, info, now)

		signed, err := pgpsign.Sign(privateKey, release)
		if err != nil {
			return nil, fmt.Errorf("sign release for suite %s: %w", suite, err)
		}

		dir := filepath.Join(public, "dists", suite)

		suiteFiles = append(suiteFiles,
			outputFile{path: filepath.Join(dir, "Release"), data: release},
			outputFile{path: filepath.Join(dir, "Release.gpg"), data: signed.Detached},
			outputFile{path: filepath.Join(dir, "InRelease"), data: signed.Clear},
		)

		summaries = append(summaries, SuiteSummary{
			Suite:         suite,
			Packages:      info.packages,
			Architectures: slices.Sorted(maps.Keys(info.archs)),
		})
	}

	if err := publishFiles(ctx, workdir, publicFiles, "created"); err != nil {
		return nil, err
	}

	if err := publishFiles(ctx, workdir, byHashFiles, "added by-hash"); err != nil {
		return nil, err
	}

	if err := publishFiles(ctx, workdir, packageFiles, "updated"); err != nil {
		return nil, err
	}

	if err := publishFiles(ctx, workdir, suiteFiles, "updated"); err != nil {
		return nil, err
	}

	err = pruneByHash(ctx, workdir, byHashFiles, now)
	if err != nil {
		return nil, err
	}

	err = removeStale(ctx, workdir, indexes)
	if err != nil {
		return nil, err
	}

	switch rejected {
	case 0:
		return summaries, nil
	case 1:
		return summaries, fmt.Errorf("1 upload rejected: %w", ErrUploadRejected)
	default:
		return summaries, fmt.Errorf("%d uploads rejected: %w", rejected, ErrUploadRejected)
	}
}

func publishFiles(ctx context.Context, workdir string, files []outputFile, createdMessage string) error {
	for _, f := range files {
		current, err := os.ReadFile(f.path)
		if err == nil && bytes.Equal(current, f.data) {
			continue
		}

		message := "updated"
		if errors.Is(err, os.ErrNotExist) {
			message = createdMessage
		} else if err != nil {
			return fmt.Errorf("read %s: %w", f.path, err)
		}

		if err := writeAtomic(f.path, bytes.NewReader(f.data), 0o644, nil); err != nil {
			return err
		}

		slog.InfoContext(ctx, message, "path", logPath(workdir, f.path))
	}

	return nil
}

// pruneByHash keeps the current by-hash files plus the two previous versions
// of each index (indexVariants files per version) in every by-hash directory.
func pruneByHash(ctx context.Context, workdir string, current []outputFile, now time.Time) error {
	referenced := make(map[string]bool, len(current))
	dirs := make(map[string]bool)

	for _, f := range current {
		err := os.Chtimes(f.path, now, now)
		if err != nil {
			return fmt.Errorf("touch %s: %w", f.path, err)
		}

		referenced[f.path] = true
		dirs[filepath.Dir(f.path)] = true
	}

	type unreferenced struct {
		path  string
		mtime time.Time
	}

	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read %s: %w", dir, err)
		}

		var files []unreferenced

		for _, e := range entries {
			file := filepath.Join(dir, e.Name())
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") || referenced[file] {
				continue
			}

			info, err := e.Info()
			if err != nil {
				return fmt.Errorf("stat %s: %w", file, err)
			}

			files = append(files, unreferenced{path: file, mtime: info.ModTime()})
		}

		slices.SortFunc(files, func(a, b unreferenced) int {
			return cmp.Or(b.mtime.Compare(a.mtime), strings.Compare(a.path, b.path))
		})

		for _, u := range files[min(len(files), 2*indexVariants):] {
			err = os.Remove(u.path)
			if err != nil {
				return fmt.Errorf("remove %s: %w", u.path, err)
			}

			slog.InfoContext(ctx, "removed by-hash", "path", logPath(workdir, u.path))
		}
	}

	return nil
}

// removeStale deletes suite, component and binary-arch directories under
// dists that have no packages in this build.
func removeStale(ctx context.Context, workdir string, indexes map[indexKey][]indexEntry) error {
	public := filepath.Join(workdir, "public")
	keep := make(map[string]bool)

	for key := range indexes {
		suite := filepath.Join(public, "dists", key.suite)
		component := filepath.Join(suite, key.component)

		keep[suite] = true
		keep[component] = true
		keep[filepath.Join(component, fmt.Sprintf("binary-%s", key.arch))] = true
	}

	return sweep(ctx, workdir, filepath.Join(public, "dists"), 0, keep)
}

func sweep(ctx context.Context, workdir, dir string, depth int, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		if depth == 2 && !strings.HasPrefix(e.Name(), "binary-") {
			continue
		}

		sub := filepath.Join(dir, e.Name())

		if !keep[sub] {
			err = os.RemoveAll(sub)
			if err != nil {
				return fmt.Errorf("remove %s: %w", sub, err)
			}

			slog.InfoContext(ctx, "removed stale", "path", logPath(workdir, sub))

			continue
		}

		if depth < 2 {
			err = sweep(ctx, workdir, sub, depth+1, keep)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func logPath(workdir, file string) string {
	rel, err := filepath.Rel(workdir, file)
	if err != nil {
		return filepath.ToSlash(file)
	}

	return filepath.ToSlash(rel)
}

func compareKeys(a, b indexKey) int {
	return strings.Compare(fmt.Sprintf("%s/%s/%s", a.suite, a.component, a.arch), fmt.Sprintf("%s/%s/%s", b.suite, b.component, b.arch))
}

func scanPool(ctx context.Context, workdir string, cache map[string]cacheEntry) (map[indexKey][]indexEntry, map[string]cacheEntry, error) {
	pool := filepath.Join(workdir, "public", "pool")
	indexes := make(map[indexKey][]indexEntry)
	fresh := make(map[string]cacheEntry)
	seenSums := make(map[string]sumSeen)

	err := walkPool(pool, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(file, ".deb") {
			return nil
		}

		if !d.Type().IsRegular() {
			return fmt.Errorf("build %s: %w: package is not a regular file", file, ErrMisplaced)
		}

		rel, err := filepath.Rel(pool, file)
		if err != nil {
			return err
		}

		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 5 {
			return fmt.Errorf("build %s: %w", file, ErrMisplaced)
		}

		err = checkNames(parts[0], parts[1])
		if err != nil {
			return fmt.Errorf("build %s: %w: %w", file, ErrMisplaced, err)
		}

		filename := path.Join("pool", filepath.ToSlash(rel))

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", file, err)
		}

		entry, ok := cache[filename]
		if !ok || !entry.matches(info) {
			opened, err := debfile.Open(file)
			if err != nil {
				return fmt.Errorf("build %s: %w", file, err)
			}

			entry = newCacheEntry(info, opened)

			slog.InfoContext(ctx, "parsed", "path", path.Join("public", filename))
		}

		fresh[filename] = entry
		pkg := entry.pkg()

		want, err := poolPath(parts[0], parts[1], pkg.Control.Fields)
		if err != nil {
			return fmt.Errorf("build %s: %w: %w", file, ErrMisplaced, err)
		}

		if want != filename {
			return fmt.Errorf("build %s: %w, want %s", filename, ErrMisplaced, want)
		}

		base := path.Base(filename)

		seen, ok := seenSums[base]
		if ok && seen.sha256 != pkg.SHA256 {
			return fmt.Errorf("build: %s and %s differ: %w", seen.filename, filename, ErrConflict)
		}

		seenSums[base] = sumSeen{sha256: pkg.SHA256, filename: filename}

		key := indexKey{suite: parts[0], component: parts[1], arch: pkg.Control.Fields["Architecture"]}

		indexes[key] = append(indexes[key], indexEntry{
			name:     pkg.Control.Fields["Package"],
			filename: filename,
			stanza:   stanza(pkg.Control.Raw, filename, pkg),
		})

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", pool, err)
	}

	return indexes, fresh, nil
}

func walkPool(pool string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(pool)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("stat %s: %w", pool, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("pool %s is not a directory", pool)
	}

	return filepath.WalkDir(pool, visit)
}

func stanza(raw, filename string, pkg debfile.Package) string {
	var lines []string
	var packageLine string
	skipField := false

	for line := range strings.SplitSeq(raw, "\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			if !skipField {
				lines = append(lines, line)
			}

			continue
		}

		name, _, _ := strings.Cut(line, ":")
		skipField = false

		switch strings.ToLower(name) {
		case "package":
			packageLine = line
		case "filename", "size", "md5sum", "sha1", "sha256":
			skipField = true
		default:
			lines = append(lines, line)
		}
	}

	if packageLine != "" {
		lines = slices.Insert(lines, 0, packageLine)
	}

	lines = append(lines,
		fmt.Sprintf("Filename: %s", filename),
		fmt.Sprintf("Size: %d", pkg.Size),
		fmt.Sprintf("MD5sum: %s", pkg.MD5),
		fmt.Sprintf("SHA1: %s", pkg.SHA1),
		fmt.Sprintf("SHA256: %s", pkg.SHA256),
	)

	return strings.Join(lines, "\n")
}

func renderPackages(entries []indexEntry) []byte {
	slices.SortFunc(entries, func(a, b indexEntry) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}

		return strings.Compare(a.filename, b.filename)
	})

	stanzas := make([]string, len(entries))
	for i, e := range entries {
		stanzas[i] = e.stanza
	}

	return []byte(fmt.Sprintf("%s\n", strings.Join(stanzas, "\n\n")))
}

func renderArchRelease(key indexKey, cfg repoConfig) []byte {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Archive: %s\n", cfg.suiteName(key.suite))

	if cfg.Origin != "" {
		fmt.Fprintf(&sb, "Origin: %s\n", cfg.Origin)
	}

	if cfg.Label != "" {
		fmt.Fprintf(&sb, "Label: %s\n", cfg.Label)
	}

	fmt.Fprintf(&sb, "Acquire-By-Hash: yes\nComponent: %s\nArchitecture: %s\n", key.component, key.arch)

	return []byte(sb.String())
}

func renderRelease(suite string, cfg repoConfig, info *suiteInfo, now time.Time) []byte {
	slices.SortFunc(info.files, func(a, b releaseLine) int {
		return strings.Compare(a.path, b.path)
	})

	var sb strings.Builder

	writeField := func(name, value string) {
		if value != "" {
			fmt.Fprintf(&sb, "%s: %s\n", name, value)
		}
	}

	sc := cfg.Suites[suite]

	writeField("Origin", cfg.Origin)
	writeField("Label", cfg.Label)
	writeField("Suite", cfg.suiteName(suite))
	writeField("Version", sc.Version)
	writeField("Codename", suite)
	writeField("Date", now.UTC().Format(time.RFC1123))
	writeField("Acquire-By-Hash", "yes")
	writeField("Architectures", strings.Join(slices.Sorted(maps.Keys(info.archs)), " "))
	writeField("Components", strings.Join(slices.Sorted(maps.Keys(info.components)), " "))
	writeField("Description", cfg.Description)

	lists := []struct {
		name string
		hash func(releaseLine) string
	}{
		{"MD5Sum", func(l releaseLine) string { return l.md5 }},
		{"SHA1", func(l releaseLine) string { return l.sha1 }},
		{"SHA256", func(l releaseLine) string { return l.sha256 }},
	}

	for _, list := range lists {
		fmt.Fprintf(&sb, "%s:\n", list.name)

		for _, line := range info.files {
			fmt.Fprintf(&sb, " %s %d %s\n", list.hash(line), line.size, line.path)
		}
	}

	return []byte(sb.String())
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// writeAtomic writes r to target through a temp file and a rename. A non-nil
// verify runs after the data is written and before the rename; a failure
// removes the temp file and leaves target untouched.
func writeAtomic(target string, r io.Reader, mode fs.FileMode, verify func() error) error {
	dir := filepath.Dir(target)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".build-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}

	_, err = io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())

		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}

	err = tmp.Close()

	if err == nil && verify != nil {
		err = verify()
	}

	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}

	if err == nil {
		err = os.Rename(tmp.Name(), target)
	}

	if err != nil {
		os.Remove(tmp.Name())

		return fmt.Errorf("write %s: %w", target, err)
	}

	return nil
}

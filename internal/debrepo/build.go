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
	"go.vitalvas.com/repomgr/internal/repofs"
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
	err := repofs.RefuseMarkers(workdir, "build", rpmMarkers, ErrRPMWorkdir)
	if err != nil {
		return nil, err
	}

	cfg, err := loadRepoConfig(filepath.Join(workdir, "config", "repo.yaml"))
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

	rejected, err := repofs.ProcessUploads(ctx, workdir, repofs.Upload{
		Ext:    ".deb",
		Layout: "upload/<suite>/<component>/<file>.deb",
		Add: func(suite, component, file string) (repofs.UploadResult, error) {
			res, err := Add(workdir, suite, component, file, false)
			if err != nil {
				return repofs.UploadResult{}, err
			}

			return repofs.UploadResult{Path: res.Path, Added: res.Added}, nil
		},
	})
	if err != nil {
		return nil, err
	}

	public := filepath.Join(workdir, "public")

	cache, err := repofs.LoadCache[cacheEntry](workdir)
	if err != nil {
		return nil, err
	}

	indexes, fresh, err := scanPool(ctx, workdir, cache)
	if err != nil {
		return nil, err
	}

	err = repofs.SaveCache(workdir, fresh)
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
		dir := filepath.Join(public, "dists", suite)

		summary := SuiteSummary{
			Suite:         suite,
			Packages:      info.packages,
			Architectures: slices.Sorted(maps.Keys(info.archs)),
		}

		if releaseCurrent(dir, release, publicKey) {
			summaries = append(summaries, summary)

			continue
		}

		signed, err := pgpsign.Sign(privateKey, release)
		if err != nil {
			return nil, fmt.Errorf("sign release for suite %s: %w", suite, err)
		}

		suiteFiles = append(suiteFiles,
			outputFile{path: filepath.Join(dir, "Release"), data: release},
			outputFile{path: filepath.Join(dir, "Release.gpg"), data: signed.Detached},
			outputFile{path: filepath.Join(dir, "InRelease"), data: signed.Clear},
		)

		summaries = append(summaries, summary)
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

		if err := repofs.WriteAtomic(f.path, bytes.NewReader(f.data), 0o644, nil); err != nil {
			return err
		}

		slog.InfoContext(ctx, message, "path", repofs.LogPath(workdir, f.path))
	}

	return nil
}

// pruneByHash keeps the current by-hash files plus the two previous versions
// of each index (indexVariants files per version) in every by-hash directory.
// Retention ranks files by mtime, so a current file older than an unreferenced
// one (an index reverted to earlier content) is touched to rank first again.
// Current files are not touched otherwise, so mtime-based syncs skip them.
func pruneByHash(ctx context.Context, workdir string, current []outputFile, now time.Time) error {
	referenced := make(map[string]bool, len(current))
	dirs := make(map[string][]string)

	for _, f := range current {
		referenced[f.path] = true
		dir := filepath.Dir(f.path)
		dirs[dir] = append(dirs[dir], f.path)
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

		for _, file := range dirs[dir] {
			info, err := os.Stat(file)
			if err != nil {
				return fmt.Errorf("stat %s: %w", file, err)
			}

			if len(files) > 0 && files[0].mtime.After(info.ModTime()) {
				err = os.Chtimes(file, now, now)
				if err != nil {
					return fmt.Errorf("touch %s: %w", file, err)
				}
			}
		}

		for _, u := range files[min(len(files), 2*indexVariants):] {
			err = os.Remove(u.path)
			if err != nil {
				return fmt.Errorf("remove %s: %w", u.path, err)
			}

			slog.InfoContext(ctx, "removed by-hash", "path", repofs.LogPath(workdir, u.path))
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

			slog.InfoContext(ctx, "removed stale", "path", repofs.LogPath(workdir, sub))

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

func compareKeys(a, b indexKey) int {
	return strings.Compare(fmt.Sprintf("%s/%s/%s", a.suite, a.component, a.arch), fmt.Sprintf("%s/%s/%s", b.suite, b.component, b.arch))
}

func scanPool(ctx context.Context, workdir string, cache map[string]cacheEntry) (map[indexKey][]indexEntry, map[string]cacheEntry, error) {
	pool := filepath.Join(workdir, "public", "pool")
	indexes := make(map[indexKey][]indexEntry)
	fresh := make(map[string]cacheEntry)
	seenSums := make(map[string]sumSeen)

	err := repofs.WalkPool(pool, func(file string, d fs.DirEntry, err error) error {
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
		if len(parts) != 6 {
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

		key := indexKey{suite: parts[0], component: parts[1], arch: pkg.Control.Fields["architecture"]}

		indexes[key] = append(indexes[key], indexEntry{
			name:     pkg.Control.Fields["package"],
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

	fallback := fmt.Sprintf(". %s", key.suite)

	fmt.Fprintf(&sb, "Archive: %s\n", cfg.suiteName(key.suite))
	fmt.Fprintf(&sb, "Origin: %s\n", cmp.Or(cfg.Origin, fallback))
	fmt.Fprintf(&sb, "Label: %s\n", cmp.Or(cfg.Label, fallback))
	fmt.Fprintf(&sb, "Acquire-By-Hash: yes\nComponent: %s\nArchitecture: %s\n", key.component, key.arch)

	return []byte(sb.String())
}

// releaseCurrent reports whether the published suite files can stay as they
// are: the published Release differs from release only in its Date line, and
// Release.gpg and InRelease still verify for it with publicKey. Keeping them
// stops a no-op build from changing files a CDN would have to purge.
func releaseCurrent(dir string, release, publicKey []byte) bool {
	current, err := os.ReadFile(filepath.Join(dir, "Release"))
	if err != nil || !bytes.Equal(withoutDate(current), withoutDate(release)) {
		return false
	}

	detached, err := os.ReadFile(filepath.Join(dir, "Release.gpg"))
	if err != nil {
		return false
	}

	inRelease, err := os.ReadFile(filepath.Join(dir, "InRelease"))
	if err != nil {
		return false
	}

	return pgpsign.Verify(publicKey, current, pgpsign.Signed{Clear: inRelease, Detached: detached}) == nil
}

func withoutDate(release []byte) []byte {
	lines := bytes.SplitAfter(release, []byte("\n"))
	lines = slices.DeleteFunc(lines, func(line []byte) bool { return bytes.HasPrefix(line, []byte("Date: ")) })

	return bytes.Join(lines, nil)
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
	fallback := fmt.Sprintf(". %s", suite)

	writeField("Origin", cmp.Or(cfg.Origin, fallback))
	writeField("Label", cmp.Or(cfg.Label, fallback))
	writeField("Suite", cfg.suiteName(suite))
	writeField("Version", sc.Version)
	writeField("Codename", suite)
	writeField("Date", now.UTC().Format(time.RFC1123))
	writeField("Acquire-By-Hash", "yes")
	writeField("Architectures", strings.Join(slices.Sorted(maps.Keys(info.archs)), " "))
	writeField("Components", strings.Join(slices.Sorted(maps.Keys(info.components)), " "))
	writeField("Description", cmp.Or(cfg.Description, "Generated by repomgr"))

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

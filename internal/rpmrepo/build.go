package rpmrepo

import (
	"bytes"
	"cmp"
	"context"
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

	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

var (
	ErrMisplaced = errors.New("package not at its pool path")

	// baseArches is sorted, so Summary.Arches comes out sorted.
	baseArches = []string{"aarch64", "x86_64"}
)

type Summary struct {
	Release, Component string
	Packages           int
	Arches             []string
}

type repoKey struct {
	release   string
	component string
}

func Build(ctx context.Context, workdir string, now time.Time) ([]Summary, error) {
	err := repofs.CheckInitialized(workdir, "build")
	if err != nil {
		return nil, err
	}

	err = repofs.RefuseMarkers(workdir, "build", debMarkers, ErrDebWorkdir)
	if err != nil {
		return nil, err
	}

	err = makeArchDirs(workdir)
	if err != nil {
		return nil, err
	}

	sk, err := loadSigningKeys(workdir)
	if err != nil {
		return nil, err
	}

	privateKey := sk.private
	publicKey := sk.public
	armored := sk.armored

	rejected, err := processUploads(ctx, workdir)
	if err != nil {
		return nil, err
	}

	cache, err := repofs.LoadCache[cacheEntry](workdir)
	if err != nil {
		return nil, err
	}

	groups, fresh, err := scanPool(ctx, workdir, cache)
	if err != nil {
		return nil, err
	}

	if !maps.EqualFunc(cache, fresh, cacheEntry.equal) {
		if err := repofs.SaveCache(workdir, fresh); err != nil {
			return nil, err
		}
	}

	for _, name := range slices.Sorted(maps.Keys(cache)) {
		_, ok := fresh[name]
		if !ok {
			slog.InfoContext(ctx, "cache dropped", "path", path.Join("public", name))
		}
	}

	var (
		summaries []Summary
		writes    []outputFile
		pairs     [][]outputFile
		prunes    []pruneTarget
		keep      = make(map[string]bool)
	)

	keys := slices.SortedFunc(maps.Keys(groups), func(a, b repoKey) int {
		return cmp.Or(strings.Compare(a.release, b.release), strings.Compare(a.component, b.component))
	})

	for _, key := range keys {
		pkgs := groups[key]
		slices.SortFunc(pkgs, func(a, b repoPackage) int {
			return cmp.Or(strings.Compare(a.pkg.Name, b.pkg.Name), strings.Compare(a.pkg.Arch, b.pkg.Arch), strings.Compare(a.path, b.path))
		})

		summary := Summary{Release: key.release, Component: key.component, Packages: len(pkgs)}

		for _, arch := range baseArches {
			repo := slices.DeleteFunc(slices.Clone(pkgs), func(p repoPackage) bool {
				return p.pkg.Arch != arch && p.pkg.Arch != "noarch"
			})
			if len(repo) == 0 {
				continue
			}

			md, files, err := renderRepo(repo, privateKey, now)
			if err != nil {
				return nil, fmt.Errorf("build %s/%s/%s: %w", arch, key.release, key.component, err)
			}

			summary.Arches = append(summary.Arches, arch)

			repoPath := filepath.Join("public", arch, key.release, key.component)
			if err := checkDirs(workdir, filepath.Join(repoPath, "repodata")); err != nil {
				return nil, err
			}

			repoDir := filepath.Join(workdir, repoPath)
			keep[filepath.Dir(repoDir)] = true
			keep[repoDir] = true

			if published, ok := repoCurrent(repoDir, md, publicKey); ok {
				prunes = append(prunes, pruneTarget{workdir: workdir, repoDir: repoDir, referenced: published})

				continue
			}

			prunes = append(prunes, pruneTarget{workdir: workdir, repoDir: repoDir, referenced: md})

			for i := range files {
				files[i].name = filepath.Join(repoDir, "repodata", files[i].name)
			}

			// The last two files are repomd.xml.asc and repomd.xml, which are
			// published together.
			writes = append(writes, files[:len(files)-2]...)
			pairs = append(pairs, files[len(files)-2:])
		}

		summaries = append(summaries, summary)
	}

	err = restoreKey(ctx, workdir, armored)
	if err != nil {
		return nil, err
	}

	for _, f := range writes {
		// Metadata files are content-addressed: skip one that is already there as
		// a regular file with the same bytes.
		if f.msg == msgAdded && isRegularWith(f.name, hexSHA256(f.data)) {
			continue
		}

		err = repofs.WriteAtomic(f.name, bytes.NewReader(f.data), 0o644, nil)
		if err != nil {
			return nil, err
		}

		slog.InfoContext(ctx, f.msg, "path", repofs.LogPath(workdir, f.name))
	}

	for _, pair := range pairs {
		err = publishPair(ctx, workdir, pair)
		if err != nil {
			return nil, err
		}
	}

	for _, p := range prunes {
		err = pruneRepodata(ctx, p, now)
		if err != nil {
			return nil, err
		}
	}

	err = removeStale(ctx, workdir, keep)
	if err != nil {
		return nil, err
	}

	return summaries, rejectedError(rejected)
}

type signingKeys struct {
	private []byte
	public  []byte
	armored []byte
}

func loadSigningKeys(workdir string) (signingKeys, error) {
	keyPath := filepath.Join(workdir, "config", "signing.asc")

	private, err := os.ReadFile(keyPath)
	if err != nil {
		return signingKeys{}, fmt.Errorf("read %s: %w", keyPath, err)
	}

	public, err := pgpsign.PublicKey(private)
	if err != nil {
		return signingKeys{}, fmt.Errorf("derive public key from %s: %w", keyPath, err)
	}

	armored, err := pgpsign.ArmorPublicKey(public)
	if err != nil {
		return signingKeys{}, fmt.Errorf("armor public key from %s: %w", keyPath, err)
	}

	return signingKeys{private: private, public: public, armored: armored}, nil
}

// publishPair writes repomd.xml.asc and repomd.xml, in that order, to temporary
// files first and renames them only when both are complete. If the second
// rename fails, it restores the previous signature.
func publishPair(ctx context.Context, workdir string, pair []outputFile) error {
	tmps := make([]string, 0, len(pair))

	defer func() {
		for _, tmp := range tmps {
			os.Remove(tmp)
		}
	}()

	for _, f := range pair {
		info, err := os.Lstat(f.name)
		switch {
		case err == nil && info.IsDir():
			return fmt.Errorf("write %s: destination is a directory", f.name)
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("stat %s: %w", f.name, err)
		}

		tmp, err := stageOutput(f.name, f.data)
		if err != nil {
			return err
		}

		tmps = append(tmps, tmp)
	}

	sig, md := pair[0].name, pair[1].name
	backup, err := stageSignatureBackup(sig)
	if err != nil {
		return err
	}

	defer func() {
		if backup != "" {
			os.Remove(backup)
		}
	}()

	if err := os.Rename(tmps[0], sig); err != nil {
		return fmt.Errorf("write %s: %w", sig, err)
	}

	if err := os.Rename(tmps[1], md); err != nil {
		err = fmt.Errorf("write %s: %w", md, err)
		var restoreErr error
		if backup == "" {
			restoreErr = os.Remove(sig)
		} else {
			restoreErr = os.Rename(backup, sig)
		}

		if restoreErr != nil {
			if backup != "" {
				err = errors.Join(err, fmt.Errorf("previous signature retained at %s", backup))
				backup = ""
			}
			return errors.Join(err, fmt.Errorf("restore %s: %w", sig, restoreErr))
		}
		return err
	}

	for _, f := range pair {
		slog.InfoContext(ctx, f.msg, "path", repofs.LogPath(workdir, f.name))
	}

	return nil
}

func stageSignatureBackup(sig string) (string, error) {
	current, err := readRegular(sig)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errNotRegular):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read %s: %w", sig, err)
	}

	return stageOutput(sig, current)
}

func stageOutput(target string, data []byte) (string, error) {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".build-*")
	if err != nil {
		return "", fmt.Errorf("create temp in %s: %w", dir, err)
	}

	_, writeErr := tmp.Write(data)
	err = errors.Join(writeErr, tmp.Chmod(0o644), tmp.Close())
	if err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("write %s: %w", target, err)
	}

	return tmp.Name(), nil
}

// restoreKey writes public/key.asc when it is missing or differs from armored.
func restoreKey(ctx context.Context, workdir string, armored []byte) error {
	keyPath := filepath.Join(workdir, "public", "key.asc")
	msg := msgUpdated

	current, err := readRegular(keyPath)

	switch {
	case err == nil && bytes.Equal(current, armored):
		return nil
	case errors.Is(err, fs.ErrNotExist):
		msg = msgCreated
	case err != nil && !errors.Is(err, errNotRegular):
		return fmt.Errorf("read %s: %w", keyPath, err)
	}

	err = repofs.WriteAtomic(keyPath, bytes.NewReader(armored), 0o644, nil)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, msg, "path", repofs.LogPath(workdir, keyPath))

	return nil
}

// scanner reads pool files, reusing matching cache entries and recording the
// entry of every file it reads in fresh.
type scanner struct {
	ctx    context.Context
	public string
	cache  map[string]cacheEntry
	fresh  map[string]cacheEntry
}

func scanPool(ctx context.Context, workdir string, cache map[string]cacheEntry) (map[repoKey][]repoPackage, map[string]cacheEntry, error) {
	public := filepath.Join(workdir, "public")
	pool := filepath.Join(public, "pool")
	groups := make(map[repoKey][]repoPackage)
	seen := make(map[string]repoPackage)
	s := scanner{ctx: ctx, public: public, cache: cache, fresh: make(map[string]cacheEntry)}

	err := repofs.WalkPool(pool, func(file string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		if !d.Type().IsRegular() {
			return fmt.Errorf("build %s: not a regular file", file)
		}

		if !strings.HasSuffix(file, ".rpm") {
			return nil
		}

		p, key, err := s.readPoolFile(file)
		if err != nil {
			return err
		}

		base := path.Base(p.path)

		first, ok := seen[base]
		if ok && first.pkg.SHA256 != p.pkg.SHA256 {
			return fmt.Errorf("build: %s and %s differ: %w", first.path, p.path, repofs.ErrConflict)
		}

		seen[base] = p
		groups[key] = append(groups[key], p)

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", pool, err)
	}

	return groups, s.fresh, nil
}

// readPoolFile takes a pool file's package from the cache or parses it, and
// checks that the file sits at the pool path its header and the release and
// component directories give.
func (s scanner) readPoolFile(file string) (repoPackage, repoKey, error) {
	info, err := os.Stat(file)
	if err != nil {
		return repoPackage{}, repoKey{}, fmt.Errorf("stat %s: %w", file, err)
	}

	rel, err := filepath.Rel(s.public, file)
	if err != nil {
		return repoPackage{}, repoKey{}, err
	}

	rel = filepath.ToSlash(rel)

	var pkg rpmfile.Package

	entry, ok := s.cache[rel]
	if ok {
		pkg, ok = entry.matches(info)
	}

	if !ok {
		f, err := os.Open(file)
		if err != nil {
			return repoPackage{}, repoKey{}, fmt.Errorf("open %s: %w", file, err)
		}
		defer f.Close()

		parsed, err := rpmfile.Parse(f)
		if err != nil {
			return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w", file, err)
		}

		pkg = parsed

		entry, err = newCacheEntry(info, pkg)
		if err != nil {
			return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w", file, err)
		}

		slog.InfoContext(s.ctx, "parsed", "path", path.Join("public", rel))
	}

	s.fresh[rel] = entry

	err = checkText(pkg)
	if err != nil {
		return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w", file, err)
	}

	parts := strings.Split(rel, "/")
	if len(parts) < 3 {
		return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w", rel, ErrMisplaced)
	}

	key := repoKey{release: parts[1], component: parts[2]}

	err = errors.Join(checkRelease(key.release), repofs.CheckName("component", key.component))
	if err != nil {
		return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w: %w", rel, ErrMisplaced, err)
	}

	want := poolPath(key.release, key.component, pkg)
	if want != rel {
		return repoPackage{}, repoKey{}, fmt.Errorf("build %s: %w, want %s", rel, ErrMisplaced, want)
	}

	return repoPackage{pkg: pkg, path: rel, mtime: info.ModTime().Unix()}, key, nil
}

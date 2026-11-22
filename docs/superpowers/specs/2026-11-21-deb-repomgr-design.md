# repomgr deb: design

`repomgr deb` manages a signed APT repository of `.deb` packages from a single
working directory. You add packages to a suite and component, then build the
published tree that APT clients consume.

## Commands

```text
repomgr deb --workdir <workdir> init --name <name> [--email <email>]
repomgr deb --workdir <workdir> add --suite <suite> --component <component> <file.deb>
repomgr deb --workdir <workdir> build
```

There is no remove command. To remove a package, delete its file from `pool/` and
run `build`.

## Constraints

- The tool is one static Go binary. It never runs external commands and does not
  use cgo, so it runs in a distroless image.
- Supported package architectures: `all`, `amd64`, `arm64`, `armel`, `armhf`,
  `i386`.
- Supported clients: Debian 10 and newer, Ubuntu 20.04 and newer.
- The repository is always signed.
- The repository supports by-hash index acquisition.

## Dependencies

| Module | Version checked | Purpose |
| --- | --- | --- |
| `go.vitalvas.com/gokit/xflags` | latest at implementation | CLI parsing |
| `go.vitalvas.com/gokit/xconfig` | latest at implementation | `config/repo.yaml` |
| `github.com/klauspost/compress` | latest at implementation | zstd for `Packages.zst` and `control.tar.zst` |
| `github.com/ProtonMail/go-crypto` | v1.5.2 | OpenPGP key generation and signing |
| `github.com/ulikunitz/xz` | v0.5.17 | `control.tar.xz` |
| `github.com/stretchr/testify` | latest at implementation | Tests |

The source of `go-crypto` v1.5.2, its dependency `cloudflare/circl` v1.6.3, and
`ulikunitz/xz` v0.5.17 has no `os/exec` or cgo in any code that the binary
compiles. `golang.org/x/crypto` v0.59.0 no longer ships `openpgp`.

## Working directory layout

```text
<workdir>/
  config/
    repo.yaml              origin, label, description, per-suite suite and version; all optional
    signing.asc            armored private key, mode 0600, no passphrase
  cache/
    index.json             pool path -> size, mtime, control fields, checksums
  public/
    key.gpg                binary OpenPGP public key for a Signed-By keyring file
    key.asc                ASCII-armored public key for an embedded Signed-By
    pool/<suite>/<component>/<prefix>/<name>/<Package>_<Version>_<Architecture>.deb
    dists/<suite>/
      InRelease
      Release
      Release.gpg
      <component>/binary-<arch>/Packages
      <component>/binary-<arch>/Packages.gz
      <component>/binary-<arch>/Packages.zst
      <component>/binary-<arch>/Release
      <component>/binary-<arch>/by-hash/MD5Sum/<md5>
      <component>/binary-<arch>/by-hash/SHA1/<sha1>
      <component>/binary-<arch>/by-hash/SHA256/<sha256>
```

`config/` holds sensitive data. `cache/` is disposable: if you delete it, the
next `build` re-reads every package. `public/` is what you publish.

The pool path contains the suite, so an access proxy can grant access per suite
by path. The same file can exist in several suites as separate copies.

## Code layout

The project uses a root `main.go` that holds only `main()`, plus these packages:

| Package | Responsibility |
| --- | --- |
| `internal/cli` | Wires `deb init`, `deb add`, and `deb build` with `xflags`; `--workdir` belongs to `deb` |
| `internal/debfile` | Reads a `.deb`: `ar` container, `control.tar` in `.gz`, `.xz`, `.zst`, or uncompressed; returns control fields, size, MD5, SHA1, SHA256 |
| `internal/pgpsign` | Generates the key, exports the binary public key, produces `InRelease` and `Release.gpg` |
| `internal/debrepo` | Workdir layout, `Init`, `Add`, `Build`, cache index, index and `Release` generation |
| `internal/debtest` | Builds `.deb` files in memory for tests in `debfile` and `debrepo` |

## Naming and validation

`add` never trusts the input file name. It reads the control file inside the
package and derives every path from it.

| Item | Rule |
| --- | --- |
| Suite, component | `^[a-z0-9][a-z0-9_-]*$` |
| `Package` | `^[a-z0-9][a-z0-9+.-]+$` |
| `Version` | Debian version syntax with a numeric epoch when present, a digit-leading upstream version, and an optional Debian revision |
| `Architecture` | One of `all`, `amd64`, `arm64`, `armel`, `armhf`, `i386` |
| `<name>` | `Source` field without any version in parentheses, or `Package` when `Source` is absent |
| `<prefix>` | `lib` plus the next letter for names starting with `lib`, otherwise the first letter |
| Pool file name | `<Package>_<Version without epoch>_<Architecture>.deb` |

`add` rejects a package that fails any rule.

Versions that differ only in epoch (`1:2.0` and `2.0`) map to the same pool
file name. `add` and `build` treat them as one file, so different bytes under
that name are a conflict.

## Command behavior

### init

1. Fail if `config/signing.asc` exists. Replacing the key would break every
   client.
2. Create `config/`, `cache/`, and `public/`.
3. Write `config/repo.yaml` with empty `origin`, `label`, and `description`.
4. Generate a v4 Ed25519 key with user ID `<name> <<email>>`, or `<name>` when
   `--email` is empty, and no expiry.
5. Write `public/key.gpg` and `public/key.asc`, then `config/signing.asc` with
   mode 0600.

### add

1. Fail if the workdir isn't initialized (no `config/repo.yaml`).
2. Validate the suite and component.
3. Parse the package, validate its fields, and compute size, MD5, SHA1, and
   SHA256 in one read.
4. Derive the target pool path.
5. Look for the same file name anywhere in the pool. If any copy
   has a different SHA256, fail. If the target already holds the same bytes, do
   nothing. Otherwise copy.
6. Copy to a temporary file in the target directory and rename it into place.
7. Update the entry in `cache/index.json`.

### build

1. Load `config/repo.yaml`, `config/signing.asc`, and `cache/index.json`, and
   derive the public key from `signing.asc`.
2. Walk `pool/`. Reuse a valid cache entry when size and mtime match. Otherwise,
   parse and hash the file again. Drop entries for missing files and save the cache.
3. Fail if a package isn't at the path its control fields produce, or if the
   same pool file name appears with different SHA256 anywhere in the pool.
4. Group packages by suite, component, and architecture. `Architecture: all`
   packages go only to `binary-all`.
5. Generate every `Packages` index with its `.gz` and `.zst` forms, every
   per-directory `Release`, the top-level `Release`, `InRelease`, and
   `Release.gpg` in memory. A failure up to this step leaves `dists/` as it
   was.
6. Write `public/key.gpg` and `public/key.asc` when either is missing or
   differs from the derived public key. Write missing by-hash files and atomically repair any current by-hash files
   whose content differs from the rendered index.
7. Replace the canonical `Packages`, `Packages.gz`, `Packages.zst`, and
   per-directory `Release` files with a temporary file and rename.
8. Replace `Release` and `Release.gpg`, then `InRelease` last.
9. Apply by-hash retention and remove the directories of suites, components,
   and architectures that no longer have packages.

## Index format

### Packages

Each stanza starts with the package control paragraph, with `Package` moved
to the first line. The build supplies `Filename`, `Size`, `MD5sum`, `SHA1`,
and `SHA256` from the indexed file and replaces any copies of those fields
in the control paragraph. `build` sorts stanzas by `Package`, then `Filename`,
so the same pool always produces the same output.

### Per-directory Release

Each `<component>/binary-<arch>/Release` contains only the fields the
repository format allows: `Archive` (the same value as `Suite`), `Origin`, `Label`,
`Acquire-By-Hash: yes`, `Component`, and `Architecture`. Empty `Origin` and
`Label` are omitted. APT doesn't read these files.

### Top-level Release

| Field | Value |
| --- | --- |
| `Origin`, `Label`, `Description` | From `config/repo.yaml`; omitted when empty |
| `Codename` | The suite name given to `--suite` |
| `Suite` | `suites.<name>.suite` from `config/repo.yaml`; the suite name when unset |
| `Version` | `suites.<name>.version` from `config/repo.yaml`; omitted when unset |
| `Date` | Build time in UTC, RFC 1123 format |
| `Acquire-By-Hash` | `yes` |
| `Architectures` | Architectures present in the suite, plus `all` when the suite has `Architecture: all` packages |
| `Components` | Components present in the suite |
| `MD5Sum`, `SHA1`, `SHA256` | Every `Packages`, `Packages.gz`, `Packages.zst`, and per-directory `Release` |

A suite holding only `Architecture: all` packages gets `Architectures: all`.
APT then fetches `binary-all` and prints an informational notice that the
repository doesn't list the client's native architecture.

## Repository metadata file

`init` writes `config/repo.yaml` with empty top-level fields:

```yaml
origin: ""
label: ""
description: ""
```

You can add an optional `suites` map keyed by the `--suite` name. Each entry
sets the `Suite` and `Version` fields of that suite's `Release`:

```yaml
origin: "vitalvas"
label: "vitalvas"
description: "VitalVas apt repository"
suites:
  bookworm:
    suite: "stable"
    version: "12.0"
```

With this file, `dists/bookworm/Release` gets `Codename: bookworm`,
`Suite: stable`, and `Version: 12.0`. A suite without an entry gets
`Suite` and `Codename` equal to its name and no `Version`. `build` ignores
entries for suites that have no packages. `build` fails if any value contains
a newline, because a newline would corrupt the `Release` file.

## By-hash

Each `Packages`, `Packages.gz`, and `Packages.zst` also exists under its own
directory at `by-hash/MD5Sum/<md5>`, `by-hash/SHA1/<sha1>`, and
`by-hash/SHA256/<sha256>`, matching the three checksum lists in `Release`. The
canonical files are plain copies. APT builds the by-hash URL from the strongest
hash in `Release`, which is SHA256, tries it first, and falls back to the
canonical path.

The repository format requires the current version and asks for at least two
previous versions of each index. `build` keeps exactly two previous versions
with no stored state:

1. Set the mtime of every by-hash file that the new `Release` references to the
   build time. A file's mtime then means the last build in which it was
   current.
2. In each `by-hash/<HashName>/` directory, sort the unreferenced files by
   mtime, newest first, keep the first six, and delete the rest.

`Packages`, `Packages.gz`, and `Packages.zst` always change together, so each
index change adds three files per directory, and six files are two previous
versions. Retention doesn't depend on `cache/`.

The retention count is fixed at two. A CDN in front of the repository is purged
on every publish, so no cache serves an older `InRelease` for long.

## Signing

- The key is an OpenPGP v4 Ed25519 key (algorithm 22, the EdDSA form used by v4
  keys).
- Signatures use SHA-512.
- `InRelease` is a clearsigned `Release`. `Release.gpg` is a detached, armored
  signature of `Release`.
- `public/key.gpg` is a binary public key. Its first byte is `0x98` or `0xc6`,
  which APT accepts for key files that don't end in `.asc`.
- `public/key.asc` is the same key in ASCII armor. APT accepts an embedded key
  in `Signed-By` only in this form, and only from Ubuntu 22.04 and Debian 12.

You use the key like this:

```text
curl -fsSL https://repo.example.com/key.gpg -o /etc/apt/keyrings/repo.gpg
```

```text
Types: deb
URIs: https://repo.example.com
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/repo.gpg
```

## Cache

`cache/index.json` maps each pool path to its size, mtime, control fields, and
checksums. `build` loads it once, parses only new or changed files, removes
entries for missing files, and writes it back once with a temporary file and
rename. `add` writes the entry for the file it adds.

## Errors and logging

- Every error is wrapped with operation context. `main` logs it once with
  `log/slog` to stderr and exits with status 1.
- `add` logs one line per package: `added` or `unchanged`, with the pool path.
- `init` logs `created` for each file it writes, or `kept` for an existing
  `repo.yaml`.
- `build` logs every change it makes, at info level, each with a
  workdir-relative `path`:
  - `parsed` for a package read because the cache had no matching entry.
  - `cache dropped` for a cache entry whose pool file is gone.
  - `created` or `updated` for `public/key.gpg` and `public/key.asc` when
    either was missing or differed.
  - `added by-hash` and `removed by-hash` for by-hash files.
  - `updated` for each `dists/` file it writes.
  - `removed stale` for each directory it deletes.

  `build` doesn't rewrite a `dists/` file whose content is unchanged.
  `Release`, `Release.gpg`, and `InRelease` change on every build because of
  `Date`. At the end, `build` logs one `built` line per suite with the package
  count and architectures.
- Two commands running at the same time on one workdir aren't coordinated. The
  code marks this with a `ponytail:` comment.

## Testing

- Tests use testify, subtests, and the race detector, and must pass `yake run`.
  Each package needs at least 80% coverage, with close to 100% as the target.
- Tests don't read fixture files and don't use the network. `internal/debtest`
  builds packages in memory with each `control.tar` compression.
- `debfile`: every compression; a corrupt `ar` archive; a missing `control`
  file; invalid `Package`, `Version`, and `Architecture`; epoch stripping; an
  input named `test.deb`. Includes a fuzz test of the parser and benchmarks.
- `pgpsign`: `InRelease` and `Release.gpg` verify with the `go-crypto`
  verifier. `key.gpg` has a `0x98` or `0xc6` header, version 4, algorithm 22,
  and the Ed25519 curve identifier `2b 06 01 04 01 da 47 0f 01`.
- `debrepo`: a second `init` fails; `add`; repeated `add` with the same bytes;
  `add` with different bytes; conflicts across suites; `Architecture: all` only
  in `binary-all`; `Architectures` values; `Release` checksums that match the
  files; cache reuse versus re-parse; by-hash files for all three hash types
  that match the canonical files; retention that keeps two previous versions
  across several builds and survives a deleted `cache/`; removal of
  directories that no longer have packages.
- Manual check: run the binary against the packages in `testsdata/` into a
  scratch workdir and inspect the output. Verifying with `apt update` on Debian
  10 and Ubuntu 20.04 or newer needs a Linux host, and you run it.

## Verified sources

| Topic | Source |
| --- | --- |
| Signature verifiers and key file formats | APT 3.1.12 (`6b12812`): `methods/sqv.cc`, `methods/gpgv.cc`, `apt-pkg/init.cc`, `debian/default-sequoia.config` |
| Oldest client behavior | APT 1.8.2: `apt-pkg/aptconfiguration.cc`, `methods/gpgv.cc`, `apt-pkg/deb/debmetaindex.cc`, `apt-pkg/acquire-item.cc` |
| Repository format and by-hash | Debian wiki `DebianRepository/Format`, archived snapshot from 2026-10-24 |
| By-hash client behavior | APT 1.8.2: `apt-pkg/acquire-item.cc` |
| Reference repositories | Zabbix 6.0 `jammy` `Release`; Debian `trixie` `Release` from snapshot 20260924T144048Z |
| Architecture `all` in another tool | reprepro 5.5.1: `distribution.c`, `binaries.c`, `checkindeb.c` |

# repomgr rpm: design

`repomgr rpm` manages a signed RPM repository from its own working directory.
You add packages to a release and component, then build the `repodata` that
`dnf` clients read. The tree follows the same idea as `repomgr deb`: one shared
pool, and indexes that point into it.

## Commands

```text
repomgr rpm --workdir <workdir> init --name <name> [--email <email>]
repomgr rpm --workdir <workdir> add --release <release> --component <component> <file.rpm>
repomgr rpm --workdir <workdir> build
```

There is no remove command. To remove a package, delete its file from `pool/`
and run `build`.

## Constraints

- The tool stays one static Go binary that never runs external commands and
  doesn't use cgo.
- Supported clients: RHEL 8 and newer, and rebuilds with the same `dnf` (Rocky,
  Alma, CentOS Stream).
- Supported package architectures: `x86_64`, `aarch64`, `noarch`.
- The repository metadata is always signed. Packages are stored unchanged and
  are never re-signed.
- An `rpm` workdir holds only RPM repositories. `deb` and `rpm` never share a
  workdir.

## Dependencies

No new modules. Gzip comes from `compress/gzip`, as on the deb side, XML from
`encoding/xml`, and signing from the existing `internal/pgpsign`.

## Working directory layout

```text
<workdir>/
  config/
    signing.asc            armored private key, mode 0600, no passphrase
  cache/
    index.json             pool path -> size, mtime, parsed header data, SHA256
  upload/<release>/<component>/*.rpm
                           inbox that build moves into the pool
  public/
    key.asc                ASCII-armored public key for gpgkey=
    <name>.repo            your own dnf repo files, never touched
    pool/<release>/<component>/<prefix>/<name>/<arch>/<NAME>-<VERSION>-<RELEASE>.<ARCH>.rpm
    <basearch>/<release>/<component>/repodata/
      repomd.xml
      repomd.xml.asc
      <sha256>-primary.xml.gz
      <sha256>-filelists.xml.gz
      <sha256>-other.xml.gz
```

`<basearch>` is `x86_64` or `aarch64`. Each index lists the packages of its
architecture plus every `noarch` package of the same release and component.
The `noarch` file exists once in the pool.

`build` writes and removes only `public/key.asc`, `public/pool/`, and the
`public/x86_64/` and `public/aarch64/` trees. Anything else under `public/`,
such as `<name>.repo` files you publish for clients, stays as it is.

Each package entry in `primary.xml` points into the pool with a path relative
to the repository directory, for example:

```text
../../../pool/9/auth-51/p/pdns/x86_64/pdns-5.1.0-1.el9.x86_64.rpm
```

A client uses the repository like this:

```text
[example-auth-51]
name=Example auth-51
baseurl=https://repo.example.com/$basearch/$releasever/auth-51
gpgkey=https://repo.example.com/key.asc
repo_gpgcheck=1
enabled=1
```

`repo_gpgcheck=1` checks the signature on `repomd.xml`, which covers every
package through the checksums in the metadata. Packages that carry a vendor
signature can also use `gpgcheck=1` with the vendor key listed in `gpgkey=`.

### Workdir type

`init` creates the same `config/signing.asc` for both formats, so that file
alone can't tell the formats apart. `rpm` commands refuse a workdir that has
`public/dists/` or `public/key.gpg`, and `deb` commands refuse one that has
`public/x86_64/` or `public/aarch64/`. Only the `deb` side writes
`public/key.gpg`, and it does so at `init`, so a `deb` workdir that was never
built is caught too. In the same way, `rpm init` creates the empty
`public/x86_64/` and `public/aarch64/` directories, and `build` never removes
them, so an `rpm` workdir that was never built is caught as well.

## Code layout

| Package | Responsibility |
| --- | --- |
| `internal/repofs` | Shared code moved from `internal/debrepo`: key creation for `init`, `writeAtomic`, the suite and component name rule, the `os.Root` upload walk with the file extension and the add step as parameters, and a generic `cache/index.json` (`Cache[T]`). `debrepo` uses it with no change in behavior apart from the workdir type check. |
| `internal/rpmfile` | `Parse(r io.Reader) (Package, error)`: lead, signature and main headers, digests, limits, validation |
| `internal/rpmtest` | Builds RPMs in memory for tests: header writer, minimal payload, correct digests |
| `internal/rpmrepo` | `Init`, `Add`, `Build`, the `primary`, `filelists`, `other`, and `repomd.xml` writers, retention, the workdir type check |
| `internal/cli` | Adds the `rpm` group with `init`, `add`, and `build`; `--workdir` belongs to `rpm` |

## Reading a package

`add` never trusts the input file name. It reads the RPM and derives every
path from the header.

- The 96-byte lead must carry the RPM magic `ed ab ee db` and the binary
  package type. A source RPM fails. No digest covers the lead, so the main
  header must also carry `SOURCERPM`: `rpm` treats a package without it as a
  source package, whatever the lead says. A header whose `SOURCEPACKAGE`
  (1106) holds a nonzero number (first element of an `INT8`, `INT16`, `INT32`,
  or `INT64` tag, read unsigned) also fails: `rpm` sets that tag on source
  packages, and the reference rpm-md writer then writes `src` as the arch. A
  zero value or any other type is ignored, as the reference does.
- Each tag may appear only once per header. `rpm` finds a tag with a binary
  search, so with duplicates the copy it uses isn't defined, and the parser
  could index a different name or version than `rpm` installs.
- Entry data follows `rpm`'s own layout check (`hdrblobVerifyInfo` in 4.14.3).
  When the first entry is a region tag (61, 62, or 63), the walk skips it.
  The remaining entries are walked in file order, and each must start at or
  after the end of the previous one. Each must have a length above zero that
  ends inside the data, and an offset aligned to 2, 4, or 8 for 16-, 32-, and
  64-bit values. A `STRING` entry must have a count of exactly 1. Every byte
  is scanned at most once, so the check is linear in the data size, and no
  two arrays can share bytes. The parser also compares the counts of a
  dependency's name, flags, and version arrays before it reads any of them.
- The signature header follows the lead and is padded to a multiple of 8
  bytes. The parser reads the header digests, SHA-256 (tag 273) and SHA-1
  (tag 269), and the size tags listed in [Extracted data](#extracted-data).
  At least one digest must be present. Each one present must be a `STRING` of
  exactly 64 (SHA-256) or 40 (SHA-1) hex digits in either case and must match
  the main header without regard to case, as `rpm`'s `validHex`, tag size, and
  `strcasecmp` checks in `lib/rpmvs.c` do. A package that carries both must
  match both. Packages built with older `rpm` carry only SHA-1.
- Both headers must parse within `rpm`'s own limits (`hdrblobRead` in
  `lib/header.c`): the signature header has at most 32 index entries and 8192
  bytes of data; the main header has at most 65535 index entries and
  268435455 (`0x0fffffff`) bytes of data. Both are checked before anything
  past the 16-byte header intro is read.
- The payload is never unpacked. When the main header has `PAYLOADDIGEST`
  (tag 5092, `STRING_ARRAY`), the parser streams the payload once and checks
  it the way `rpm` 4.14.3 verifies that tag: every element must be valid hex
  (even length, at least 40 digits, only hex digits) and must equal the
  SHA-256 of the payload bytes without regard to case. `rpm` 4.14.3 always
  uses SHA-256 for this tag and doesn't read `PAYLOADDIGESTALGO` (tag 5093)
  when it verifies, so neither does the parser. Without the tag, the payload
  isn't checked. A truncated or edited file fails.
- The parser returns the byte range of the main header for
  `rpm:header-range`.

Tag numbers and header limits are checked against the `rpm` 4.14 sources that
RHEL 8 ships before implementation.

### Naming and validation

| Item | Rule |
| --- | --- |
| Release | A whole number of 8 or more, without leading zeros |
| Component | `^[a-z0-9][a-z0-9_-]*$` |
| `NAME` | `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, case kept |
| `VERSION`, `RELEASE` | `^[A-Za-z0-9._+~^]+$` |
| `EPOCH` | Absent or a whole number |
| `ARCH` | `x86_64`, `aarch64`, or `noarch` |
| `SOURCERPM` | Required; must end in `.src.rpm` or `.nosrc.rpm` (the name `rpm` gives the source package of a spec with `NoSource` or `NoPatch`) and have at least two `-` before the suffix; written to `<rpm:sourcerpm>` as is |
| `<name>` | The name part of `SOURCERPM` (`pdns-5.1.0-1.el9.src.rpm` gives `pdns`), which must pass the `NAME` rule |
| `<prefix>` | Lowercase `lib` plus the next letter for names starting with `lib`, otherwise the lowercase first letter |
| Pool file name | `<NAME>-<VERSION>-<RELEASE>.<ARCH>.rpm` |

`add` rejects a package that fails any rule. The epoch is left out of the file
name, so two packages that differ only in epoch share a file name, and
different bytes under that name are a conflict.

### Extracted data

- Name, epoch, version, release, arch.
- Summary, description, URL, packager, vendor, group, build host, source RPM,
  build time.
- Package size, installed size, archive size.
- `provides`, `requires`, `conflicts`, `obsoletes`, `recommends`, `suggests`,
  `supplements`, `enhances`, and the old `suggests` and `enhances` tags, each
  with name, flags, and version.
- The file list from dirnames, basenames, and directory indexes, with the mode
  and ghost flags.
- The changelog: author, time, and text.

[Dependency lists](#dependency-lists) describes how these become the lists in
`primary.xml`.

The descriptive fields come from these main header tags:

| Field | Tag | Type | When absent |
| --- | --- | --- | --- |
| Summary | 1004 | `I18NSTRING` or `STRING`, first string | Empty |
| Description | 1005 | `I18NSTRING` or `STRING`, first string | Empty |
| Build time | 1006 | `INT32`, count 1, unsigned | 0 |
| Build host | 1007 | `STRING` | Empty |
| Vendor | 1011 | `STRING` | Empty |
| License | 1014 | `STRING` | Empty |
| Packager | 1015 | `STRING` | Empty |
| Group | 1016 | `I18NSTRING` or `STRING`, first string | Empty |
| URL | 1020 | `STRING` | Empty |

The first string of an `I18NSTRING` is the untranslated text, which is what
`rpm` returns when no locale is set. The installed size is tag 5009 (`INT64`,
count 1) when present, else tag 1009 (`INT32`, count 1), else 0. The archive
size is tag 271 (`INT64`, count 1) when present, else tag 1046 (`INT32`,
count 1), else 0. `rpm` copies signature tags into the main header when the
main header lacks them, so tag 271 may also come from the signature header,
and signature tag 1007 (`INT32`, count 1) stands in for tag 1046. Signature
tag 1046 is never used. The tag that a field is taken from fails as an invalid
field when it has the wrong type or count; a fallback tag that isn't used
isn't checked.

The changelog uses tags 1080 (times, `INT32`), 1081 (authors, `STRING_ARRAY`),
and 1082 (texts, `STRING_ARRAY`). All three absent means no changelog. If any
is present, all three must be, with the same count, compared before any array
is read. Only the first 10 entries in header order are kept, and they're
written in reverse header order. Each entry is processed in header order:

1. The time is the unsigned 32-bit value. The author loses trailing spaces,
   but its first byte is never removed.
2. When the time equals the last remembered time, which starts at 0, the
   entries processed before it get their times raised: walk back from the
   one just before, and while an entry's time equals a counter that starts at
   the current time truncated to a signed 32-bit integer, add 1 to both that
   entry's time and the counter. A time of 2^31 or more never matches.
   Otherwise the current time becomes the last remembered time.

### Text in the metadata

Before writing, the package is refused when any of these holds a byte below 32
other than tab (9), newline (10), or carriage return (13): name, arch,
version, epoch, release, summary, description, URL, license, vendor, group,
build host, source RPM, packager, the name, epoch, version, and release of
every entry in the dependency lists after the rules in
[Dependency lists](#dependency-lists) (including entries later skipped for an
empty name), every file's directory name and base name, and the author and
text of every kept changelog entry. The pool location is built only from
fields the naming rules already limit to ASCII, so it needs no check.

A text value that isn't valid UTF-8 by the loose check (each lead byte
followed by the right number of continuation bytes) is converted from
Latin-1: bytes below 128 are kept except control bytes other than 9, 10, and
13, bytes 128 to 191 are dropped, and bytes 192 to 255 become two-byte UTF-8.
After that step, a value that is still not strict UTF-8, or holds U+FFFE or
U+FFFF, refuses the package with an error naming the field. The loose check
accepts overlong forms, surrogates, and values above U+10FFFF, and the
reference XML library writes them in ways Go can't reproduce, so these
packages are refused instead.

Whether an optional attribute is written depends on the raw value, before
conversion, as in the reference: a dependency's `ver` whose raw text is only
bytes that conversion drops is still written, as `ver=""`.

`add` refuses such a package before copying it, and `build` fails on one
found in the pool.

The metadata matches the reference after parsing, not byte for byte. Every
element, attribute, and value a client reads is the same, but the escaping
comes from Go's `encoding/xml`. In element text it writes `'`, `"`, newline,
and tab as character references where the reference XML library writes them
as-is, and in attributes it uses other reference forms (`&#xA;` where the
reference writes `&#10;`). It writes non-ASCII text as UTF-8 where the
reference writes character references, and an empty element as a start and
end tag.

## Command behavior

### init

1. Fail if `config/signing.asc` exists, or if the workdir has `public/dists/`
   or `public/key.gpg`.
2. Create `config/`, `cache/`, `public/`, `public/x86_64/`, and
   `public/aarch64/`.
3. Generate a v4 Ed25519 key, as `deb init` does.
4. Write `public/key.asc`, then `config/signing.asc` with mode 0600.

### add

1. Fail if the workdir isn't initialized or is a `deb` workdir.
2. Validate the release and component.
3. Parse the package, validate it, and compute size and SHA256 in one read.
4. Derive the pool path.
5. Look for the same file name anywhere in the pool. If any copy has a
   different SHA256, fail. If the target already holds the same bytes, do
   nothing. Otherwise copy it with a temporary file and rename.
6. Update the entry in `cache/index.json`.

### build

1. Fail if the workdir isn't initialized or is a `deb` workdir. Create
   `public/x86_64/` and `public/aarch64/` when missing, and fail if either is
   anything other than a directory, a symlink included. Load
   `config/signing.asc` and derive the public key.
2. Process `upload/` as described in [Upload inbox](#upload-inbox).
3. Load `cache/index.json` and walk `pool/`. Reuse a cache entry when size and
   mtime match; otherwise parse the file again. Drop entries for missing files
   and save the cache.
4. Fail if a package isn't at the path its header produces, or if the same
   pool file name appears with different SHA256 anywhere in the pool.
5. Group packages by release, component, and base architecture. `noarch`
   packages join both base architectures. A base architecture with only
   `noarch` packages still gets an index.
6. Render every `primary`, `filelists`, and `other` file, every `repomd.xml`,
   and every `repomd.xml.asc` in memory. A failure up to this step leaves
   the published `repodata/` directories as they were.
7. Write `public/key.asc` when it is missing or differs from the derived key.
8. For each changed repository, write the new metadata files. Then write
   `repomd.xml.asc` and `repomd.xml` to temporary files in the same
   directory, and only when both are written rename `repomd.xml.asc` into
   place, then `repomd.xml`.
9. Apply retention and remove the release and component directories that no
   longer have packages for that base architecture. Removal stays inside
   `public/x86_64/` and `public/aarch64/`: those two directories stay even
   when empty, only directories are removed, and files directly in `public/`
   are never touched.
10. If any upload was rejected, return an error naming the count, so the
    command exits with status 1 after everything else is published.

`repomd.xml` and its signature are two files. A client that fetches between
the two writes sees a pair that doesn't match and fails that refresh; the next
refresh succeeds. `dnf` has no inline signed form like `InRelease`.

### Upload inbox

The inbox follows the `deb` rules with `.rpm` in place of `.deb`, through the
shared walk in `internal/repofs`:

- `build` walks `upload/` in lexical order. A missing `upload/` counts as
  empty.
- It skips names that start with `.` and files that don't end in `.rpm`.
- An `.rpm` must sit at `upload/<release>/<component>/<file>.rpm` and be a
  regular file. A symlink is rejected.
- The open and the delete go through an `os.Root` on `upload/`, and the open
  doesn't block, so a swapped directory or FIFO is rejected.
- Each upload goes through `add` steps 2 to 5. On success, or when the pool
  already holds the same bytes, `build` deletes the upload.
- Any failure leaves the file in `upload/` with an error line and counts it as
  rejected.

## Metadata format

All files use the standard namespaces: `http://linux.duke.edu/metadata/common`,
`.../rpm`, `.../filelists`, `.../other`, and `.../repo`. Packages are sorted by
name, then arch, then pool path, so the same pool always produces the same
bytes.

### primary.xml

One `<package type="rpm">` per package with `name`, `arch`, `version`
(`epoch`, `ver`, `rel`; epoch `0` when absent), `checksum type="sha256"
pkgid="YES"`, `summary`, `description`, `packager`, `url`, `time` (`file` is
the pool file mtime, `build` the header build time), `size` (`package`,
`installed`, `archive`), and `location href` relative to the repository
directory.

`primary.xml` matches the reference rpm-md writer exactly; nothing is added,
dropped, or reordered on a guess. `<format>` holds, in this order:

1. `rpm:license`, `rpm:vendor`, `rpm:group`, `rpm:buildhost`, and
   `rpm:sourcerpm`, each written as an element even when its value is empty.
2. `rpm:header-range` with `start` and `end`.
3. The dependency containers `rpm:provides`, `rpm:requires`, `rpm:conflicts`,
   `rpm:obsoletes`, `rpm:suggests`, `rpm:enhances`, `rpm:recommends`, and
   `rpm:supplements`, built as described in
   [Dependency lists](#dependency-lists). A container is left out only when
   its list is empty. Inside a container, an entry with an empty name writes
   nothing, so a list of only empty names gives an empty container. Each
   `rpm:entry` has `name`. It has `flags` only when the flags string isn't
   empty, and `epoch`, `ver`, and `rel` only together with `flags`, each only
   when not empty. It has `pre="1"` only on requires.
4. One `<file>` for every file whose full path starts with `/etc/`, contains
   `bin/` anywhere (so `/usr/sbin/` counts), or is exactly
   `/usr/lib/sendmail`, whatever its type. `type` is `dir` for a directory,
   `ghost` for a ghost file, and left out for a regular file.

### Dependency lists

The lists come from the header in this tag order: provides, conflicts,
obsoletes, requires, suggests, enhances, recommends, supplements, then the old
suggests tags (1156 name, 1157 version, 1158 flags) and the old enhances tags
(1159 name, 1160 version, 1161 flags). Within a list, entries keep header
order. For every entry:

- The flags string comes from `flags & 0xf`: 2 is `LT`, 4 is `GT`, 8 is `EQ`,
  10 is `LE`, 12 is `GE`, and any other value gives no string.
- The version splits like this. An empty version gives no epoch, `ver`, or
  `rel`. Otherwise, when it has a `:`, the epoch is good when a C `strtol`
  base-10 parse of the version stops exactly at the first `:`. That allows
  leading C `isspace` characters (space, tab, newline, vertical tab, form
  feed, carriage return) and a sign before the digits, and an empty text before the
  `:`. A good epoch is the raw text before the `:`, or `0` when that text is
  empty. Any other epoch is bad, and the entry is dropped whatever its flags. Without a `:`, the
  epoch is `0`. The rest splits at its first `-`: `ver` is the part before it,
  and `rel` the part after it when that isn't empty. Without a `-`, all of the
  rest is `ver`.

Requires get extra rules, checked in this order:

1. A name starting with `rpmlib(` is dropped.
2. A name starting with `/` that is one of the package's own files and passes
   the primary file rule is dropped.
3. An entry whose name, flags string, and raw version, joined as plain
   strings, equal those of a provide of the same package is dropped.
4. `pre` is set when the flags have any of bit 6, 9, or 10.
5. An entry is dropped when the last kept require with the same name has the
   same flags string, raw version, and `pre`. Entries that rules 7 and 8
   handle never count as kept requires here.
6. A bad epoch drops the entry, as for every list.
7. An entry with flag bit 19 moves to recommends and skips the next rule.
   These entries keep header order and come before the package's own
   recommends.
8. Of the entries whose name starts with `libc.so.6`, only one stays: the
   first, replaced by a later one only when the later one compares higher.
   That one goes at the end of requires. The compare looks at the text between
   the first `(` and the next `)`. A name without `(` is lower than one with
   it. When neither name has a `)` after its `(`, the kept one stays; when
   only one has it, the one without it is lower. An empty `()` is lower than
   a non-empty one, and text without a digit is lower than text with one.
   Otherwise the text from the first digit to the `)` is compared with
   `rpmvercmp`.

The old suggests entries go to recommends when the flags have bit 27, and to
suggests when they don't. The old enhances entries go to supplements with bit
27, and to enhances without it.

### filelists.xml and other.xml

`filelists.xml` has one `<package pkgid name arch>` per package with its
`version` and every file, marked `type="dir"` or `type="ghost"` when it is one.
`other.xml` has the same package element with each kept changelog entry,
after `version`, as `<changelog author date>` with the text as content.

### repomd.xml

`repomd.xml` has a `revision` and one `<data type>` for `primary`,
`filelists`, and `other`, each with `checksum` and `open-checksum` (SHA-256
of the compressed and uncompressed bytes), `location`
(`repodata/<sha256>-<type>.xml.gz`), `timestamp`, `size`, and `open-size`.

`revision` and the timestamps are the time of the build that last changed the
repository. When the rendered `open-checksum` values match the published
`repomd.xml` and its signature verifies with the current key, `build` keeps
both files unchanged. A build with no changes writes nothing.

Metadata is gzip only. Every client back to RHEL 8 reads it.

## Signing

- `repomd.xml.asc` is the armored detached signature from `pgpsign.Sign`,
  SHA-256 over Ed25519.
- `librepo` on RHEL 8 checks it through GnuPG 2.2, which supports Ed25519
  keys. This isn't verified against sources yet; the `dnf` client tests on EL
  8, 9, and 10 confirm it.
- Packages aren't signed. `gpgcheck=1` works only for packages that already
  carry a vendor signature.

## Retention

Each `repodata/` keeps the metadata files of the two previous generations, so
a client holding an older `repomd.xml` can still finish its download. As with
`deb` by-hash, a file's mtime is the build in which it last became current.
For each type, `build` sorts the unreferenced files by mtime, newest first,
keeps two, and deletes the rest. A referenced file older than the newest
unreferenced file of its type (content that came back after a change) gets
its mtime set to the build time, so it ranks as current. Only files named
`<sha256>-<type>.xml.gz` count; other files in `repodata/` are left alone.
Retention doesn't depend on `cache/`.

## Errors and logging

- Every error is wrapped with operation context. `main` logs it once and exits
  with status 1.
- `init` logs `created` for each file it writes.
- `add` logs `added` or `unchanged` with the pool path.
- `build` logs, each with a workdir-relative `path`:
  - `moved`, `removed duplicate`, and `upload rejected` for uploads.
  - `parsed` and `cache dropped` for the pool scan.
  - `created` or `updated` for `public/key.asc`.
  - `added` for each metadata file, `updated` for `repomd.xml` and
    `repomd.xml.asc`, and `removed` for each metadata file retention drops.
  - `removed stale` for each directory it deletes.
  - One `built` line per release and component with the package count and
    base architectures.
- Two commands running at the same time on one workdir aren't coordinated.

## Client notes

- On RHEL 8, modular filtering hides a package from a non-modular repository
  when an enabled module stream ships a package of the same name. `repomgr`
  doesn't write `modules.yaml`.
- Debuginfo repositories are out of scope.

## Testing

- Tests use testify, subtests, and the race detector, and must pass
  `yake run` with at least 80% coverage per package.
- Unit tests don't use the network or fixture files. `internal/rpmtest` builds
  packages in memory.
- `rpmfile`: a table test per validation rule; each limit at the limit and one
  byte over; every truncation; a source RPM; a header digest and a payload
  digest that don't match; a fuzz test of the parser.
- `rpmrepo`: pool paths; repeated `add` with the same bytes; conflicts across
  releases and components; `noarch` in both base architectures; XML content
  field by field; `repomd.xml` checksums and sizes that match the files; the
  signature verified with `pgpsign.Verify`; a second build that writes
  nothing; retention that keeps two previous generations across several
  builds; removal of stale directories while a `public/<name>.repo` file
  stays; the inbox; the workdir type check.
- `debrepo`: the existing suite passes unchanged after the move to
  `internal/repofs`.
- Real packages: a handful of RPMs downloaded directly, without a proxy, from
  the Rocky and EPEL 8 and 9 repositories into `.tmp/`. The parser must read
  every one and produce the right fields.
- Real clients: `dnf` in `rockylinux:8`, `rockylinux:9`, and an EL 10 image
  (`dnf` 5) installs from a built repository served over HTTP with
  `repo_gpgcheck=1`. This also proves the relative pool locations.

## Verified sources

| Topic | Source |
| --- | --- |
| Package URL from base URL and location | `librepo` 1.14.5: `librepo/downloader.c` (`select_next_target`, `lr_pathconcat`; `CURLOPT_PATH_AS_IS` not set) |
| Local file name of a download | `librepo` 1.14.5: `librepo/package_downloader.c` (`g_path_get_basename`) |
| Tag numbers and tag types | `rpm` 4.14.3: `lib/rpmtag.h` |
| Lead layout and checks | `rpm` 4.14.3: `lib/rpmlead.c` (magic, major 3 or 4, signature type 5, type 1 for source) |
| Header magic and limits | `rpm` 4.14.3: `lib/header.c` (`8e ad e8 01`, at most 65535 entries and 256 MiB of data; the signature header at most 32 entries and 8192 bytes) |
| Dependency flags | `rpm` 4.14.3: `lib/rpmds.h` (`RPMSENSE_PREREQ` 1<<6, `SCRIPT_PRE` 1<<9, `RPMLIB` 1<<24) |
| primary.xml content and order | The rpm-md reference writer from rpm-software-management, 0.17.7: `src/xml_dump_primary.c` (`<format>` order, `rpm:entry` attributes), `src/xml_dump.c` (`<file>` filter and `type`), `src/misc.h` (primary file rule), `src/misc.c` (flags strings, version split), `src/parsehdr.c` (dependency tag order, requires filtering, `libc.so.6` compare, old weak dependency tags, file types), `CMakeLists.txt` (old weak dependency support on by default) |
| Version compare | `rpm` 4.14.3: `lib/rpmvercmp.c` (`rpmvercmp`) |
| Header and payload digest checks | `rpm` 4.14.3: `lib/rpmvs.c` (`rpmvfytags`, `rpmvfyitems`: tag 5092 verified as SHA-256; `validHex`; `verifyDigest` with `strcasecmp`), `lib/rpmtag.h` (5092, 5093) |
| Descriptive fields, sizes, changelog | The reference writer 0.17.7: `src/parsehdr.c` (fields, changelog limit and time fix-up, author trim), `src/cmd_parser.h` (changelog limit 10), `src/xml_dump.c` (control character refusal, Latin-1 conversion), `src/xml_dump_other.c`; `rpm` 4.14.3: `lib/rpmtag.h`, `lib/tagexts.c` (64-bit size fallback), `lib/package.c` (`headerMergeLegacySigs`), `lib/rpmtd.c` (unsigned numbers) |
| UTF-8 check and XML escaping | `libxml2` 2.9.7: `xmlstring.c` (`xmlCheckUTF8`), `xmlsave.c` (`xmlEscapeEntities`, `xmlBufAttrSerializeTxtContent`) |
| Old weak dependency tags and flags | `rpm` 4.14.3: `lib/rpmtag.h` (1156-1161), `lib/rpmds.h` (`RPMSENSE_MISSINGOK` 1<<19); bit 27 as defined in the reference `src/parsehdr.c` |
| How dnf reads the metadata | `libsolv` 0.7.20: `ext/repo_rpmmd.c`; `librepo` 1.14.5: `librepo/repomd.c` |
| Ghost file flag | `rpm` 4.14.3: `lib/rpmfiles.h` (`RPMFILE_GHOST` 1<<6) |
| Reference layout | PowerDNS `el-auth-51.repo`: `baseurl=.../el/$basearch/$releasever/auth-51` |

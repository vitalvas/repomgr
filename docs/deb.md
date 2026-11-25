# Deb repositories

Deb repositories work on Debian 10 and Ubuntu 20.04 or newer.

## Commands

Every command takes `--workdir`, the directory that holds the repository.

### Initialize a workdir

```shell
repomgr deb --workdir /srv/repo init --name "Example Repo" --email repo@example.com
```

`init` creates the workdir layout and generates the signing key. The key is an
OpenPGP v4 Ed25519 key with no passphrase, stored in `config/signing.asc`. The
public half goes to `public/key.gpg` in binary form and to `public/key.asc` in
ASCII armor. `--email` is optional; without it, the key's user ID is just the
name. Running `init` again on the same workdir fails, so it never replaces a
key your clients already trust.

### Add a package

```shell
repomgr deb --workdir /srv/repo add --suite noble --component main ./ikev2-hub.deb
```

`add` reads the control data inside the package and ignores the input file
name. It validates `Package`, `Version`, and `Architecture`, then copies the
file to its pool path:

```text
pool/<suite>/<component>/<prefix>/<name>/<Architecture>/<Package>_<Version>_<Architecture>.deb
```

`<name>` is the `Source` field, or `Package` when there's no `Source`. The
version in the file name drops any epoch. Supported architectures are `all`,
`amd64`, `arm64`, `armel`, `armhf`, and `i386`.

A package whose `control.tar` unpacks to more than 64 MiB, or whose `control`
file is over 16 MiB, fails. A `control.tar.xz` must be one xz stream whose
blocks use LZMA2 with a dictionary of at most 64 MiB, which every standard
`xz` preset meets.

Adding the same bytes again does nothing. Adding different bytes under a file
name that already exists in any suite or component fails. You can add the same
package to several suites; each suite gets its own copy.

### Build the indexes

```shell
repomgr deb --workdir /srv/repo build
```

`build` scans the pool and writes everything under `public/dists/`:

- `Packages`, `Packages.gz`, and `Packages.zst` for each suite, component, and
  architecture. `Architecture: all` packages go only into `binary-all`.
- A `Release` file in each `binary-<arch>` directory.
- The suite `Release`, its detached signature `Release.gpg`, and the
  clearsigned `InRelease`. All signatures use SHA-256.
- By-hash copies of every index, with the two previous versions kept so
  clients that fetched an older `InRelease` can still finish.

`build` signs everything in memory before it writes anything, and writes
`InRelease` last. It removes directories of suites, components, and
architectures that no longer have packages. It fails without touching
`dists/` if a pool file isn't at the path its control data gives, or if two
files share a name but differ in content.

`build` only writes files whose content changed. When nothing changed, it
writes nothing, so you can run it from cron without touching your CDN. A
suite's `Release` keeps its old `Date` until the suite's indexes, its metadata
in `repo.yaml`, or the signing key change.

`build` also restores `public/key.gpg` and `public/key.asc` from
`config/signing.asc` when either file is missing or differs.

`build` caches parsed packages in `cache/index.json` and only re-reads files
whose size or modification time changed. You can delete `cache/` at any time.
It also resets the `deb-mirror` rollback state (see "Mirror an upstream
repository").

### Upload inbox

Instead of running `add` for each package, you can drop packages into
`upload/<suite>/<component>/` and run `build`:

```shell
cp ikev2-hub.deb /srv/repo/upload/noble/main/
repomgr deb --workdir /srv/repo build
```

Before it scans the pool, `build` checks every `*.deb` directly inside an
`upload/<suite>/<component>/` directory the same way `add` does. Then:

- A package with no conflict is copied into its pool path and then deleted from
  `upload/`. It lands in the indexes of the same build.
- A package whose exact bytes are already in the pool is deleted from
  `upload/`.
- A symlink in `upload/` is rejected and stays in place.
- A package that fails a check stays in `upload/` and gets an error line. This
  covers a conflict with the pool, an invalid package, a bad suite or component
  name, or a `.deb` at any other depth. `build` still publishes everything else,
  then exits with status 1.

`build` ignores files that don't end in `.deb`, and files and directories whose
names start with a dot. Upload to a temporary name such as `.ikev2-hub.deb` or
`ikev2-hub.deb.part`, then rename it once the copy is complete, so `build`
never reads a half-written package.

### Mirror an upstream repository

`deb-mirror` copies packages from a remote APT repository into the pool of an
initialized workdir:

```shell
repomgr deb-mirror --workdir /srv/repo \
  --source-repo https://packages.broadcom.com/artifactory/saltproject-deb/ \
  --source-suite stable --source-component main \
  --target-suite mirrors --target-component salt-3006 \
  --filter-name 'salt.*' --filter-version-exclude '.*~rc.*' --filter-version '3006.*'
repomgr deb --workdir /srv/repo build
```

It reads `dists/<source-suite>/InRelease`, then the listed package indexes for
supported architectures. It prefers `Packages.zst`, then `Packages.gz`, then
plain `Packages`. At least one supported index must be
listed for the component. It checks each index against the size and SHA256 in
`Release` and each `.deb` against the size, SHA256, and package identity in the
index. Then it adds the package to `--target-suite` and `--target-component`
the same way `add` does.
It doesn't build indexes, so run `build` after your mirror runs.

Before it requests any index, it runs three checks on `InRelease`, whether or
not you set `--source-key`:

- The `Suite` field must equal `--source-suite`. A `Codename` match also
  passes, unless `Suite` starts with `<source-suite>-`. That case is a pocket
  of the same codename, such as `noble-updates` served for `noble`, and it
  fails.
- `Date` must be present and no more than 5 minutes in the future. When
  `Valid-Until` is present, it must not be in the past.
- `Date` must not be older than the last one accepted for this source repo and
  suite. An equal or newer date passes.

`cache/mirror-state.json` holds that last accepted date per source repo and
suite, keyed by the URL as you give it without any `user:password@` part. A
corrupt file stops the run.
Deleting `cache/` resets the rollback protection, and the next run trusts any
validly signed, unexpired `Release`.

The mirror only adds. It never deletes local packages, even when upstream drops
them. It copies every matching version and skips downloading packages already
in the pool that match the index.

These flags select packages. Each one is a Go regular expression that must
match the whole value of the package control field. The name filters match the
`Package` field. An empty value means no filter, and an invalid pattern fails
before any request:

| Flag | Field | Default |
| --- | --- | --- |
| `--filter-name` | `Package` | `.*` |
| `--filter-name-exclude` | `Package` | none |
| `--filter-version` | `Version` | `.*` |
| `--filter-version-exclude` | `Version` | none |
| `--filter-architecture` | `Architecture` | none |
| `--filter-architecture-exclude` | `Architecture` | none |

A package is mirrored when every include filter matches and no exclude filter
matches. Filters see the fields exactly as upstream writes them, so a version
with an epoch such as `1:3006.0` doesn't match `3006.*`. Field names in the
upstream `InRelease` and `Packages`, and in package control files, are matched
case-insensitively, as in deb822.

An upstream that needs a login can take credentials in the URL, as in
`https://user:token@host/path/`. `deb-mirror` sends them with every request but
removes the whole `user:password@` part from every URL it logs, puts in an
error, or stores, because the user name can be the token too.

`--source-key <file>` takes the upstream public key, armored or binary. With
it, `deb-mirror` verifies the `InRelease` signature and stops if it doesn't
match. Without it, the signature isn't checked.

If a local pool file has a different SHA256 than upstream, that package fails.
`--force` replaces it with the verified upstream file instead, which repairs a
corrupted local copy. `--force` only touches the target suite and component; a
file with the same name and different content anywhere else in the pool still
fails.

A package that fails to download, verify, or add gets an error line, and the
rest of the run continues. The command then exits with status 1.

These limits keep an upstream from stalling the run or exhausting memory or
disk:

- A request that receives no data for 60 seconds fails. This covers
  connecting, waiting for the response, and every pause in the body, so a
  large package on a working link still finishes.
- `InRelease` can be at most 16 MiB. A `Packages` index can be at most 256 MiB,
  both as listed in `Release` and after decompression. Going over either limit
  stops the run.
- A package fails if downloading it would leave less than 1 GiB free on the
  filesystem that holds `cache/`. The check counts twice the package size,
  because the file sits in `cache/` while it's copied into the pool.

An upstream that sends a byte just often enough to beat the 60-second limit
can still keep a run going. To cap the total time, run the command under a
limit such as `timeout 2h`. `SIGINT` and `SIGTERM` stop the command cleanly.

## Workdir layout

```text
<workdir>/
  config/
    repo.yaml       repository metadata, optional
    signing.asc     private signing key, mode 0600
  cache/
    index.json      parsed package cache
  upload/
    <suite>/<component>/
                    packages waiting for the next build
  public/
    key.gpg         binary public key for a Signed-By keyring file
    key.asc         ASCII-armored public key for an inline Signed-By
    pool/           packages
    dists/          indexes and signatures
```

Publish `public/` and keep `config/` and `upload/` private. The `Origin`, `Label`,
`Description`, and per-suite `Suite` and `Version` fields come from
`config/repo.yaml`. `init` doesn't create this file. When a field isn't set, `Origin` and `Label`
default to `. <suite>` (for example `. stable`),
`Description` to `Generated by repomgr`, and `Version` is left out.

## Use the repository with apt

You can point `Signed-By` at a keyring file, which works on every supported
release, or embed the key in the source file, which needs Ubuntu 22.04 or
Debian 12 and newer.

### Signed-By with a keyring file

Download the public key on the client:

```shell
mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.example.com/key.gpg -o /etc/apt/keyrings/repo.gpg
```

Then add a source file, for example `/etc/apt/sources.list.d/repo.sources`:

```text
Types: deb
URIs: https://repo.example.com/
Suites: noble
Components: main
Signed-By: /etc/apt/keyrings/repo.gpg
```

The one-line format works too:

```text
deb [signed-by=/etc/apt/keyrings/repo.gpg] https://repo.example.com/ noble main
```

### Signed-By with an embedded key

On Ubuntu 22.04, Debian 12, and newer, you can put the key directly in the
source file and skip the separate keyring. Use the armored `key.asc`. In the
`Signed-By` value, start every line with a space and write the empty line as
` .`. This command prints the key in that form:

```shell
curl -fsSL https://repo.example.com/key.asc | sed -e 's/^$/./' -e 's/^/ /'
```

Paste the output under `Signed-By:`:

```text
Types: deb
URIs: https://repo.example.com/
Suites: noble
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 xjMEawJAJBYJKwYBBAHaRw8BAQdAUWa6BPpbJn/aXaGEfPRrty8XL8+lR22JfNje
 ...
 -----END PGP PUBLIC KEY BLOCK-----
```

Ubuntu 20.04 and Debian 10 and 11 don't accept an embedded key. Use the keyring
file there.

## Logging

Each command logs to stderr with `log/slog`. Every change gets an info line
with a workdir-relative `path`:

- `init` logs `created` for each file it writes.
- `add` logs `added` or `unchanged`.
- `build` logs:
  - `moved` or `removed duplicate` for each upload, with the upload `path` and
    the pool `target`, or an error line `upload rejected` with the reason;
  - `parsed` for each package it reads;
  - `cache dropped` for each package that left the pool;
  - `created` or `updated` for `public/key.gpg` and `public/key.asc` when it
    restores the key;
  - `added by-hash`, `updated`, `removed by-hash`, and `removed stale` for
    what it changes under `dists/`;
  - one `built` line per suite.
- `deb-mirror` logs:
  - `added` or `replaced` with the pool `path` for each package it writes;
  - `mirror failed` with the upstream `filename` and the reason;
  - one `mirrored` line with the counts of added, replaced, unchanged, and
    failed packages. Its `suite` and `component` are the target values.

On error, the command logs the error once and exits with status 1.

Two commands running at the same time on one workdir aren't coordinated, so run
them one at a time.

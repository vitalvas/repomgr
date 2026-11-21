# repomgr

`repomgr` builds and signs APT repositories of `.deb` packages. It is a single
static binary that never runs external commands, so it works in a distroless
image. Repositories it builds work on Debian 10 and Ubuntu 20.04 or newer.

## Commands

Every command takes `--workdir`, the directory that holds the repository.

### Initialize a workdir

```shell
repomgr deb --workdir /srv/repo init --name "Example Repo" --email repo@example.com
```

`init` creates the workdir layout, writes `config/repo.yaml` with empty
metadata, and generates the signing key. The key is an OpenPGP v4 Ed25519 key
with no passphrase. It's stored in `config/signing.asc`, and the public half
goes to `public/key.gpg`. Running `init` again on the same workdir fails, so it
never replaces a key your clients already trust.

### Add a package

```shell
repomgr deb --workdir /srv/repo add --suite noble --component main ./ikev2-hub.deb
```

`add` reads the control data inside the package and ignores the input file
name. It validates `Package`, `Version`, and `Architecture`, then copies the
file to its pool path:

```text
pool/<suite>/<component>/<prefix>/<name>/<Package>_<Version>_<Architecture>.deb
```

`<name>` is the `Source` field, or `Package` when there's no `Source`. The
version in the file name drops any epoch. Supported architectures are `all`,
`amd64`, `arm64`, `armel`, `armhf`, and `i386`.

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
  clearsigned `InRelease`. All signatures use SHA-512.
- By-hash copies of every index, with the two previous versions kept so
  clients that fetched an older `InRelease` can still finish.

`build` signs everything in memory before it writes anything, and writes
`InRelease` last. It removes directories of suites, components, and
architectures that no longer have packages. It fails without touching
`dists/` if a pool file isn't at the path its control data gives, or if two
files share a name but differ in content.

`build` caches parsed packages in `cache/index.json` and only re-reads files
whose size or modification time changed. You can delete `cache/` at any time.

## Workdir layout

```text
<workdir>/
  config/
    repo.yaml       repository metadata
    signing.asc     private signing key, mode 0600
  cache/
    index.json      parsed package cache
  public/
    key.gpg         public key for apt
    pool/           packages
    dists/          indexes and signatures
```

Publish `public/` and keep `config/` private. The `Origin`, `Label`,
`Description`, and per-suite `Suite` and `Version` fields come from
`config/repo.yaml`; see the
[repository metadata section of the design](docs/superpowers/specs/2026-11-21-deb-repomgr-design.md#repository-metadata-file).

## Use the repository with apt

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

## Logging

Each command logs to stderr with `log/slog`. Every change gets an info line
with a workdir-relative `path`:

- `init` logs `created` for each file it writes, or `kept` for an existing
  `repo.yaml`.
- `add` logs `added` or `unchanged`.
- `build` logs:
  - `parsed` for each package it reads;
  - `cache dropped` for each package that left the pool;
  - `added by-hash`, `updated`, `removed by-hash`, and `removed stale` for
    what it changes under `dists/`;
  - one `built` line per suite.

On error, the command logs the error once and exits with status 1.

Two commands running at the same time on one workdir aren't coordinated, so run
them one at a time.

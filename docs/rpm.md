# RPM repositories

RPM repositories work on RHEL 8 or newer and compatible releases.

`repomgr rpm` builds an RPM repository from its own workdir. Packages sit in
one shared pool, and the metadata for each release and component points into
it. A workdir holds one format, so `rpm` and `deb` never share one.

## Initialize a workdir

```shell
repomgr rpm --workdir /srv/rpm-repo init --name "Example Repo" --email repo@example.com
```

`init` generates the signing key, an OpenPGP v4 Ed25519 key with no
passphrase, and stores it in `config/signing.asc`. It writes the public half to `public/key.asc` in ASCII
armor. It also creates the empty `public/x86_64/` and `public/aarch64/`
directories, which mark the workdir as an rpm workdir. `--email` is optional.
Running `init` again on the same workdir fails.

Each side refuses the other's workdir. `rpm` commands fail on a workdir with
`public/dists/` or `public/key.gpg`, and `deb` commands fail on one with
`public/x86_64/` or `public/aarch64/`.

## Add a package

```shell
repomgr rpm --workdir /srv/rpm-repo add --release 9 --component auth-51 ./pdns-5.1.0-1.el9.x86_64.rpm
```

`add` reads the package header and ignores the input file name. It copies the
file to its pool path:

```text
pool/<release>/<component>/<prefix>/<name>/<arch>/<NAME>-<VERSION>-<RELEASE>.<ARCH>.rpm
```

`<name>` is the name part of the source RPM file name. `<prefix>` is the first
letter of `<name>` in lowercase, or `lib` plus the next letter for names that
start with `lib`. The epoch isn't part of the file name.

- `--release` is a whole number of 8 or more, without leading zeros.
- `--component` matches `^[a-z0-9][a-z0-9_-]*$`.
- Supported architectures are `x86_64`, `aarch64`, and `noarch`.

`add` rejects a source RPM and a package without a source RPM tag. It also
rejects a header that repeats a tag, has an inconsistent layout, or goes over
the limits `rpm` itself enforces: 32 entries and 8 KiB for the signature
header, 65535 entries and just under 256 MiB for the main header. The signature
header must carry a SHA-256 or SHA-1 digest of the main header, and every
digest it carries must match. Packages built with older `rpm` versions carry
only SHA-1. When the package has a payload digest, `add` streams the payload
once and checks it.
A truncated or edited file fails.

`repomgr` never re-signs a package. It stores the bytes you give it.

Adding the same bytes again does nothing. Adding different bytes under a file
name that already exists anywhere in the pool fails.

## Build the metadata

```shell
repomgr rpm --workdir /srv/rpm-repo build
```

`build` writes one repository for each base architecture (`x86_64` and
`aarch64`), release, and component, under
`public/<basearch>/<release>/<component>/repodata/`. A `noarch` package goes
into both base architectures and exists once in the pool. A base architecture
with only `noarch` packages still gets a repository.

Each `repodata/` holds:

- `primary.xml.gz`, `filelists.xml.gz`, and `other.xml.gz`, named
  `<sha256>-<type>.xml.gz`.
- `repomd.xml`, which lists them.
- `repomd.xml.asc`, the armored detached signature of `repomd.xml`, made with
  SHA-256.

`build` renders and signs everything in memory before it writes anything, and
writes `repomd.xml` last. It only writes files whose content changed. A build
with no changes writes nothing. `revision` and the timestamps in `repomd.xml`
keep the time of the build that last changed the repository.

Each `repodata/` keeps the metadata files of the two previous generations, so a
client that holds an older `repomd.xml` can finish its download. `build` also
removes the release and component directories that no longer have packages for
that base architecture. It never removes `public/x86_64/` or
`public/aarch64/`, and it never touches other files in `public/`, such as the
`.repo` files you publish for clients.

`build` restores `public/key.asc` from `config/signing.asc` when it's missing
or differs. It caches parsed packages in `cache/index.json` and only re-reads
files whose size or modification time changed. You can delete `cache/` at any
time.

`build` fails without touching `repodata/` if a pool file isn't at the path its
header gives, or if two files share a name but differ in content. It also
refuses a package whose text the metadata can't hold. That covers control
characters in a text field and text that isn't valid UTF-8 after a Latin-1
conversion. `add` refuses such a package up front.

Only the XML escaping can differ from the metadata other tools write, and
clients read both forms the same way.

## Upload inbox

Instead of running `add` for each package, you can drop packages into
`upload/<release>/<component>/` and run `build`:

```shell
cp pdns-5.1.0-1.el9.x86_64.rpm /srv/rpm-repo/upload/9/auth-51/
repomgr rpm --workdir /srv/rpm-repo build
```

Before it scans the pool, `build` checks every `*.rpm` directly inside an
`upload/<release>/<component>/` directory the same way `add` does. Then:

- A package with no conflict is copied into its pool path and then deleted from
  `upload/`. It lands in the metadata of the same build.
- A package whose exact bytes are already in the pool is deleted from
  `upload/`.
- A symlink in `upload/` is rejected and stays in place.
- A package that fails a check stays in `upload/` and gets an error line. This
  covers a conflict with the pool, an invalid package, a bad release or
  component name, or a `.rpm` at any other depth. `build` still publishes
  everything else, then exits with status 1.

`build` ignores files that don't end in `.rpm`, and files and directories whose
names start with a dot. Upload to a temporary name such as `.pdns.rpm` or
`pdns.rpm.part`, then rename it once the copy is complete, so `build` never
reads a half-written package.

## Workdir layout

```text
<workdir>/
  config/
    signing.asc     private signing key, mode 0600
  cache/
    index.json      parsed package cache
  upload/
    <release>/<component>/
                    packages waiting for the next build
  public/
    key.asc         ASCII-armored public key for gpgkey=
    <name>.repo     your own dnf repo files, never touched
    pool/           packages
    x86_64/<release>/<component>/repodata/
    aarch64/<release>/<component>/repodata/
                    metadata and signatures
```

Publish `public/` and keep `config/` and `upload/` private.

## Use the repository with dnf

Add a repo file on the client, for example `/etc/yum.repos.d/example-auth-51.repo`:

```text
[example-auth-51]
name=Example auth-51
baseurl=https://repo.example.com/$basearch/$releasever/auth-51
gpgkey=https://repo.example.com/key.asc
repo_gpgcheck=1
enabled=1
```

`$basearch` and `$releasever` match the directories under `public/`, and the
last path part is the component. `repo_gpgcheck=1` checks the signature on
`repomd.xml`, which covers every package through the checksums in the metadata.
Packages that carry a vendor signature can also use `gpgcheck=1` with the
vendor key listed in `gpgkey=`.

On RHEL 8, modular filtering hides a package from this repository when an
enabled module stream ships a package of the same name. `repomgr` doesn't write
`modules.yaml`.

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
  - `created` or `updated` for `public/key.asc` when it restores the key;
  - `added` for each new metadata file, `updated` for `repomd.xml` and
    `repomd.xml.asc`, and `removed` for each metadata file that retention
    drops;
  - `removed stale` for each release or component directory it deletes;
  - one `built` line per release and component, with the package count and the
    base architectures.

On error, the command logs the error once and exits with status 1.

Two commands running at the same time on one workdir aren't coordinated, so run
them one at a time.

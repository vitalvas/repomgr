# repomgr deb-mirror: design

`repomgr deb-mirror` copies packages from a remote APT repository into the pool
of a local workdir. It selects packages with regular expressions, verifies
every file it downloads, and adds each one the same way `repomgr deb add` does.
It doesn't build indexes; run `repomgr deb build` after one or more mirror runs.

## Command

```text
repomgr deb-mirror --workdir <workdir>
  --source-repo <url> --source-suite <suite> --source-component <component>
  --target-suite <suite> --target-component <component>
  [--source-key <file>] [--force]
  [--filter-name <regexp>] [--filter-name-exclude <regexp>]
  [--filter-version <regexp>] [--filter-version-exclude <regexp>]
  [--filter-architecture <regexp>] [--filter-architecture-exclude <regexp>]
```

Example that mirrors the Salt 3006 and 3007 lines into two components:

```shell
repomgr deb-mirror --workdir /srv/repo --source-repo https://packages.broadcom.com/artifactory/saltproject-deb/ --source-suite stable --source-component main --target-suite mirrors --target-component salt-3006 --filter-name 'salt.*' --filter-version-exclude '.*~rc.*' --filter-version '3006.*'
repomgr deb-mirror --workdir /srv/repo --source-repo https://packages.broadcom.com/artifactory/saltproject-deb/ --source-suite stable --source-component main --target-suite mirrors --target-component salt-3007 --filter-name 'salt.*' --filter-version-exclude '.*~rc.*' --filter-version '3007.*'
repomgr deb --workdir /srv/repo build
```

`deb-mirror` is a top-level command with its own `--workdir`. The workdir must
be initialized: `config/signing.asc` must exist, or the command fails with
`ErrNotInitialized`. A missing trailing `/` on `--source-repo` is added.

## Behavior

The mirror is add-only. It never deletes local packages, even when upstream
drops them or they stop matching the filters. It mirrors every matching
version, not only the newest.

1. Fetch `<source-repo>/dists/<source-suite>/InRelease`. It must be a
   clearsigned message. With `--source-key`, verify the signature against that
   key and fail if it doesn't verify. Without it, read the cleartext and don't
   check the signature. Then run three checks on the `Release` text, with or
   without `--source-key`, before any index request:

   - Suite: the `Suite` field must equal `--source-suite`. A `Codename` match
     also passes, unless `Suite` starts with `<source-suite>-`. That case is a
     pocket of the same codename, such as `noble-updates` served for `noble`.
   - Freshness: `Date` is required and must not be more than 5 minutes ahead of
     the current time. `Valid-Until`, when present, must not be in the past.
     Both use RFC 1123 dates with a one or two digit day and a zone name or a
     numeric offset.
   - Rollback: `cache/mirror-state.json` maps each source repo URL, without
     its `user:password@` part, and suite to the last accepted `Date`. An older `Date` is fatal, an equal or newer one
     passes, and a missing file means no limit. A corrupt file is fatal.

   After the indexes verify and before any package download, the command
   stores the `Date` in that file. Deleting `cache/` resets the rollback check.
2. Fail if the `Components` field doesn't list `--source-component`.
3. Take the architectures from the `Architectures` field that repomgr supports
   (`all`, `amd64`, `arm64`, `armel`, `armhf`, `i386`) and ignore the rest. Fail
   if none remain.
4. For each of those architectures, fetch the first of
   `<component>/binary-<arch>/Packages.zst`, `Packages.gz`, and `Packages`
   that the `SHA256` section of `Release` lists. Skip architectures
   without a listed index for the component. Fail if no supported index is
   listed for the component. Check the downloaded file's size and SHA256
   against `Release`, then decompress it.
5. Split each index into stanzas and drop duplicates by `Filename`, because
   upstreams repeat `Architecture: all` packages in every `binary-<arch>`
   index. A stanza without `Filename`, `Size`, or `SHA256` is fatal, as is a
   repeated filename with conflicting metadata.
6. Apply the filters to the stanza's `Package`, `Version`, and `Architecture`
   fields exactly as upstream writes them. Each filter must match the whole
   field value. The version keeps its epoch, so `1:3006.0` doesn't match
   `3006.*`.
7. Compute the local pool path from the stanza with the same rules as `add`.
   If that file matches the stanza's size, SHA256, and package identity,
   count it as unchanged and skip the download.
8. If that file exists with a different SHA256 and `--force` isn't set, the
   package fails with `ErrConflict`.
9. Otherwise, download `<source-repo>/<Filename>` to a temporary file under
   `cache/`, check its size, SHA256, and package identity against the stanza,
   and add it to the target suite and component. The add parses the control
   data, checks for conflicts with the rest of the pool, writes the file
   atomically, and
   updates `cache/index.json`. The temporary file is removed on every success
   and error path. A killed process can leave a `cache/.mirror-*.deb` behind.
   It is safe to delete.
10. With `--force`, a local file at the target pool path whose SHA256 differs
    from upstream is replaced atomically by the verified upstream file. Use
    this to repair a corrupted local copy. `--force` never touches other
    suites or components: if a file with the same name and different content
    exists elsewhere in the pool, the package fails with `ErrConflict`.

Downloads run one at a time.

## Filters

Each filter is a Go regular expression that must match the whole value of the
package control field. The name filters match the `Package` field. An empty
value means no filter. Field names in the upstream `InRelease` and `Packages`, and in
package control files, are matched case-insensitively, as in deb822.

| Flag | Field | Default |
| --- | --- | --- |
| `--filter-name` | `Package` | `.*` |
| `--filter-name-exclude` | `Package` | none |
| `--filter-version` | `Version` | `.*` |
| `--filter-version-exclude` | `Version` | none |
| `--filter-architecture` | `Architecture` | none |
| `--filter-architecture-exclude` | `Architecture` | none |

A stanza passes when every include filter matches and no exclude filter
matches. An invalid pattern is fatal before any network request.

## Verification

With `--source-key`, every downloaded file is tied to the upstream signing key
through this chain:

1. The `InRelease` signature.
2. The index's size and SHA256 in `Release`.
3. The package's `Size` and `SHA256` in the index.
4. The `.deb` bytes.

Without `--source-key`, the chain starts at step 2. `--source-key` accepts an
ASCII-armored or binary public key.

## Errors

These errors stop the command before it downloads any package:

- The workdir isn't initialized.
- A filter isn't a valid regular expression. It fails before any
  request.
- The target suite or component isn't a valid name.
- The `--source-key` file can't be read or holds no public key.
- `InRelease` or an index returns an HTTP status other than 200.
- `InRelease` isn't clearsigned, or its signature doesn't verify.
- Neither `Suite` nor `Codename` equals `--source-suite`, or only `Codename`
  matches and `Suite` is a pocket (`<source-suite>-...`) of it.
- `Date` is missing, unparseable, or more than 5 minutes in the future.
- `Valid-Until` is unparseable or in the past.
- `Date` is older than the one stored in `cache/mirror-state.json`, or that
  file is corrupt.
- The component isn't listed in `Components`.
- No supported architecture is listed in `Architectures`.
- No supported index is listed, or a listed index's size or SHA256 doesn't match.
- A stanza lacks `Filename`, `Size`, or `SHA256`.

These errors fail only the package they belong to:

- The package download returns an HTTP error.
- The package size, SHA256, or identity doesn't match the stanza.
- The add fails, for example on a conflict, an invalid package, or an
  unsupported field value.

`deb-mirror` logs each package failure, keeps going with the rest, and at the
end returns `ErrMirrorFailed`, so the command exits with status 1.

## HTTP

The command uses the standard library HTTP client, which honors `HTTPS_PROXY`
and the related environment variables. Requests send `Accept-Encoding:
identity`, so the bytes that arrive match the sizes and hashes in `Release`.

Every request has a 60-second stall timer. It starts before the request is
sent and restarts on each body read that returns data. When it fires, it
cancels the request, and the error reads `no data for 1m0s`. There is no
overall timeout because packages can be large. `main` cancels the context on
`SIGINT` and `SIGTERM`.

The mirror bounds what it holds and writes:

- `InRelease` is read up to 16 MiB, and a larger body is fatal.
- An index whose `Release` size is over 256 MiB is fatal before it's requested.
  Decompression stops past 256 MiB, which is also fatal.
- Before each download, `statfs` on `cache/` must show twice the package
  `Size` plus 1 GiB free. Otherwise the package fails and the run continues.

The limits live in an unexported `MirrorOptions` field, which is zero outside
tests and then takes the defaults, so tests can shrink them.

`--source-repo` may carry credentials as `user:password@` or a token as the
user name. The client sends them as Basic auth. `debrepo.StripUserinfo` removes
the whole userinfo from every URL that goes into a log line, an error, or
`cache/mirror-state.json`. Errors from the HTTP client drop its `*url.Error`
wrapper, because that text repeats the URL with the user name.

## Logging

Each line goes to stderr through `log/slog`:

- `added` with the pool `path` for each new package.
- `replaced` with the pool `path` for each package `--force` replaced.
- `mirror failed` with the upstream `filename` and the `error`.
- One `mirrored` line at the end with `source`, `suite`, `component`, `added`,
  `replaced`, `unchanged`, and `failed`. The `suite` and `component` are the
  target values.

Packages that are already in the pool get no line of their own, so repeated
runs from cron stay quiet.

## Code layout

- `internal/debrepo/mirror.go` holds `Mirror`. It reuses `poolPath`,
  `fileSHA256`, and the add logic from `add.go`.
- `internal/pgpsign` gets `VerifyClear`, which verifies a clearsigned message
  against a public key and returns its plaintext.
- `internal/cli` gets the `deb-mirror` command. It reads the key file, passes the
  filter strings to `Mirror`, which compiles them, and logs the result.

## Testing

Tests use an `httptest.Server` as the upstream and never reach the network.
The fake upstream serves packages from `debtest.Build`, indexes in each
compression, and an `InRelease` signed with `pgpsign.Sign`. The tests cover:

- Matching packages land at their pool paths and in the cache.
- A second run downloads no packages.
- Every include and exclude filter, and the defaults.
- `Architecture: all` packages appear once.
- Unsupported architectures are skipped.
- Index preference: `Packages.zst`, then `Packages.gz`, then `Packages`.
- With `--source-key`, a valid signature passes and a wrong key or edited text
  fails. Without it, a run with a wrongly signed `InRelease` still passes, and
  a body that isn't clearsigned fails.
- Suite match on `Suite` only, on `Codename` only, and on neither.
- The pocket rule: `noble-updates` with codename `noble` fails for `noble`,
  while `noble`/`noble`, `stable`/`bookworm`, and
  `stable-updates`/`bookworm-updates` pass.
- `Date` missing, unparseable, 10 minutes ahead (fatal), and 1 minute ahead
  (passes). `Valid-Until` in the past or unparseable is fatal, and in the
  future passes. The tests inject the clock through `MirrorOptions.Now`.
- Rollback: the first run stores the date, an equal date passes, an older date
  is fatal and leaves the state, a newer date is stored, and a corrupt state
  file is fatal.
- Each fatal error in the list above.
- Package size or SHA256 mismatch and a pool conflict fail only that package,
  and the run returns `ErrMirrorFailed`.
- `--force` replaces a corrupted target file and still fails on a conflict in
  another suite.
- With `user:password@` and with a token as the user name, every request
  carries the credentials, while log lines, the state file key, HTTP status
  errors, hash errors, and connection errors never contain them.
- Limits: an `InRelease` over its cap, an index listed over its cap (never
  requested), an index of exactly the cap, and `.gz` and `.zst` indexes that
  decompress one byte over or exactly to the cap. A server that never answers
  is fatal, a package body that stalls fails that package, and a slow body
  that keeps sending passes. A package that would leave too little free space
  fails without a request.
- The CLI wires the flags, rejects a bad expression, and rejects a missing key
  file.

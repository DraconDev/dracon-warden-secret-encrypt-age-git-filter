# Changelog

All notable changes to `dracon-warden` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### v0.112.33 — 2026-07-21 — H2 follow-up: pre-push test-identity author rejection

**Operator-visible change (from `AUDIT_FULL_2026-07-21.md`, F0.1 follow-up):**

- **Pre-push hook now rejects pushes containing commits authored by test identities** (`test@test`, `test@test.com`, `test@example.com`) in the PUSHED range. The F0.1 incident (2026-07-21) showed a test writing `user.email = test@test` into a LIVE repo's config, after which the daemon committed with the poisoned identity and the poisoned commit landed on all mirrors. Historical commits outside the pushed range are unaffected. Hook diagnostics now go to stderr. 2 behavioral tests (reject poisoned author, pass trusted author).

**Tests:** dracon-warden 83 (+2). `cargo clippy --workspace --locked -- -D warnings` clean. `cargo deny check` clean.

### v0.112.32 — 2026-07-21 — audit warden batch (H8/H9 HIGH + M29-M32 MEDIUM)

**Operator-visible changes (from `AUDIT_FULL_2026-07-21.md`):**

1. **`harden_repo` no longer wipes operator `.gitignore` / `.gitattributes` content** (H8/F4.1). The surgical `replace_managed_block` (previously `#[cfg(test)]`-only) is now used in production for both files: replace only the delimited managed block, preserve everything outside it, append if absent. Verified live: `dracon-warden once` on dracon-utilities preserved the operator's nested-repo section (a 2026-06-28 harden pass had wiped the previous one, commit `3a67685f`).
2. **Whole-file-encrypted BINARY secrets round-trip as bytes** (H9/F4.2). New `decrypt_whole_file_tag` in `dracon-security`: when the entire content is one secret tag (the format used for binary files in sensitive locations), decrypt to RAW BYTES in `seal_smudge` + `decrypt_file`. The previous `String::from_utf8_lossy` path corrupted non-UTF-8 payloads (DER keys, SQLite, .kdbx) with U+FFFD, and the corruption re-encrypted into history.
3. **`allow_v1_fallback = true` policy field now works** (M29/F4.3). Wired to the runtime gate in `WardenPolicy::load` — the documented V1 (AES-CFB) migration path ("set the flag, decrypt once to re-encrypt under V2, unset") is now actually accessible.
4. **`setup-hooks --local` works** (M30/F4.4). Was `git config local core.hooksPath <dir>` (missing `--`) — always failed after the hook files were written.
5. **Filter-clean fails closed for oversized/refused inputs** (M31/F4.5). The >10 MiB and path guards previously passed the input through to git in the clean direction — the file was committed UNENCRYPTED with no warning. Now exit non-zero so git aborts the add.
6. **Pre-push hook scans filenames with spaces** (M32/F4.6). NUL-delimited iteration + `xargs -0` argument passing (the old `for f in $(git diff --name-only ...)` word-split on whitespace, silently skipping space-containing filenames).

**Architectural:**

- dracon-warden now depends on the LOCAL `src/security` crate BY PATH (`dracon-security-kit = { package = "dracon-security", version = "0.3.0", path = "src/security" }`) — previously it built the published crates.io v0.3.0, so fixes to the local source never reached the binary. The H9 fix required this.
- `dracon-warden/src/security` is now a full workspace member: `cargo test --workspace --locked` runs the security crate's ~109 tests.

**Tests:** all workspace suites green (dracon-warden 81 incl. 4 new: M29 gate wiring, M30 --local behavioral, M31 fail-closed predicate, M32 space-filename hook; dracon-security ~109 incl. 2 new: binary round-trip byte-identical, inline-tag path). `cargo clippy --workspace --locked -- -D warnings` clean (also fixed a pre-existing needless-borrow lint exposed by membership). `cargo deny check` clean.


> **Note**: prior to 0.112.12, `dracon-warden` was developed inside the
> [`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
> monorepo. Releases 0.0.0–0.112.11 are recorded in
> [`dracon-utilities/CHANGELOG.md`](https://github.com/DraconDev/dracon-utilities/blob/main/CHANGELOG.md)
> under the `dracon-warden` heading. From 0.112.12 onward, this CHANGELOG
> is the canonical record.

## [Unreleased]

## [0.112.12] - 2026-06-21

### Changed
- **Standalone repo**: `dracon-warden` is now a first-class standalone git
  repository at
  [`DraconDev/dracon-warden-secret-encrypt-age-git-filter`](https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter).
  Previously this code lived in
  [`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
  as a workspace member. Source-of-truth has moved to the standalone repo;
  future releases are cut from there via `scripts/release.sh`.
- **`scripts/release.sh`**: new per-repo release script. Same interface as
  the parent monorepo's `release.sh` (`<version> --yes [--dry-run] [--abort]`),
  scoped to the standalone repo's Cargo.toml, CHANGELOG, crates.io publish,
  and GitHub release. Each utility now releases independently on its own
  cadence.
- **Push-protected remotes**: the verbose repo name
  (`dracon-warden-secret-encrypt-age-git-filter`) is the public-facing
  identity. Local directory is `dracon-warden/` for ergonomics. The
  4-keyword description in the repo metadata ("secret, encrypt, age,
  git-filter") is the canonical public description.

### Verified
- `cargo info dracon-warden` confirms version 0.112.12 on crates.io
- `gh release view v0.112.12` (verbose repo) shows the github release
- Daemon's `dracon-sync repos` continues to see this repo and pushes to
  the 3 remotes (github + gitlab + codeberg) on its own cycle

[Unreleased]: https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter/compare/v0.112.12...HEAD
[0.112.12]: https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter/releases/tag/v0.112.12

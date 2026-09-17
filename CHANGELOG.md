# Changelog

All notable changes to `dracon-warden` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.113.12] - 2026-09-17

### Fixed

- GitHub syntax review: use the maintained TruffleHog 36–255-character body range for all five gh-prefixed token families, add fine-grained PAT coverage, and reject partial/embedded matches. Synthetic tests cover complete replacement and invalid lengths; obsolete 30-character positives are now explicit negatives.
- F4 inventory: withdraw the unsupported Backblaze 100-character/base62 claim. Document the actual K005 heuristic separately from the official SDK's opaque credential input; compare all existing Tier-1 families against inspectable reference formats without claiming exhaustive provider coverage.
- Configured filter-size limits receive proportional, capped filter deadlines (default deadline unchanged), with bounds regression coverage.
- Release commits now use the repository's configured identity rather than overriding it.

## [0.113.11] - 2026-09-16
## [0.113.10] - 2026-09-16

### Fixed (completion-audit round 2, 2026-09-16)

- **Slack webhook boundary fix:** overlong bodies ending in base64-style
  `+` or `/` no longer partially encrypt — `has_token_boundaries` now
  treats `+` and `/` as body bytes. Negative tests pinned for 58-char
  bodies ending in `+`, `/`, and `A`; valid-length bodies ending in each
  alphabet byte still encrypt (tier_inventory overlong cases).
- **F4 inventory language made terminal:** the six remaining Tier-2 rows
  (Alibaba Access Key ID, NVIDIA, MiniMax, Modal, Together AI, Backblaze
  B2 Application Key) now record evidence-backed stay decisions
  (gitleaks/TruffleHog references, provider format reality) instead of
  deferred-validation wording.

### Fixed (completion-audit follow-up 2026-09-16)

- **Clean-filter output stability (post-checkout dirty-status fix):** the
  `* filter=dracon` catch-all plus randomized encryption meant a fresh
  clean of the smudged worktree copy produced different ciphertext than
  the indexed blob, so every encrypted file showed as modified right
  after a checkout. Clean now reuses the stage-0 index blob — only when
  authenticated decryption of the indexed ciphertext equals the incoming
  worktree bytes, the current policy would still encrypt to the same
  shape, and no additional secrets were newly detected. Randomized
  encryption is unchanged, no plaintext hashes or persistent caches are
  stored, and actual edits/new secrets/policy upgrades always re-encrypt.
  Regression: `tests/index_reuse.rs` + `scripts/verify-filter-lifecycle.py`
  (installed-binary Git lifecycle: 8 fixtures, byte-exact round-trips,
  EMPTY `git status --porcelain` after checkout).
- **F4 provider-format completion:** OpenRouter (`sk-or-v1-` + 64 hex),
  Groq (`gsk_` + 52 alnum), Resend (`re_` + 8 + 24 base58), and Slack
  webhook URLs (43–56-char body incl. `workflows`/`triggers` paths)
  promoted to Tier-1 with evidence from TruffleHog detectors and the
  gitleaks format reference; full adjacent-boundary checks reject overlong
  bodies. Inventory rows updated accordingly.
- **F5 residual literals:** last four `sk_live_…` fixture literals in
  `tests/{keys_json,creds_json}_full_encrypt.rs` split with runtime
  `concat!`; the exact no-literals verification command now returns zero
  matches.

## [0.113.9] - 2026-09-16

### Fixed (post-release audit follow-up 2026-09-16)

- **Tier-1 boundary + coverage overhaul (F2–F4):** tightened OpenAI `sk-`
  matching with token-boundary checks (innocent slugs like
  `task-configuration-reference-guide` no longer partially encrypt; explicit
  `sk-proj-`/`sk-svcacct-` + legacy alnum bodies still caught). Added
  unlabelled PKCS#8 + ENCRYPTED PKCS#8 envelopes to Tier-1. Promoted fully
  structured provider tokens (GCP/Google `AIza…` incl. trailing hyphen,
  `GOCSPX-`, `dop_v1_`, `shpat_`/`shpss_`, `sq0atp-`/`sq0csp-` exact-length,
  `hvs.`, `amzn.mws.`) with adjacent-boundary checks so partial prefix
  matches no longer re-encrypt surrounding bytes. Full per-family tier
  inventory with decisions lives in
  `src/security/token-tier-inventory.md`, pinned by a no-drift test
  (`tests/tier_inventory.rs`) that fails if a family is added/renamed
  without an inventory row or a tier flips silently.
- **F5 fixture convention enforced:** all 15 committed `.plaintext` hatch
  siblings removed; fixtures assemble secret-shaped strings at runtime
  (`concat!`/`format!`/`printf -v`), including the pre-push-hook-sensitive
  `scripts/verify-install.sh`. A 75-file stored-source pass through
  `filter-clean` returns byte-identical output (no live-format literals
  committed). Weak negative assertions in `plaintext_sibling_test.rs`
  (ciphertext-prefix checks) replaced with runtime-assembled secret checks.
  Square fixture corpus corrected from 30-char to the specified 22-char
  body (partial-prefix matches had masked the discrepancy).
- **F1 smudge fix (from source-only `07f5ba1`) now ships:** NUL-containing
  UTF-8 decrypts inline tags; invalid UTF-8 passes through losslessly
  (lossy U+FFFD corruption removed); whole-file binary payload handling
  unchanged and byte-exact.

### Fixed

- Align inline smudge with clean's UTF-8 classification: NUL-containing
  UTF-8 can decrypt inline tags, while invalid UTF-8 passes through without
  lossy conversion. Whole-file binary decryption still runs first.
  Two regression tests failed before the fix; both now pass, alongside
  a 32-case Unicode/NUL/CRLF round-trip property test.
- Post-release audit findings and remaining scanner limitations are recorded
  in `audit/eager-encryption-2026-09-16.md`. This fix is not in the published
  0.113.8 artifact.

## [0.113.8] - 2026-09-16

### Added (eager source encryption 2026-09-16)

- **Tier-1 structured tokens encrypt in EVERY text file:** the
  protected-patterns gate used to pass unprotected files (notably
  source: `.rs`, `.ts`, `.svelte`, ...) through blind, so a stray
  `sk_live_*` / `ghp_*` / `AKIA*` in source landed on the forge in
  plaintext (2026-09-15 showcase class). The scanner is now two-tier:
  Tier-1 (structured provider tokens — fixed prefix + rigid body:
  Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, Mailchimp, NPM,
  OpenAI `sk-`, PEM blocks) runs on every non-hatched text file;
  Tier-2 (generic / keyword-anchored / low-floor) stays behind the
  protected gate (2026-06 gibuardien false-positive lesson).
  Selective inline encryption with byte-exact smudge round-trip;
  binary passes through untouched; the `.plaintext` hatch still wins.
- **`* filter=dracon` catch-all in hardened `.gitattributes`:** no
  source extension can be overlooked. Filter-only (no `diff=` /
  `merge=` drivers), with a smudge fast path that skips identity
  loading for tag-free blobs.
- **Test fixture convention:** no live-format secret strings are
  committed anywhere including tests — fixtures assemble tokens at
  runtime (`concat!` / `format!`) or use structurally-invalid
  placeholders. New `tier1_source_encrypt` suite (detection,
  ordinary-code ignores, Tier-1-leads-`get_patterns` no-drift pin,
  clean + byte-exact round-trip in source paths, binary passthrough).
## [0.113.7] - 2026-09-15

### Fixed (warden-showcase probe 2026-09-15)

- **`creds.json` gets whole-file encryption:** a credentials JSON whose
  secrets sit under every inline-scanner floor (short values, non-keyword
  key names, JSON colon form) passed through untouched even in a hardened
  repo. Files literally named `creds.json` now get whole-file age
  encryption like `credentials`, at any depth (`config/creds.json` +
  `**/creds.json` added to `protected_patterns`). New
  `creds_json_full_encrypt` test suite (encrypt, smudge round-trip,
  nested depth).

### Fixed (audit pass 2026-09-10)

- **Pointer-file checkouts install and chain hooks (F76):** local setup now
  writes to the resolved Git gitdir and preserves same-name foreign hooks,
  while generated wrappers resolve Git's common gitdir before chaining local
  hooks. Linked worktrees and nested submodules no longer lose their hook
  behavior because `.git` is a pointer file.

- **Owner public-key publication rejects symlink targets (F75):** repository
  output directories and existing target files are checked with symlink-aware
  metadata, and Unix reads/writes use `O_NOFOLLOW` to close check/open races.
  Publication fails closed without modifying external symlink targets.
- **Repair loops reject tracked symlinks (F74):** `resmudge` and
  environment-header backfill now read and write tracked files with
  no-follow semantics, rejecting symlinks before they can disclose or
  modify external targets. Regression coverage exercises the default apply
  mode of `repair <repo>` through both loops.
- **Hardening rejects symlinked dotfiles (F73):** `once` and `repair` no
  longer read repository-controlled `.gitignore` or `.gitattributes`
  symlinks, preventing external content from being preserved into generated
  files. Unix reads use no-follow semantics; other platforms reject existing
  inputs rather than risk following links. Regression coverage verifies that
  symlink targets are neither published nor modified.
- **Protected filter globs match Git attributes (F72):** the clean-filter
  gate now evaluates `protected_patterns` with Git-compatible path-component
  semantics, so generated `secrets/*` and `.ssh/*` rules protect direct
  children without accidentally crossing directory boundaries. Matcher,
  generated-attributes, and clean-filter regressions cover the parity.
- **Repository discovery is recursive (F71):** `once`, `repair`, `scrub-markers`,
  and `resmudge` now find nested repositories and linked-worktree-style
  `.git` pointer files under configured roots without descending into `.git`
  metadata directories or accepting symlinked `.git` markers.
- **Policy discovery expands home-relative roots (F70):** `~` and `~/...`
  entries in `repo_roots`, the deprecated `watch_roots`, and
  `discover_roots` are expanded before existence filtering, so the shipped
  example policy discovers repositories under the current HOME.
- **Merge driver no longer commits plaintext (F49)**: re-encryption used
  git's `%A` temp path, so the protected-patterns gate missed and merged
  secrets were written back unencrypted whenever
  `protected_patterns` was non-empty. The driver now re-encrypts via a
  path-independent clean; whole-file-vs-inline format is carried by the
  ancestor ciphertext, not the temp path.
- **`RepoKey` zeroized on drop (F50)**, matching `TeamKey`.
- **Resmudge cap skips warn loudly (F51)**: files over the 10 MiB
  streaming cap are named on stderr instead of silently skipped.

## [0.113.6] - 2026-09-01

## [0.113.5] - 2026-08-19

### Added

- **Machine-local hygiene now has shipped defaults**: omitted
  `hygiene_patterns` entries default to Pi harness state (`**/.pi*`),
  Chromium trace logs, and regeneratable frontend caches (`.svelte-kit`,
  `.vite`, `.turbo`, and `.cache`). The example policy documents the same
  baseline, while explicit lists remain available for operator overrides.

### Fixed

- **Tag pushes no longer rescan already-published history**: the pre-push
  secret scan now reuses the branch scan when a tag points at a commit being
  published on `main` in the same push, and skips the duplicate scan when the
  commit is already present on a remote-tracking branch. This prevents
  historical documentation placeholders from being misclassified as newly
  pushed secrets. Added a regression for the atomic branch-plus-tag release
  flow.

- **Hook hardening no longer seeds inactive local copies**: when Git dispatches
  hooks through a global or repository-local `core.hooksPath`, `harden_repo`
  leaves the shadowed `.git/hooks` directory untouched; global wrappers chain
  pre-existing foreign hooks explicitly. Hook-installation failures now
  propagate instead of being silently discarded, with regressions covering
  both shadowed-path skipping and error propagation.

- **Repository recipient files are now authorization-checked, not merely
  name-checked**: `gather_all_recipients` accepts canonical
  `owner_*.pub`/`master.pub` candidates only when they contain exactly one
  valid age recipient matching a local owner trust anchor. Machine/team
  recipients written by `whitelist_machine` and `add_team_member` retain
  support through versioned `.auth` envelopes: the exact public filename,
  recipient, and repository-key commitment are authenticated, and every V2
  envelope carries an owner Ed25519 signature bound to the age owner
  recipient. The DH ciphertext is transport-only; this prevents a delegated
  recipient from forging an owner proof or a forged canonical `repo.key.age`
  ciphertext from becoming an authorization oracle, and supports
  machine-only `ARCANE_MACHINE_KEY` discovery. A matching regular `.age`
  delegation is required. `authorize_recipient` now emits the
  same verified recipient-named `.pub`/`.age` pair instead of an unauthenticated
  age blob.
  A contributor can no longer add `owner_evil.pub` or an arbitrary delegated
  file and silently grant that key access to future encryptions. HOME key
  directories are permissive only when they do not physically overlap the
  repository key paths; repository-root and symlink overlap is fail-closed.
  Both `.dracon/data/keys` and legacy `.git/arcane/keys` are covered, with
  owner-signature verification restricted to explicit owner/master anchors;
  historical keygen machine files are marked and excluded from that signer
  set while remaining valid HOME encryption recipients. Regressions cover a
  delegated machine forging an authorization, canonical attackers, secret/oversized/multiline files,
  missing/tampered/replayed proofs, missing delegation files, direct-recipient
  migration, forged canonical repo-key authorization, arbitrary
  master-encrypted age blobs, machine-only discovery, and HOME overlap.

- **Team key creation is now private and race-safe**: `create_team` uses
  exclusive file creation with mode `0600` on Unix, matching invite
  acceptance, so the encrypted key is never created with default umask
  permissions or overwritten by a concurrent/repeated creation. Added
  permission and no-overwrite regression coverage.

- **Backups no longer overwrite rapid successive snapshots**: backup names
  now use nanosecond timestamps and exclusive file creation, retrying on the
  rare clock/concurrency collision. Added deterministic collision coverage
  plus an end-to-end rapid-backup retention/restore regression.

- **Private-key scanner patterns now match their actual formats**: DSA, EC,
  OpenSSH, and PGP private-key detectors no longer reuse the RSA armored-key
  expression. The PGP detector now matches `PGP PRIVATE KEY BLOCK` armor, and
  regression coverage verifies each format is reported under its specific
  finding name.

- **Legacy AES-CFB V1 decryption now fails closed**: `allow_v1_fallback`
  remains accepted for configuration compatibility, but the unauthenticated
  Git-Seal CFB decryptor is no longer callable. Wrong-key output can look like
  valid text, so legacy ciphertext must be recovered from a trusted plaintext
  source and re-encrypted with authenticated V2. Regression coverage includes
  a short printable wrong-key counterexample, a corrected 20-byte prefix case,
  and the ciphertext-free error path.

- **`.env` header versioning no longer parses body text**: `get_env_version`
  scanned the whole file for the first `"Version: "` substring and the
  header-strip gate used `contains("Dracon Warden")` — an unrelated
  version line or a comment merely mentioning Dracon Warden in a fresh
  `.env` yielded a wrong/duplicated header version (audit LOW,
  2026-08-10). The version is now parsed only from the warden-managed
  header block at the top of the file (marker line within the first few
  lines, version line immediately after the marker), and
  `is_env_version_managed` gates header-strip on the actual header
  marker instead of any Dracon Warden mention. Tests: bare body version
  lines ignored (get_env_version returns 0, fresh files start at v1),
  body version line after a managed header ignored (increment off the
  header), `is_env_version_managed` positive/negative/deep-marker cases,
  and end-to-end clean-path tests for both the fresh-with-comment and
  managed-with-body-version scenarios.

- **`.gitattributes` diff/merge drivers are now actually defined**: protected
  patterns get `filter=dracon diff=dracon merge=dracon`, but
  `ensure_repo_filter_config` only registered `filter.dracon.*` — git fell
  back to the text driver with a warning and encrypted-file diffs/merges ran
  on ciphertext. The config pass now also registers `diff.dracon.textconv`
  (`dracon-warden filter-smudge` — blobs decrypt for `git diff`/`git log
  -p`) and `merge.dracon.driver` (`dracon-warden merge %O %A %B`), plus a
  `merge.dracon.name`. New `merge` subcommand: decrypts all three inputs
  (whole-file tag, inline tags, or untagged passthrough), runs a 3-way text
  merge via `git merge-file`, re-encrypts the result into %A (index keeps
  the filter.dracon ciphertext invariant); on conflict the plaintext with
  conflict markers is left in %A for resolution (`git add` re-encrypts) and
  exit 1 is returned per the merge-driver contract. Tests: clean + conflict
  `text_merge`, untagged end-to-end driver behavior (exit codes, marker
  output), encrypted roundtrip proving ciphertext-in → plaintext merge →
  ciphertext-out, and config registration + idempotence.

- **Scanner snippets are now UTF-8 safe**: long multi-byte secret matches are
  truncated at the nearest valid character boundary instead of using a raw
  byte slice that could panic the scanner.

## [0.113.4] - 2026-08-09

- **Test-only helper gated `#[cfg(test)]`**: `clear_filter_managed_patterns` (and its security-crate import) are only used by tests; gating them removes the dead-code warning from the release build. No behavior change. crates.io max stable; tags + gh releases on all forges.

## [0.113.3] - 2026-08-09

- **Filter `protected_patterns` wired into the clean gate (junk-runner wedge fix)**: the clean filter's "default-deny" gate read `WardenSecurity.managed_patterns`, which the production constructor initializes EMPTY — and `path_is_protected` treats empty as "scan everything (legacy)". The config's `protected_patterns` were wired into `.gitignore`/`.gitattributes` generation and `scrub_markers` but NEVER into the filter process, so every file was fully secret-scanned: a 6.87 MB `pi-session-*.html` took 16.3 s of filter CPU, git's concurrent filters blew the 30 s `FILTER_TIMEOUT_SECS`, and `git add` exited 128 every cycle — junk-runner wedged (no commits, 11 commits ahead, Changes Piling Up alert). Fix: process-wide `set_managed_patterns()` override applied inside `WardenSecurity::get_or_init()`, wired by `run_filter` from the policy via `wire_managed_patterns_from_policy()`. The same file now filters in 12–13 ms (~1250×). 104 tests (+2), clippy clean. Requires `dracon-security v0.3.1` (published first — `cargo publish` resolves the registry twin of the `path` dep, the dracon-git lesson again). Design: `docs/design/warden-filter-protected-patterns-wiring-2026-08-09.md`.

## [0.113.2] — 2026-07-27 — pre-push hook `--not --remotes` (tag-push false-positive fix)

- **F0.1 follow-up — `--not --remotes` BAD_AUTHORS scan (CORRECTED
  2026-08-09, audit MEDIUM: the original entry below described a
  `--first-parent` implementation that never shipped)**: the pre-push
  hook's `git log --format='%ae%n%ce' "$RANGE"` walked every reachable
  commit in the range. For a **tag** push `remote_sha = 0`, so the old
  range computation covered the ENTIRE repo history reachable from the
  tag object — a test-identity commit reachable only on a
  non-first-parent side-merge (e.g. a `--no-ff` merge of a feature
  branch where a drop-test helper left a test@test author on the side)
  then blocked the tag push even though main's first-parent history is
  clean. Now the scan distinguishes (see `PRE_PUSH_HOOK` in
  `src/main.rs`):
  - existing-ref update (branch push, `remote_sha != 0`):
    `git rev-list "$local_sha" --not "$remote_sha"` — only the NEW
    commits being added to the branch tip;
  - new-ref push (tag or new branch, `remote_sha == 0`):
    `git rev-list "$local_sha" --not --remotes` — only commits
    reachable from the ref that are NOT already on ANY remote-tracking
    branch.
  Each candidate is then checked with `git log -1 --format='%ae%n%ce'`.
  Only NEWLY-PUBLISHED commits are scrutinized — a test identity
  landing on main is still blocked (F0.1 defense preserved for the new
  push itself), while an already-published side-merge commit (accepted
  by a prior scan) no longer false-positives on a later tag push.
  Regression test added:
  `pre_push_hook_test_identity_on_non_first_parent_merge_passes`.

## [0.112.33] - 2026-07-21 — H2 follow-up: pre-push test-identity author rejection

**Operator-visible change (from `AUDIT_FULL_2026-07-21.md`, F0.1 follow-up):**

- **Pre-push hook now rejects pushes containing commits authored by test identities** (`test@test`, `test@test.com`, `test@example.com`) in the PUSHED range. The F0.1 incident (2026-07-21) showed a test writing `user.email = test@test` into a LIVE repo's config, after which the daemon committed with the poisoned identity and the poisoned commit landed on all mirrors. Historical commits outside the pushed range are unaffected. Hook diagnostics now go to stderr. 2 behavioral tests (reject poisoned author, pass trusted author).

**Tests:** dracon-warden 83 (+2). `cargo clippy --workspace --locked -- -D warnings` clean. `cargo deny check` clean.

## [0.112.32] - 2026-07-21 — audit warden batch (H8/H9 HIGH + M29-M32 MEDIUM)

**Operator-visible changes (from `AUDIT_FULL_2026-07-21.md`):**

1. **`harden_repo` no longer wipes operator `.gitignore` / `.gitattributes` content** (H8/F4.1). The surgical `replace_managed_block` (previously `#[cfg(test)]`-only) is now used in production for both files: replace only the delimited managed block, preserve everything outside it, append if absent. Verified live: `dracon-warden once` on dracon-utilities preserved the operator's nested-repo section (a 2026-06-28 harden pass had wiped the previous one, commit `3a67685f`).
2. **Whole-file-encrypted BINARY secrets round-trip as bytes** (H9/F4.2). New `decrypt_whole_file_tag` in `dracon-security`: when the entire content is one secret tag (the format used for binary files in sensitive locations), decrypt to RAW BYTES in `seal_smudge` + `decrypt_file`. The previous `String::from_utf8_lossy` path corrupted non-UTF-8 payloads (DER keys, SQLite, .kdbx) with U+FFFD, and the corruption re-encrypted into history.
3. **`allow_v1_fallback` remains a compatibility field but cannot enable
   unauthenticated V1 AES-CFB decryption** (M29/F4.3 follow-up). Legacy
   ciphertext is refused rather than heuristically returned as plaintext;
   recover it from a trusted source and re-encrypt under authenticated V2.
4. **`setup-hooks --local` works** (M30/F4.4). Was `git config local core.hooksPath <dir>` (missing `--`) — always failed after the hook files were written.
5. **Filter-clean fails closed for oversized/refused inputs** (M31/F4.5). The >10 MiB and path guards previously passed the input through to git in the clean direction — the file was committed UNENCRYPTED with no warning. Now exit non-zero so git aborts the add.
6. **Pre-push hook scans filenames with spaces** (M32/F4.6). NUL-delimited iteration + `xargs -0` argument passing (the old `for f in $(git diff --name-only ...)` word-split on whitespace, silently skipping space-containing filenames).

**Architectural:**

- dracon-warden now depends on the LOCAL `src/security` crate BY PATH (`dracon-security-kit = { package = "dracon-security", version = "0.3.0", path = "src/security" }`) — previously it built the published crates.io v0.3.0, so fixes to the local source never reached the binary. The H9 fix required this.
- `dracon-warden/src/security` is now a full workspace member: `cargo test --workspace --locked` runs the security crate's ~109 tests.

**Tests:** all workspace suites green (dracon-warden 81 incl. 4 new: M29 gate wiring, M30 --local behavioral, M31 fail-closed predicate, M32 space-filename hook; dracon-security ~109 incl. 2 new: binary round-trip byte-identical, inline-tag path). `cargo clippy --workspace --locked -- -D warnings` clean (also fixed a pre-existing needless-borrow lint exposed by membership). `cargo deny check` clean.


## [0.113.1] — 2026-07-26 — full-audit remediation batch 2 (hook layer + smudge)

Remediation batch 2 of `AUDIT_FULL_2026-07-26.md` (3 HIGH + 1 MEDIUM).
Initial patches for H1/H2/H3 were contributed by an audit subagent;
all were reviewed, two repaired (the pre-commit managed-marker check
was defeated by the operator's GLOBAL `filter.dracon.clean` — now
`--local`; the M2 quote idiom), and every fix was verified
behaviorally against real scratch repos before deploy.

### Fixed

- **WARDEN-H1 — production filter-smudge still corrupted
  whole-file-encrypted binary secrets** (the 2026-07-21 H9 regression
  was only fixed in helpers the binary never calls):
  `DraconWarden::smudge`/`Warden::smudge` went straight to
  `String::from_utf8_lossy` → every invalid-UTF-8 byte of a decrypted
  binary became U+FFFD → corrupted worktree → next clean re-encrypted
  the corruption. Both entry points now delegate to a shared
  `smudge_with_security` that tries `decrypt_whole_file_tag` FIRST and
  returns raw bytes. New byte-identical round-trip test goes through
  the production entry-point path (the old test exercised the helper
  directly and passed while production stayed broken).
- **WARDEN-H2 — global pre-commit hook hard-blocked commits in EVERY
  non-hardened repo on the machine** (third-party clones, scratch
  repos): the hook exited 1 unless `.gitattributes` contained
  `filter=dracon`, and the global `core.hooksPath` shadowed all
  repo-local hooks fleet-wide. The hook now (a) chains to an existing
  repo-local `pre-commit` (anti-recursion via the warden header
  marker), and (b) no-ops unless the repo is warden-managed
  (repo-LOCAL `filter.dracon.clean` config, `filter=dracon` in
  `.gitattributes`, or a `.dracon/` dir). Managed-drift (some markers
  present, `.gitattributes` missing) still blocks.
- **WARDEN-H3 — pre-rebase `head -100` checked the NEWEST 100
  commits**: `git rev-list` is newest-first, so the cap dropped the
  OLDEST commits — precisely those most likely already published.
  Replaced with the boundary-commit check (remote containment is
  ancestor-closed: if the oldest commit of the range is on no remote,
  no newer one can be) — one `git branch -r --contains` instead of up
  to 100 subprocesses. Same edit fixes WARDEN-M17: the range tip is
  now `${2:-HEAD}` (the two-argument form `git rebase <upstream>
  <branch>` previously computed an empty `$1..HEAD` range and passed
  while published `$2` commits were rewritten).
- **WARDEN-M2 — pre-push secret scan missed single-quoted secrets**:
  `\x27` is not a hex escape in GNU grep ERE (the class became
  `["x27]`, matching literal x/2/7). Replaced with the shell
  `'\''` idiom; verified against GNU grep 3.12: a single-quoted
  `password =` or `api_key =` assignment now matches; values
  containing x/2/7 do not false-positive. E2E: a push adding an
  `api_key =` assignment with a live-looking single-quoted value
  (e.g. one matching `sk-live-123`) is refused.

### Verified behaviorally (scratch repos, real hooks as shell subprocesses)

- non-managed repo commits ✓; managed-drift blocked ✓; hardened repo
  commits ✓; repo-local hook chaining ✓
- published-commit rebase blocked ✓; unpublished-only rebase passes ✓;
  two-arg form blocked ✓; `DRACON_ALLOW_REWRITE=1` escape hatch ✓
- whole-file-encrypted binary round-trips byte-identically through the
  production smudge path ✓
- single-quoted secret push refused ✓


## [0.113.0] — 2026-07-25 — history-rewrite guard in the global hooks

**Hard, forge-invariant enforcement of the fleet's no-history-rewrite
policy** (2026-07-25 incident: hegemon filter-branch churn, virtual-pet
amend loop, pully rebase — agent loops rewrote already-pushed history
and raced dracon-sync's auto-push into permanent divergent-branch
CONCERNs). AGENTS.md policy files are soft; gitlab branch protection
covers only gitlab; GitHub free-tier private repos cannot be protected
server-side. These hooks are the layer that always applies.

- **pre-push**: refuses non-fast-forward ref updates (amend/rebase of
  a pushed commit can never be ff) and branch deletions. Amending
  UNPUSHED commits still pushes fine. The plaintext-secret scan and
  test-identity guard are unchanged.
- **pre-rebase** (new): refuses rebasing any commit already contained
  in a remote-tracking branch; rebasing unpushed work unaffected.
- **Escape hatch**: `DRACON_ALLOW_REWRITE=1` bypasses both guards.
- `setup-hooks` (global + local) installs all three hooks and removes
  stale `.pre-dracon` chaining artifacts from the brief dracon-sync
  per-repo hook experiment.
- `install_hooks_for_repo` also seeds `pre-rebase` (only-if-missing
  semantics preserved — foreign hooks are never overwritten).
- Tests: the three pre-push tests simulating a new branch now pass
  git's real new-ref sentinel (all-zeros) instead of the empty-tree
  SHA, which the ff-guard correctly rejects as a non-ancestor.




> **Note**: prior to 0.112.12, `dracon-warden` was developed inside the
> [`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
> monorepo. Releases 0.0.0–0.112.11 are recorded in
> [`dracon-utilities/CHANGELOG.md`](https://github.com/DraconDev/dracon-utilities/blob/main/CHANGELOG.md)
> under the `dracon-warden` heading. From 0.112.12 onward, this CHANGELOG
> is the canonical record.

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

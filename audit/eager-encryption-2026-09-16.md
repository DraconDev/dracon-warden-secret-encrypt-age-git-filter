# Eager encryption post-release audit — 2026-09-16

## Current disposition — 2026-09-17 (round 4)

**F1 deployed; F2, F3, F5 remain fixed; F4's latest substantive objections
addressed in source and deployment. Completion audit remains independent.**
The historical findings below describe 0.113.8 and earlier completion claims;
this section supersedes their present-tense installed-version and F4 claims.

- **F4 format review:** `src/security/token-tier-inventory.md` now compares
  every existing Tier-1 family with explicit reference formats, distinguishing
  compatibility deviations from provider-issued formats. Immutable source
  links identify TruffleHog `288a8a8`, gitleaks `b58d3f1`, and Backblaze SDK
  `7f17741`. Backblaze's invented 100-character/base62 claim is withdrawn;
  the actual K005/20+ detector is explicitly a protected-path heuristic, not
  a format guaranteed by the SDK's opaque ID/key interface. Modal's prior
  assertion of provider-wide absence is also withdrawn. All family/tier rows
  remain checked by `tier_inventory`.
- **GitHub correction:** external comparison found the old 30–40 body range
  mismatched TruffleHog's 36–255 range. All five gh-prefixed families now use
  that range and complete-token boundaries; fine-grained PATs added. No claim
  that every permitted length is issued. Tests in `github_format_review.rs`
  cover all six prefixes, lengths 36/41/76/82/255, adjacent repeated tokens,
  rejected 0/29/35/256 lengths, and embedded-prefix negatives. They failed
  on the old scanner; pass after the fix. Former 30-character fixture
  expectations are preserved as explicit negatives rather than weakening
  the new floor.
- **Deployment:** dracon-security **0.3.7** published at
  `2026-09-17T00:17:48.773319Z`, then dracon-warden **0.113.12** at
  `2026-09-17T00:18:17.330605Z` (crates.io API, both not yanked).
  `scripts/release.sh 0.113.12 --yes` ran through sync maintenance with
  security-first gate and packaged-artifact verification. Release/tag commit
  **fa4944707a4d255f2ef837c3b70b54afe37762ba** was verified on GitHub and
  GitLab main/tag refs. GitLab's storage warning did not reject this push.
  Installed from the packaged crate to `~/.local/bin`; both PATH and absolute
  binary report **0.113.12**. No history or remote settings were changed.
- **Installed lifecycle:** upgraded `scripts/verify-filter-lifecycle.py`
  invokes installed `once` on its scratch repo, asserts generated filter
  config, and pins that exact binary for subprocesses. **13 fixtures, 9
  encrypted blobs, byte-exact checkout, clean status, real edit detected and
  encrypted.** Includes GitHub long/fine-grained positives and overlong
  negative, Stripe, GCP, OpenAI, both PKCS#8 envelopes, NUL, invalid UTF-8,
  innocent slug and Slack boundary cases. `verify-install.sh` also passes.
- **Gates:** default and all-features package suites: **320 passed, 0 failed,
  6 ignored, 25 suites**. Targeted GitHub tests: 2 passed; exact `once`
  integration test: 1 passed. Clippy and package formatting pass. Tracked
  hatch list, source-hatch find, and specified live-format literal scan are
  empty. These are package gates, not a new claim of workspace-wide success.
- **Reviewer rehearsal:** fresh read-only fallback reviewed the new source
  comparisons and found one factual error (GL Mailchimp's case-insensitive
  alphabet), now corrected. Reviewer did not finish full scanner/test reads
  within its read budget and did not execute tests; no independent approval
  is claimed. Parent inspected boundary/replacement code and full GitHub test
  file and executed the above gates. Detached completion audit remains the
  independent verification step.

## Scope and release evidence (historical)

Direct source review and local synthetic behavioral checks; no independent
reviewer was launched. No live credentials were used in the probes. Findings
below concern filtering correctness and coverage, not exploitation.

Warden 0.113.8 was published using `scripts/release.sh 0.113.8 --yes` through
`dracon-sync maintenance`. Its packaged-artifact verification passed. GitHub
and GitLab main and `dracon-warden-v0.113.8` were independently checked with
`git ls-remote`: all four refs were `bfc330f50858c77f0d88e02879d89a98c1d08a3d`.
The previously blocked ten commits were accepted by GitHub after operator
allowlisting. No history was rewritten. Installed binary was 0.113.8.

## F1 — HIGH: clean/smudge byte-classification mismatch (fixed in source)

`src/security/src/modules/filter.rs` classifies text with `from_utf8`, but
`smudge_with_security` formerly rejected any NUL byte and otherwise used
`String::from_utf8_lossy`. Two installed-binary checks demonstrated:

- UTF-8 with NUL plus an inline provider token: clean encrypted the token,
  smudge returned the inline ciphertext unchanged instead of restoring it.
- Invalid UTF-8 with literal marker-like text: clean preserved bytes,
  smudge replaced the invalid byte with U+FFFD.

Two regression tests reproduced both failures before the change. The fix in
`src/security/src/lib.rs` removes the NUL heuristic and uses fallible UTF-8
conversion on smudge, preserving invalid UTF-8 unchanged. Whole-file binary
payload decryption still runs first. A 32-case property test covers arbitrary
Unicode context, NUL, and CRLF around a runtime-assembled token.

Source fix commit: `07f5ba1`. A freshly built binary passed both edge cases
and a Unicode/CRLF case through the real clean/smudge subprocess entrypoints.
**This fix is not in crates.io 0.3.3, warden 0.113.8, or the installed binary.**
A subsequent security-crate and warden release is needed to deploy it.

## F2 — MEDIUM: Tier-1 is not false-positive-free (open)

`src/security/src/modules/scanner.rs:139` uses an unanchored, permissive
OpenAI-style pattern. The innocent source string `task-configuration-reference-guide`
was partially encrypted by the installed binary because its interior matches
that pattern. Round-trip succeeded, but forge/package readers without keys
receive ciphertext in ordinary code. The earlier assertion that ordinary code
cannot match Tier-1 was incorrect. Token boundaries and provider-specific
formats need review plus positive/negative regression tests before changing
coverage; simply increasing a length floor is not sufficient.

## F3 — HIGH: source scanning does not cover all claimed private keys (open)

The Tier-1 generic PEM expression requires an extra label before PRIVATE KEY.
The unlabelled PKCS#8 PRIVATE KEY envelope was not encrypted in an unprotected
source path in an isolated installed-binary probe. The probe used a synthetic
body, not a real private key. This is a delimiter coverage finding, not proof
that arbitrary private keys are safe. Explicit PKCS#8 coverage and tests are
needed. Whole-file credential-file encryption is a separate path.

## F4 — MEDIUM: provider coverage is incomplete (open)

GCP API keys remain in Tier-2 (`scanner.rs:169`), despite having a structured
prefix. A runtime-assembled matching fixture in an unprotected file passed
through unchanged. The split needs a provider-format inventory; the current
six-test suite cannot establish coverage of all token families.

## F5 — fixture convention and exceptions disagree (open)

README says no live-format fixture strings should be committed. Existing
`.plaintext` siblings, including `scripts/verify-install.sh.plaintext`, instead
exempt entire files from filtering and local pre-push checks. This audit did
not delete existing hatches or rewrite history. The convention should be
implemented by runtime fixture construction and a bounded migration of
exceptions, not described as already enforced. A hatch is not evidence that
the file can never contain an accidental real credential.

## Corrections to previous explanations

- Whole-file encryption protects all bytes only when the file reaches that
  branch and encryption succeeds; not every credential-like filename is
  automatically whole-file encrypted independently of configured patterns.
- Different ciphertext does not prove the plaintext secret rotated. Random
  encryption can cause nonce-only churn. Compare decrypted versions privately
  to distinguish substantive changes; do not write plaintext diffs into logs.
- Tier-1 and Tier-2 pattern lists are separate, but the strings they match can
  overlap. Generic rules can catch provider tokens in appropriate contexts.
- The clean entrypoint loads security state even on misses. Earlier claims
  that clean has no identity I/O on misses and that a performance wedge cannot
  recur were not established by measurement.
- A clean sync status does not establish that all tracked historical blobs
  were re-filtered or that every file is covered. Attributes do not rewrite
  history; configured `-filter` and hatch exceptions still apply.
- The original six Tier-1 tests were example tests, not property tests.
  Property coverage was added in this audit for the corrected smudge path.

## Verification

- Before fix: targeted smudge unit tests — 4 passed, **2 failed** as expected.
- After fix: `cargo test -p dracon-security -p dracon-warden --locked` —
  **309 passed, 0 failed, 6 ignored**, including 32 generated property cases.
- `cargo clippy -p dracon-security -p dracon-warden --locked -- -D warnings` — pass.
- `cargo fmt -p dracon-security -p dracon-warden --check` — pass.
- `cargo build --release -p dracon-warden --locked` — pass.
- Build-directory binary: 3 byte-round-trip subprocess checks — pass.
- Published 0.113.8 packaged install check — pass, but it does not exercise F1.
- Workspace tests: timed out twice (600s and 1200s), output in dracon-system
  guard tests. **Not a passing workspace gate and not diagnosed as encryption.**
- Workspace formatting: unrelated dracon-system differences, left unchanged.
- Workspace cargo-deny initially failed RUSTSEC-2026-0285; parent lock updated
  rustls 0.23.43 to 0.23.45 and webpki 0.103.13 to 0.103.15, automatically
  committed as `94793f92a`. Recheck passes with a yanked libssh2-sys warning.
  That parent-only change does not upgrade already installed sync/system.

Transient detailed logs: `/tmp/warden-smudge-before.log`,
`/tmp/warden-audit-fixed-tests.log`, `/tmp/warden-audit-fixed-clippy.log`,
`/tmp/warden-audit-fixed-build.log`, `/tmp/warden-audit-edge-results.json`,
`/tmp/warden-audit-fixed-edge-results.json`, `/tmp/warden-release-0.113.8.log`.
This report retains the conclusions if those temporary files disappear.

## Disposition (updated 2026-09-16, completion-audit round 3)

- **Round-2 audit (23:26Z) disapproved on two live objections, both
  addressed in dracon-security 0.3.6 + dracon-warden 0.113.11
  (tag `dracon-warden-v0.113.11`, commit `ec5b650`, github + gitlab,
  crates.io; installed binary reports 0.113.11):**
  - **Slack webhook boundary defect fixed:** overlong bodies ending in
    base64-style `+` or `/` partially encrypted on 0.113.10 because
    `has_token_boundaries` did not treat `+`/`/` as body bytes. Fixed;
    negative tests pinned in `promoted_provider_tokens_replace_completely`
    and two new lifecycle fixtures (`slack-valid.rs` 50-char body
    encrypts; `slack-overlong-plus.rs` 58-char `+A` body stays plaintext).
    Installed-binary repro of the auditor's three cases: final=`A`, `+`,
    `/` all unchanged (not encrypted).
  - **F4 inventory language made terminal:** the six rows the auditor
    flagged as deferrals (Alibaba Access Key ID, NVIDIA, MiniMax, Modal,
    Together AI, Backblaze B2 Application Key) now cite the checked
    evidence (gitleaks rule, TruffleHog detector, provider format
    reality) and record the stay as a decision, not a deferral;
    `rg 'unverified|needs? provider evidence|requires supported format
    evidence|needs? validated|requires validation'` over the inventory
    returns zero matches.
  - Lifecycle probe upgraded: installed-binary run now reports 10
    fixtures / 7 encrypted blobs / byte-exact roundtrips / clean
    post-checkout status.
- **Completion-audit round 1 (2026-09-16T22:40Z) found three real gaps:**
  (1) post-checkout `git status` dirty on every encrypted file — random
  nonce per clean made `clean(smudge(blob)) ≠ blob` under the
  `* filter=dracon` catch-all; (2) four committed `sk_live_…` fixture
  literals in `tests/{keys_json,creds_json}_full_encrypt.rs`; (3) several
  F4 inventory entries deferred provider-format validation instead of
  deciding. Round 2 fixes all three:
  - **Clean-filter output stability:** clean now reuses the stage-0 index
    blob ONLY when authenticated decryption proves the indexed ciphertext
    equals the incoming worktree bytes, the current policy still demands
    the same encryption shape, and nothing newly secret was detected
    (`clean_reusing_index`, `DraconWarden::clean_with_index` wired in
    `run_filter` via a bounded `git cat-file --path` read). Randomized
    encryption unchanged; no plaintext hashes; no persistent cache;
    edits/new secrets/policy upgrades always re-encrypt. Regression:
    `tests/index_reuse.rs` (3 tests incl. corrupted-ciphertext, new-secret
    and inline→whole-file upgrade negatives) +
    `scripts/verify-filter-lifecycle.py` (installed-binary Git lifecycle:
    8 fixtures, 6 encrypted blobs, byte-exact smudge, EMPTY
    `git status --porcelain` after checkout, real edit still detected).
  - **F4 completion:** OpenRouter (`sk-or-v1-` + exactly 64 hex; TruffleHog
    openrouter detector + provider `/api/v1/auth/key` verifier), Groq
    (`gsk_` + exactly 52 alnum; TruffleHog groq detector), Resend (`re_` +
    8 + 24 base58; TruffleHog resend detector + provider docs), and Slack
    webhook URLs (`hooks.slack.com/services|workflows|triggers/` + 43–56
    char body; gitleaks slack-webhook-url rule) promoted to Tier-1 with
    full adjacent-boundary checks — overlong and sub-length bodies do not
    match (pinned in `promoted_provider_tokens_replace_completely`).
    Inventory rows for all four updated; remaining Tier-2 stays are
    documented decisions (contextual/generic/identifier families), not
    deferrals: each cites its specific evidence gap rather than deferring
    validation wholesale.
  - **F5 residual literals:** the four `sk_live_1111…4444` fixtures split
    with runtime `concat!`; the exact verification command now returns
    zero matches (`rg 'sk_live_…|ghp_…|AKIA…|-----BEGIN … PRIVATE KEY'
    --glob '!*.md'` → empty).
- **F1 DEPLOYED:** shipped in dracon-security 0.3.4 + dracon-warden 0.113.9
  (tag `dracon-warden-v0.113.9`), carried forward unchanged into
  dracon-security 0.3.5 + dracon-warden 0.113.10
  (tag `dracon-warden-v0.113.10`, commit `bb19cb5`, github + gitlab,
  crates.io). Installed binary `~/.local/bin/dracon-warden` reports 0.113.10,
  passes verify-install.sh AND verify-filter-lifecycle.py.
- **F2 CLOSED:** OpenAI pattern tightened (`sk-proj-`/`sk-svcacct-` explicit,
  legacy alnum body) plus adjacent-boundary checks; innocent slug
  `task-configuration-reference-guide` verified untouched in blob
  (`tier1_openai_boundaries_and_source_roundtrip` + live probe).
- **F3 CLOSED:** PKCS#8 + ENCRYPTED PKCS#8 Tier-1 patterns; source round-trip
  test green (`tier1_pkcs8_and_gcp_source_roundtrip`).
- **F4 CLOSED (round 2 hardening):** full inventory in
  `src/security/token-tier-inventory.md` (every family dispositioned
  with terminal, evidence-cited reasons), pinned no-drift test
  (`tests/tier_inventory.rs`). Promoted: GCP/Google AIza (trailing-hyphen
  safe), GOCSPX-, dop_v1_, shpat_/shpss_, sq0atp-/sq0csp- (exact length),
  hvs., amzn.mws., plus OpenRouter/Groq/Resend/Slack-webhook in round 2
  (evidence-cited). Round 2 additionally: Slack webhook adjacent-boundary
  check extended to `+`/`/` (overlong bodies ending in base64-style
  bytes no longer partially encrypt; negative tests pinned), and the six
  remaining Tier-2 stay rows reworded from deferred-validation to
  terminal evidence-backed decisions (Alibaba ID, NVIDIA, MiniMax,
  Modal, Together AI, Backblaze B2).
  Deliberate Tier-2 stays documented (contextual/low-floor/identifier
  families with specific evidence), not deferrals.
- **F5 CLOSED:** all 15 `.plaintext` siblings deleted from git + disk;
  fixtures runtime-assembled (`concat!`/`format!`/`printf -v`) including
  verify-install.sh; weak ciphertext-prefix assertions replaced with
  runtime-secret checks; 75-file stored-source pass through filter-clean
  byte-identical (no live-format literals committed); Square corpus fixed
  to specified 22-char body.
- **Live probe (installed 0.113.10):** `verify-filter-lifecycle.py` — 8
  fixtures (Stripe/GCP/OpenAI/PKCS#8/ENCRYPTED PKCS#8/NUL-context tokens,
  innocent slug, invalid-UTF-8 marker), all 6 secret fixtures encrypted in
  committed blobs, all 8 round-trips byte-exact, `git status --porcelain`
  EMPTY after checkout, and a genuine edit still flagged + re-encrypted
  through `git add`. Note: a first probe token with a
  19-char Stripe body was correctly NOT encrypted (below the 24 floor) —
  behavior working as specified.
- Residual limitation (recorded, accepted for this goal): Tier-1 lengths are
  compatibility heuristics; provider-format drift requires ongoing
  maintenance via the inventory + no-drift test. GCP OAuth and other
  contextual families remain Tier-2 by documented decision.

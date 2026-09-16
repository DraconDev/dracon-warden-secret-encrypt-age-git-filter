# Eager encryption post-release audit — 2026-09-16

## Scope and release evidence

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
OpenAI-style pattern. The innocent source string `ta[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBjL0ZYWTZkcUFUclpJaFJ1emlRSmRoMUF3SEdSOG95REgvZFQzUUFpdGswCjV0ZFIvTDRrekxRTy9jdjFZSk16Y1dGVlEyOUpzbndKbVdMcy9NM0JSQUUKLT4gWDI1NTE5IElVNGpIbUlUdngwTlNrNmt1N2Vmc0UveEtRZHhUZENTTHdtbFZ3ZURXVzQKWE95Mm1JN1NuZy9DMlgyYTMzNUhtNWx2Q3hoOUxkSjNKWitueUdMZTg4OAotPiBYMjU1MTkgWGFkYVVqSzJyVURkS1dGbGd0UDRKRk5ReHo0WG1xTldabDJNZGlwSUNRdwpsWmN0ZnhucmgxbXhua1JMR2JqWWJVVFdIUU42NHc3MVU0STM3UEVWcnNRCi0+IFgyNTUxOSBCT0VBbTJ3ZGVKdGo5UmxhekFDMlpvZ04zdlV3dHJpcFlaNVYvNkNyWGlRCkczTXlEV3dta1dpcG5oWkFRNHR1TUlEMGRZMWhtV3czbVB2cGJQdEpHcE0KLT4gWDI1NTE5IHluZjc3b0RkNWtRYlovZHNKOG9iSWNIdHJwOUFFZFVHaGVHTjhBZFh1VGcKNFhVVUpXYzZ5K3dmek1icVA5RDEwTThVRkNsdm1UT1FtdEhzMDlucDRLQQotPiBtZGVVSy5DNi1ncmVhc2UKRWpXSklnQ3ZVRzN1cnJENWlwbEJmVEMzN1Z2WUFIRzFoL21jbzlEOE9ETUFNQ1hqS2hZaFRtNWFuOU5GcGY2Sgo1b2VHZk9USDNtWEVSbnlRT0xxRlpoNUVYTFdaS0tydUtMWHc2eWhscFk1YnJhVEhFRHc5bHIrRAotLS0gWWFCc1V0RHIzMStzUzNmZ3VsQW5vL3lDWGlrOFRVbzNoTnY4YUtGM2dZYwqYEZOM2yPkvKVsLLo1ZDVl2MKJuuQze+i6oyOVgBQjXszm8K0WBeE0WPmj0e6xtby+qRFmTzISHzJekghgNwpN]`
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

## Disposition

0.113.8 publication is verified; a clean audit verdict is NOT warranted.
F1 is repaired in source and tested, deployment pending. F2–F5 remain explicit
follow-up work. No unrelated repository cleanup, history rewrite, or blanket
fixture exemption was performed during this audit.

# Preserve the OpenAI boundary in the pre-push hook

## Failure and authorization

Fleet-convergence investigation found dracon-strategy's push retry budget
exhausted by Warden's added-blob scan. Its downloaded public GOV.UK guidance
page contains an SVG URL ending in `govuk-icon-mask-<64-hex-digest>.svg`.
The hook interprets the `sk-<digest>` substring inside `mask-` as an OpenAI
credential. The same bytes occur in unpublished historical commits, so changing
only the current file would not cure the refusal. History rewriting and hook
bypasses remain prohibited.

The operator explicitly authorized a **precision repair** after seeing this
redacted diagnosis, requiring real-key detection (including binary-safe scans)
to remain enforced, with no filename exemptions, allowlists or history rewrites.
This authorization extends only to this demonstrated detector defect; it does
not grant trust, ownership or general security-policy changes.

## Root cause and repair

The core scanner already begins its OpenAI pattern with a word boundary. The
hook's POSIX ERE transliteration omitted that boundary deliberately under an
assumption that false positives only delay pushes. In practice a public filename
can stop all autonomous publication for an otherwise safe repository.

Preserve that existing scanner boundary using `(^|[^[:alnum:]_])` in the hook
shape and its checked-in generated template. Keep the other provider patterns,
key-length rules, added/diff/binary scans and security-hook ordering unchanged.
No GOV.UK-specific rule or pathname-based exception is added.

The portable boundary consumes a delimiter rather than using a lookbehind.
Canonicalize that one delimiter out of matching OpenAI tokens before exact-match
review checks and binary parent comparisons. Otherwise an unrelated punctuation
change around an inherited binary token could spuriously appear to introduce a
new credential. Existing reviewed-match receipts are not extended or changed.

## Verification so far

- The public-asset behavioral regression fails against the original hook with
  its exact added-file plaintext-secret refusal; it is not a vacuous fixture.
- The repaired hook passes the public-asset test but still blocks a separate
  synthetic credential added to that very same HTML file.
- Legacy, project and service-account synthetic keys are rejected both when
  added and when changed, in quoted text and NUL-delimited binary payloads.
- An inherited binary token whose surrounding delimiter changes stays inherited.
- A scanner/ERE parity regression covers asset substrings, real keys at start,
  quoted/colon/space/NUL boundaries and non-boundary word prefixes.
- The targeted hook tests pass 3/3; the scanner parity test passes 1/1; the full
  Warden binary suite passes 223/223 (includes the targeted hook tests).

Raw receipts are retained in dracon-sync's
`evidence/fleet-convergence-2026-10-23/checks/`.
At that investigation stage, workspace qualification and production installation
were still pending. The later fleet qualification passed the workspace suite,
Clippy, release build and dependency check. The qualified Warden executable is
now installed with a backup; before that replacement all three global hook
scripts already matched its renderer byte-for-byte, so the installation did not
change hook files or settings. See dracon-sync's
`evidence/fleet-convergence-2026-10-23/qualification-checkpoint.md` and its retained
installation receipt. Strategy retry/publication remains unproven; test success
and installation are not convergence claims.

# Platform encryption-scope mismatch — root repair

## Demonstrated failure

The unchanged platform pre-commit hook rejected auth-api, billing-api and
email-api `.env.dev` staged blobs because they were not whole-file encrypted.
Each path had filter=dracon, no plaintext sibling, and the configured filter
returned its staged bytes unchanged. The live policy's DECIDE 4 comment explains
why credential names were removed from protected_patterns: that list also emits
ignore negations and therefore made new credentials automatically stageable.
Manual attributes retained encryption declarations, but the filter's independent
protected-pattern gate no longer honored that intended encryption scope.

## Durable separation

`encryption_only_patterns` now adds filter scope and attribute declarations but
never ignore negations. Default empty preserves previous behavior, including
legacy empty-protected-list scan-everything. Validation rejects exact plaintext
contradictions. Input-size guards, marker repair and smudge scope use the same
effective encryption scope. Existing media and plaintext precedence is unchanged.

The live rollout opts in only these demonstrated paths:
- apis/services/auth-api/.env.dev
- apis/services/billing-api/.env.dev
- apis/services/email-api/.env.dev

No credential pattern was restored to protected_patterns. No .gitignore or
.gitattributes publication, plaintext hatch, hook bypass, manual staging,
manual commit or manual push was used for rollout.

Qualification also reproduces/fixes .env ciphertext churn from managed header
creation/increment: reuse may match the authenticated generated managed-header
representation for .env files, while edits to the environment body or trailing
whitespace remain visible. Existing real version headers intentionally change
through the original cleaner; preservation compares the actual environment
body byte-exact after stripping only that recognized managed header. The first
candidate check incorrectly expected the entire header to remain byte-identical
and aborted before live changes; it was not counted as a pass.

## Evidence

Unit regressions show encryption-only scope leaves the generated ignore block
byte-identical, applies full .env encryption, preserves legacy defaults, and
rejects plaintext conflicts. Reuse regressions cover both headerless and already
managed env worktrees, real body edits, whitespace edits and policy upgrades.
All four unmodified workspace gates pass on unchanged source-input inventories
(v2-workspace-gates.json), using a dedicated target directory.

A copied-index positive control encrypts only the original three staged bodies,
proves body preservation and repeat-clean ciphertext stability, then passes the
original pre-commit hook. The old real-index diagnostic remains a failed result.
Qualified Warden release 39db331b735b4c71a25e27e2d7c90cf171301406c3b1ca786f5ea207f0fed370
was atomically installed with binary/policy backups. The daemon independently
replaced the three canonical staged blobs with whole-file tags. A later
unaltered copied-index invocation of the original hook passes in 7.8s, with no
errors (deployed-original-hook.json). Environment values were not printed or
persisted in evidence.

The next live report records platform publishing with three commits ahead;
a concurrent-index/parent-change deferral is also retained in the journal.
This is progress, not all-remote or clean-idle proof. Doomtap's four NEW QA paths,
browser's genuine real-feed evidence failure, strict staged-count cap migration
preconditions, and canonical-writer preservation remain unresolved.

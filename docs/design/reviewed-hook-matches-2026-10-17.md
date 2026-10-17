# Content-bound review receipts for non-secret hook matches — 2026-10-17

## Authorization and scope

The operator explicitly authorized correcting these verified false positives
with regression tests, guarded pushes, and no blanket file/path exemptions.
The global pre-push hook had blocked dracon-sync (30 ahead) and daemon-home
(21 ahead). Both histories must remain forward-only.

Read-only dry-run pushes reproduced the refusals on storage.test.mjs and
bin/runner.bundle.mjs. Inspection found one deliberately synthetic fixture
and SDK object-property reads, not credentials. No live credential values
were printed or recorded.

## Reviewed receipts

Each entry binds an entire blob SHA-256 to an individual regex-match SHA-256.
The receipts are versioned in the hook template, not mutable repository
configuration or worktree hatch files. Paths below identify evidence only;
paths confer no permission. The hook logs each accepted receipt to stderr.

| Full blob SHA-256 | Individual match SHA-256 | Review |
|---|---|---|
| f8687f3a17de5d4b236770e5860aed778480e3885f63c4b8942eb1cecc77ca4a | 9e0bc72796a817546301febd8583d0a7929c3114bde9e9dcdf8ea562aa61fee7 | storage.test.mjs synthetic fixture, explicitly not a real credential |
| 04839542aab3443cb43c7949d92472124c794aaabf64084c617a83ab07092556 | 8bca1bb2c590d8da610b1f5991a27cf8f598a17ba3e913c52b06f1b968d8ce73 | source runner bundle, SDK property read |
| 04839542aab3443cb43c7949d92472124c794aaabf64084c617a83ab07092556 | ec8b975e7d58592b7739c81b1549fd472c8174fc03e2a6f88f5ded441eb7cf98 | source runner bundle, SDK property read |
| 04839542aab3443cb43c7949d92472124c794aaabf64084c617a83ab07092556 | 5a1e908a7dee00419725c2ed891fa753ec55b6b73a4d45d492ce9fad3c403ff0 | source runner bundle, SDK property read (two occurrences) |
| f1d0ff1fcb8b82d9bb3d835b07393f7cb94dca40c50dfba4136b847240b88612 | 8bca1bb2c590d8da610b1f5991a27cf8f598a17ba3e913c52b06f1b968d8ce73 | deployed runner bundle, same SDK expression |
| f1d0ff1fcb8b82d9bb3d835b07393f7cb94dca40c50dfba4136b847240b88612 | ec8b975e7d58592b7739c81b1549fd472c8174fc03e2a6f88f5ded441eb7cf98 | deployed runner bundle, same SDK expression |
| f1d0ff1fcb8b82d9bb3d835b07393f7cb94dca40c50dfba4136b847240b88612 | 5a1e908a7dee00419725c2ed891fa753ec55b6b73a4d45d492ce9fad3c403ff0 | deployed runner bundle, same SDK expression (two occurrences) |

Historical Git blob IDs: a9bd439dbf46c86cbd6c2083156cff29e5ed3c19,
487ca4f65acaae1c7c12a8bb435ff5a5172bd537,
e18506fd894f7ba2f62afe766ab56a1ba69179ec, respectively.

## Boundaries

No file, extension, directory, executable or whole-blob exemption. No regex
relaxation, secret-filter bypass, hooksPath override, plaintext sibling,
history rewrite or credential privilege change. Unknown matches still
block even in a blob with an approved match. Changing any byte invalidates
the receipt: a rebuilt bundle needs fresh review, deliberately. This bounded
review mechanism is preferable to guessing whether arbitrary JavaScript
expressions or arbitrary test literals are safe. It is not an automatic
credential classifier, nor permission to approve future candidates.

Binary PEM handling, provider-token rules, modified-text added-line scans,
local hook chaining and history guards are unchanged. The existing binary
parent-match residual remains. Hashing/tool failures refuse the scan.

## Tests

`pre_push_review_receipt_binds_blob_and_individual_match` uses a temporary
repository and a test-only rebound blob digest. It proves acceptance and
loud logging for the approved pair, refusal after any blob change, and
refusal of an additional unapproved match even when the blob is bound.
The production receipts remain the seven reviewed pairs above.

`cargo test -p dracon-warden --locked pre_push_`: 36 passed, zero failed.
Full qualification and live push outcomes are recorded separately after
deployment. A passing dry run alone does not establish remote convergence.

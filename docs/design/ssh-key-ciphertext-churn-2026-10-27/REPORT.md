# Repeated dracon-home GitGuardian alerts — repaired cause

## Observed

Gmail's inbox contained repeated GitGuardian threads for DraconDev/dracon-home,
mostly Generic High Entropy Secret incidents. One opened thread linked commits
7d7abf15 and 55f21121. Both replace the same 16 SSH-key files with one encrypted
line per file. Private in-memory comparisons established that all 16 files in
both commits are age envelopes and decrypt to identical plaintext. No key
plaintext was printed, written to evidence, or sent to another service.
This establishes ciphertext churn in the sampled alerts, not that every
historical incident in this repository is harmless.

## Root cause and repair

An inline PEM scanner encrypts the PEM block but leaves its final newline
outside the tag. That representation also matches whole-file tag recognition,
whose binary-safe smudge intentionally ignores exterior newline artifacts.
The index-reuse comparison therefore saw 398 decrypted bytes versus 399
worktree bytes for the sampled micro3 key. It rejected reuse and generated
fresh randomized encryption on every sync pass. The secret was unchanged,
but Git and GitGuardian repeatedly saw new high-entropy strings.

The reuse check now permits authenticated inline-text reconstruction when the
newly cleaned representation has exactly the same exterior bytes. It still
rejects real content edits, added/removed whitespace, plaintext indexed input,
newly detected unencrypted secrets, and whole-file policy upgrades that move
the newline inside the encrypted payload. The first patch exposed an existing
missing-newline false-reuse branch; the additional exterior-layout condition
closes that branch too. Failed controls remain in the session record.
No key file, security rule, GitGuardian setting or notification filter changed.

## Qualification and deployment

The new synthetic-PEM regression failed before the repair and passes afterward,
including whitespace/content/whole-file-upgrade negative cases. Read-only
candidate checks reused authenticated indexed ciphertext for all 16 real paths.
All four unmodified workspace gates pass with identical source-input manifests
before/after; raw outcomes are in workspace-gates.json. Builds use a dedicated
persistent target directory, not the live daemon helper target. The earlier
/tmp frozen snapshot disappeared before this work; no result was inferred from
that missing artifact.

The qualified Warden binary was atomically installed with a retained backup;
deployment.json binds both hashes. No daemon restart, manual commit, manual
push, history rewrite, producer shutdown or hook bypass was performed.

After installation, four normal-Git observations over 105 seconds show zero
changed key paths and zero key-changing commits, while HEAD continues advancing
on unrelated eligible work. See live-post-deployment-window.json. This is a
bounded successful runtime observation, not a promise that all future emails
stop immediately: already published historical ciphertext and notification
backlogs remain. Historical incidents were not blanket-dismissed.

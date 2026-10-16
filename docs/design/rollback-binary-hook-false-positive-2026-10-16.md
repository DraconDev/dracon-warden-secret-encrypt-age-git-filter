# Rollback binaries falsely classified as private keys — 2026-10-16

## Evidence and corrected diagnosis

The user reported `.dracon` RETRYING with 21 unpushed commits and `doomtap`
UNKNOWN with one untracked file. Read-only triage found the latter already
being committed by its live loop/daemon; its edits were not touched.

Running the installed pre-push hook locally with the actual HEAD and
origin/main ref tuple (no network, no bypass) returned 1 and named:
`backups/ui-delay-20261016-155232/dracon-sync` (added-file binary scan).
The rollback binaries were introduced by the preceding UI/lifecycle deployment
and auto-committed into the watched daemon-home repository. Six matches in
Warden and one in Sync were PEM header labels, not serialized private-key
material. Matching bytes were not printed or included in evidence.

This corrects the preceding UI investigation's attribution to an existing
secret refusal on events.jsonl. A changing event log does not establish that
it caused a hook rejection. The actual refusal names rollback executables.

## Fix and safety boundary

The hook retains its exact provider-token/assignment expression and its
conservative text-header rule. Binary blob scans distinguish PEM vocabulary
from armored key material: header plus adjacent base64 body is rejected,
including one-line armor, CRLF and legacy encryption metadata. NUL boundaries
are not joined. No filename, executable, ELF, path or artifact hash is exempt.

Added and modified blobs use the same matcher; a missing/unreadable blob
fails closed. Existing published-blob and parent-match semantics are unchanged.
The existing parent-match residual still applies to binary key material
(see the Tier-2 residuals document); this fix does not claim to close it.

Future UI deployment rollback binaries go under
`~/.local/state/dracon/rollback-binaries`, outside daemon-home source. Targeted
ignore patterns in daemon-home cover future copies at the old UI backup paths.
Already tracked binaries and rollback copies are retained; no history rewrite,
index removal, file deletion, hooksPath bypass or plaintext sibling was used.
Operator event-log and ledger edits were preserved and committed by the daemon.

## Verification and deployment

- `cargo test -p dracon-warden --locked pre_push_`: 35 passed, zero failed.
  Tests include compiled labels, labels followed by another NUL-separated
  literal, real-shaped body, same-line body, CRLF/legacy metadata, bare text
  marker, and newly introduced material in a modified binary. Existing binary
  provider-token and history-guard tests still pass.
- Full workspace tests, release build, Clippy with `-D warnings`, and deny pass.
  Logs: `docs/evidence/rollback-hook-2026-10-16/`.
- Atomic install via `dracon-sync maintenance -- bash
  dracon-warden/scripts/deploy-rollback-hook-fix-2026-10-16.sh`; binary and
  original pre-push retained outside daemon-home. Global hooks installed using
  Warden's ordinary setup command, retaining enforcement and local chaining.
- Installed Warden SHA-256:
  `bc1a81ee8b6288433d9f496bd74fd8654cf3d15931b7aaa12a8d0592c5ee3657`.
- The exact formerly failing local hook invocation returns 0 after installation.
- `dracon-sync repair stuck-unstuck /home/dracon/.dracon` used only AFTER the
  cause was fixed; normal guarded fast-forward push to origin succeeded:
  `4fb623263d..0980eb4d0f`. No force or guard overrides. The daemon then resumed
  committing the accumulated event/ledger and ignore changes; newly ahead
  commits are subsequent work, not the original frozen 21-commit backlog.

Warden is invoked as a Git filter/hook helper, not a daemon service; replacing
it atomically affects subsequent invocations without a Sync restart. Sync and
system guard stayed active; maintenance always resumed.

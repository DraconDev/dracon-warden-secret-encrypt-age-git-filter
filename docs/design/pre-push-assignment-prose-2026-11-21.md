# Pre-push false positive: prose quoting an empty assignment — 2026-11-21

## Symptom

`dracon-utilities/dracon-sync` could not publish. Five commits were ahead of
`origin/main`, and every push was refused by the machine-global Warden
pre-push hook:

```
⛔ /home/dracon/Dev/dracon-utilities/dracon-sync pin 849e4531 refused by the local pre-push hook
```

The hook's own message narrowed it to one file:

```
⚠️  Possible plaintext secrets detected in added file 2026-11-20-231438-reading-this-table.txt (binary-safe scan).
```

That file is a pasted terminal transcript. It is not a credential store, and
`git show` finds nothing resembling a live key in it.

## Root cause

The hook's quoted-assignment alternatives were:

```
password\s*=\s*["'\''][^|"'\''][^"'\'']*[[:alnum:]][^"'\'']*["'\'']
secret\s*=\s*["'\''][^|"'\''][^"'\'']*[[:alnum:]][^"'\'']*["'\'']
api_key\s*=\s*["'\''][^|"'\''][^"'\'']*[[:alnum:]][^"'\'']*["'\'']
```

Two properties combine badly:

1. The value class `[^"'\'']` permits **whitespace**, so the "value" can span
   an arbitrary run of prose between two quotes.
2. The only content requirement is **one** `[[:alnum:]]` character anywhere
   inside that span.

The transcript quotes an earlier browser-extensions-shared incident. That
incident's text contains an ad-block filter rule with an **empty** `api_key=`
value:

```
||challenge.seyra.online/challenge.js?api_key=
```

The quote after `=` is the ad-block rule's own delimiter, but the scanner read
it as the opening quote of a value, swallowed the next sentence, and closed the
match on the apostrophe in "I'm":

```
api_key=",. I'
```

The extracted "credential" is the three characters `. I'`. Nothing was
secret; the file was never a risk. The push was refused anyway, and because
the hook scans the whole pushed range, the refusal blocked **every** commit
queued behind it — the repository was unpublishable until the scanner changed.

## Why this is a hook defect, not a content problem

The Rust core scanner in the same crate disagrees with the hook. Its
`Generic API Key` pattern has always required a value that is
**whitespace-free** and at least 20 characters:

```
(?i)(?:api[_-]?key|apikey).{0,10}[=:].{0,5}["'][^\s"\[]{20,}["']
```

The same file therefore passes the core scanner and fails the hook. Two lanes
of one security product must not disagree about whether a blob is clean, and
the hook — the lane that can strand a repository — was the wrong one.

## Fix

The quoted-value class in all three alternatives now excludes whitespace:

```
password\s*=\s*["'\''][^|"'\''][^[:space:]"'\'']*[[:alnum:]][^[:space:]"'\'']*["'\'']
```

Applied identically to (a) the checked-in `SECRET_RE` line in the
`PRE_PUSH_HOOK` template and (b) the test-only `HOOK_ASSIGNMENT_ALTERNATIVES`
render, so `pre_push_hook_secret_re_matches_token_shape_source` keeps them in
step.

Deliberately **not** changed:

- The one-alphanumeric content requirement. Keeping it means the hook still
  catches short quoted secrets (a keyword assignment with a short quoted value)
  that the core scanner's
  20-character floor would miss. The whitespace ban alone is what separates a
  credential from prose.
- Any provider-token shape, any receipt, any path exemption, any history. No
  byte of history was rewritten; the refusal was removed rather than worked
  around.

## Evidence

Before/after, running the installed hook against the real unpublished range
in `dracon-sync` (`origin/main` → `HEAD`):

| case | old hook | new hook |
| --- | --- | --- |
| transcript `2026-11-20-…reading-this-table.txt` | exit 1 (`possible plaintext secrets`) | exit 0 |
| transcript `codex-session-01a1fb3d-…md` | exit 1 (`possible plaintext secrets`) | exit 0 |
| whole unpublished branch | exit 1 | exit 0 |

Negative controls, both hooks, on a throwaway repo:

| content | old | new |
| --- | --- | --- |
| an AWS-style access-key ID assigned to `api_key` | blocked | blocked |
| a short quoted password value | blocked | blocked |

Both refusals above come from provider-token shapes and the unchanged
one-alphanumeric assignment rule, not from the prose case that was removed.

Regression coverage in `src/tests.rs`:

- `pre_push_hook_ignores_prose_quoting_an_empty_assignment` — the incident
  shape passes; a real quoted `password` assignment added in the same file
  still blocks.
- `pre_push_hook_ignores_unpaired_assignment_quote`,
  `pre_push_hook_blocks_password_secret_api_key_double_quoted_branches`,
  `pre_push_hook_secret_re_matches_token_shape_source` — unchanged behavior.

Warden suite: 263 unit + 21 + 2 + 4 integration tests pass. Workspace
`cargo test --workspace --locked` passes; `cargo clippy --workspace --locked -- -D
warnings` is clean; `cargo deny check` reports advisories/bans/licenses/sources
ok.

## Rollout

1. Build and install the binary (`target/release/dracon-warden`), keeping the
   previous binary and all four installed hook files in
   `~/.local/state/dracon/rollback-binaries/warden-hook-<stamp>/`.
2. `dracon-warden setup-hooks --global` rewrites `~/.config/git/hooks/pre-push`
   from the new template. `core.hooksPath` is unchanged.
3. Re-probe the refused ranges with the installed hook (table above), then
   `dracon-sync repair stuck-unstuck` for the affected repos so the daemon
   resumes pushing, then `dracon-sync sync-now <repos>`.

A hook-only install is not a release: this fix reaches other machines through
the next `dracon-warden` release and a `setup-hooks` run there.

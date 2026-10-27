# Pre-push fail-closed repair was being silently reverted — root cause and fix

Status: repaired, gated and DEPLOYED. Live hook verified fail-closed and stable.

## Demonstrated failure

On 2026-10-27 the fail-closed pre-push scan checks (`66c6d4d`, `d68a654`) were
added to `PRE_PUSH_HOOK` and reproduced-correctly against the fail-open
installed hook: `reproduce-prepush-io-failopen.py` refused the simulated
Git-scan failure against the candidate and returned `fail_open_reproduced:
true` against the installed one.

While re-checking that repair the live global hook was found in the FAIL-OPEN
state again, and it flipped back and forth:

| observation | pre-push sha256 (first 16) | `refusing push` checks |
| --- | --- | --- |
| fail-closed, present at 17:24 | `d122d8c10c2bec46` | 7 |
| fail-open, observed 19:50:32 | `1eaadcf344d11a19` | 0 |
| fail-closed again, 19:51 | `d122d8c10c2bec46` | 7 |

Two independent writers were doing it:

1. **The installed binary regenerates the OLD hook.** The live
   `~/.local/bin/dracon-warden` is the 09:58 deployment
   (`39db331b…0fed370`), which predates the fail-closed template. Running
   `setup-hooks` from it emits `1eaadcf3…` (`hook-generated-by-installed-binary.pre-push`),
   and `reproduce-prepush-io-failopen.py` against that generated file returns
   `fail_open_reproduced: true` (`control-installed-binary-generated.json`).
   The **daemon calls this path on every pass**: `sweep_warden_autoharden`
   runs `dracon-warden once <repo>` (`dracon-sync/src/sync.rs:1107`), and
   `once` → `harden_repos` → `refresh_global_hooks_if_stale()`
   (`dracon-warden/src/main.rs:2151`) rewrites the live global hook from
   whichever binary is installed.
2. **The workspace test suite wrote the live hook too.** `refresh_warden_hook_if_stale`
   compares only "is this ours" plus "does the text differ". Both variants
   carry the same `# dracon-warden-managed-hook-v1` marker, so neither binary
   could tell a downgrade from a drift repair — the newer one "fixed" the hook,
   the older one "fixed" it back. The `integration_test` binary then ran `once`
   and `repair` without a private `HOME`, so `cargo test` also rewrote the
   operator's live hook (reproduced: hook changed to `d122d8c1…` across a
   34-second `cargo test -p dracon-warden --test integration_test` run, before
   the isolation fix).

Neither writer is a Git or network fault. The safety repair was correct; the
mechanism that distributes it had no way to represent a hook generation.

## Durable fix

**A hook can never be downgraded.** `WARDEN_HOOK_GENERATION` (now `2`) is
stamped into every rendered template through
`WARDEN_HOOK_MARKER_PREFIX`/`current_hook_marker()`. `refresh_warden_hook_if_stale`
refuses — with an ERROR, not a silent success — when the hook on disk carries a
newer generation than the running binary, leaving its bytes untouched. This is
generation-parsed by prefix (`^# dracon-warden-managed-hook-v([0-9]+)$`), not by
a closed marker list, so a hook from a future warden is still recognized as
warden-owned and still compared. A comment that merely *mentions* the marker is
not a marker.

**The in-hook chain check is generation-aware.** The templates decided whether a
repo-local hook was warden's own with `grep -qFx
'# dracon-warden-managed-hook-v1'` — an exact v1 match. Once hooks are stamped
v2 that check stops matching, and a warden-local hook would be chained and run
**twice** in the same push. All three templates now use
`grep -qE '^# dracon-warden-managed-hook-v[0-9]+$'`, verified against v1, v2,
v99 (skipped as warden's) and `-v1-extra` / "see … for details" / plain
`#!/bin/sh` (still chained as foreign).

**Tests can no longer reach the operator's hooks.** Every `integration_test`
invocation that can trigger a global refresh (`once`, `repair`, `scrub-markers`,
`resmudge`, `keygen`) now runs with a private `HOME` via `private_home()` /
`warden_in_home()`, and `test_warden_keygen` no longer mutates the process
environment with `set_var`. `assert_live_hooks_untouched` is available for
future hook-sensitive tests.

## Verification

- `refresh_never_downgrades_a_newer_hook_generation` — a v3 hook is recognized
  as warden's own, `hook_is_newer_than_binary` is true, refresh returns an error
  naming the downgrade, and the newer hook's bytes are preserved exactly; a
  same-generation hook still refreshes; an older generation still upgrades; a
  mention-only comment stays foreign.
- `rendered_hooks_carry_the_current_generation_marker` — all three templates
  render with the current generation, so the downgrade window cannot silently
  re-open if a template is edited without raising the marker.
- Full `cargo test -p dracon-warden --bin dracon-warden`: **245 passed, 0 failed**.
- `integration_test`: 18 passed, and the live hook sha256 was **unchanged**
  across the run (`d122d8c1…` before and after) — the leak that produced the
  flip-flop is closed.
- Hook control against the fixed binary's own output
  (`hook-generated-by-fixed-binary.pre-push`, `cc7caa7b…`):
  `control-fixed-binary-generated.json` refuses the synthetic secret, passes a
  harmless change, refuses the simulated scan failure, and reports
  `fail_open_reproduced: false`.

## Deployment and gate evidence

All four workspace gates pass on one committed assembly
(`final-gates.json`, raw logs adjacent):

| gate | result |
| --- | --- |
| `cargo test --workspace --locked` | 44 suites, **2888 passed, 0 failed** |
| `cargo build --release --locked` | exit 0 |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` | exit 0 |
| `cargo deny check` | advisories/bans/licenses/sources all ok |

Deployed through `dracon-sync maintenance` (pause → install → resume), so the
daemon never ran against a half-installed binary. Installed
`~/.local/bin/dracon-warden` = `b31f59ad…f9124`, byte-identical to the gated
release build, replacing the stale `39db331b…0fed370`. Rollback dir with the
previous binary, policy and hook: `/home/dracon/.local/state/dracon/rollback-binaries/warden-20261027T200325Z`.

The live global pre-push hook is now `cc7caa7b…cb5fc`, marker
`dracon-warden-managed-hook-v2`, with all 7 fail-closed scan checks.
`control-live-hook-final.json` runs the discretionary control against that live
file: synthetic secret refused, harmless change passes, simulated scan failure
refused, `fail_open_reproduced: false`.

## Downgrade is actually stopped

Running the daemon's exact auto-harden path (`dracon-warden once REPO`, policy
supplied) against the deployed binary leaves the live hook byte-identical, and
it stayed `cc7caa7b…` across subsequent live daemon cycles. Both the installed
and the qualified-release binaries generate the same `cc7caa7b…` hook from
`setup-hooks`, so there is no second, older template left in the fleet.
Before the binary was replaced, the same path stamped `1eaadcf3…` (fail-open)
every pass — that was the flip-flop, and it is gone.

## Remaining (not waived)

The guard protects future hooks; it cannot retroactively harden a binary that
does not contain it. Until the fixed `dracon-warden` is built, gated and
installed, the live daemon keeps re-stamping the fail-open hook from the stale
09:58 binary on every `once` pass. Deploying it is the required next step, and
it is blocked behind the same workspace gates as the rest of task 4 — which is
also why this report claims no deployment or convergence result.

Related, still open from the same incident: whether the plaintext `.env.dev`
commits were pushed with hooks bypassed has not been established, and the
encryption-scope rollout remains limited to the three demonstrated paths.

Nothing in this report is a fleet-convergence claim. Publication is still
contained by the intentional global `auto_push = false`, task 2's staging /
inspection repairs are not finished, and no clean-idle observation has been
made. This repair removes a demonstrated cause of silent security regression,
not the goal's remaining work.

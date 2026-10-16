# IndexBatch transport deadline and ownership

Scope: optional staged-ciphertext lookup only. No packet-protocol changes,
filter lifetime timeout, deployment, or encryption changes. main.rs delegates
IndexBatch to src/index_batch.rs. One-shot lookup is unchanged.

## Mechanism and bounds

Each lookup starts a 5-second monotonic budget covering resolver output/status,
batch query writes and header/body reads. Both pipes are nonblocking; WouldBlock
is retried with at most 2 ms sleeps, checking the same deadline on every I/O.
There are no reader threads, detached tasks, channels or blocking wait calls.
Header/resolver output are capped at 1 MiB; bodies at 64 MiB (same batch cap).
No timer runs between lookups: an idle persistent cat-file is legal.

Every helper starts in its own process group, isolated from the invoking Git.
The owner sends SIGKILL to that group BEFORE reaping the leader, avoiding signals
to a reused PGID. Resolver status uses waitid(WNOWAIT), preserving ownership until
cleanup. Drop then polls try_wait with a 1-second grace. No direct child is
abandoned. An unreapable helper triggers a payload-free diagnostic and exit(1),
without a core dump. This final backstop was approved by the parent orchestrator.

For ordinary userspace-stalled helpers, lookup returns within the 5-second I/O
budget plus at most a 1-second final cleanup grace (scheduler tolerance applies).
Prior cleanup consumes the request budget, and no new child starts after expiry.
Idle-session Drop separately has a 1-second grace. Timeout discards the entire
positional session; subsequent lookups resolve/restart as needed. Index locks and
mtime changes also retire the session.

The result of lookup failure is None: existing clean_reusing_index still computes
fresh valid ciphertext and only reuses old ciphertext after authenticated,
byte-exact decryption equality and policy checks. It never grants plaintext fallback.
Non-Unix builds disable this optional reuse transport rather than start unbounded
blocking helpers (not cross-compiled here).

## Focused validation

Run from dracon-warden, under outer `timeout 120s` watchdogs:

- `cargo test -p dracon-warden --locked index_batch --no-fail-fast`: 11 passed.
- `cargo test -p dracon-warden --locked filter_transform_batch_matches_oneshot`:
  1 passed.
- `cargo clippy -p dracon-warden --bin dracon-warden --tests --locked -- -D warnings`:
  passed.

Logs are adjacent. Fault tests inject child commands directly, never modify PATH
or process-global keys, use temporary synthetic repositories and memory-only age
identities, and set a 150 ms request budget with a 2-second return assertion.
Fixtures cover silent/partial output, non-reading stdin (4 MiB pathname), resolver
stall, exited leader with descendant-retained stdout, malformed/oversized headers,
helper exit, replacement and reuse after an idle gap. Each fault also checks fresh
ciphertext for protected text/binary, authenticated byte-exact reuse and rejection
of changed plaintext. A real staged-ciphertext test verifies lookup + authenticated
reuse. Direct-child waitpid verifies ECHILD after cleanup; Linux /proc additionally
verifies the stdout-retaining descendant is absent or dead (zombie), not running.
Whole-file binary equality is verified by clean_reusing_index's authenticated
smudge predicate, without passing bytes through a lossy string API.

Early fixture failures used a plain non-secret scanning-only path, then .env's
intentional version-header behavior; final fixtures use whole-file `credentials`
with all encryption and byte-equality assertions intact.

## Irreducible limits / deferred work

This is userspace pipe cancellation, not a hard real-time OS guarantee. Synchronous
spawn/exec setup, filesystem metadata and pathological kernel I/O can themselves
block in the kernel; no thread deadline safely cancels those operations. Kernel-
uninterruptible children cannot be guaranteed reaped; the bounded-reap fail-stop
is explicit, not a claim otherwise. Tests do not induce kernel failures or exercise
that final process exit. Helpers escaping the dedicated process group are outside
this normal Git-helper model. Descendant zombies belong to the system reaper, not
Warden (no process-wide subreaper side effects); group kill stops them but cannot
waitpid nonchildren. The Linux fixture documents this distinction explicitly.

Outer filter packet reads/writes and absolute-path normalization are separate seams
and remain unchanged. The historical incident's exact blocked instruction remains
unproven. Full workspace gates are owned by the parent; this evidence is focused.

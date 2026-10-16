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
On Linux, pre-exec arms direct-helper PR_SET_PDEATHSIG(SIGKILL) and starts an
independent in-group guardian using raw clone with fork semantics (no libc
pthread_atfork callbacks, shared memory, or shared FD table). The guardian blocks
SIGUSR1, installs a group-kill handler, arms SIGUSR1 parent-death notification,
and checks getppid to cover death before prctl. It closes every inherited FD via
close_range, including the exec-error pipe and data pipes, then sigsuspend
atomically unblocks/waits. The handler uses only kill(0, SIGKILL) and _exit.
The guardian's live group membership pins the PGID while signalling. Thus abrupt
Warden death kills the direct helper, whose death triggers guardian group kill;
direct-helper death without Warden Drop also triggers group kill. A normal helper
exit cannot leave its descendants or guardian running. Pre-exec explicitly sets
the isolated group before cloning; no privileged or process-wide subreaper setup.
Fork-to-prctl races on both generations are checked before normal operation.

Linux 5.9+ close_range (or a backport) is required for guarded helpers. A syscall
failure kills the isolated group instead of executing an unguarded helper; index
reuse then fails safely toward fresh encryption. No fallback performs unbounded
FD loops or retains unknown inherited descriptors.

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

- `cargo test -p dracon-warden --locked index_batch --no-fail-fast`: 14 passed (13 substantive tests plus the exact-worker fixture entry).
- `cargo test -p dracon-warden --locked sigkill --no-fail-fast` repeated 10 times
  under one 120-second outer watchdog: all 20 abrupt-death checks passed
  (`index-batch-abrupt-repeat.log`).
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
Two Linux abrupt-death regressions start only the exact fixture-worker test in
an isolated owner process group. They wait for a live helper, sleep descendant,
and guardian (with zero retained descriptors), verify the helper PGID is separate
from the owner, then SIGKILL either the outer owner's group or the direct helper.
All three helper-group processes must cease running within 2 seconds, without
calling PipeChild Drop; the direct-death case also verifies the owner stays alive.
The outer owner is boundedly reaped. No recursive test suite or live processes
are involved. Guardian setup/readiness waits also have bounded assertions.

Whole-file binary equality is verified by clean_reusing_index's authenticated
smudge predicate, without passing bytes through a lossy string API.

The guardian made an exited resolver's stdout close promptly, exposing an empty
resolver-output case: empty paths are now rejected rather than joined to cwd.

Early fixture failures used a plain non-secret scanning-only path, then .env's
intentional version-header behavior; final fixtures use whole-file `credentials`
with all encryption and byte-equality assertions intact.

## Irreducible limits / deferred work

This is userspace pipe cancellation, not a hard real-time OS guarantee. Synchronous
spawn/exec setup, filesystem metadata and pathological kernel I/O can themselves
block in the kernel; no thread deadline safely cancels those operations. Kernel-
uninterruptible children cannot be guaranteed reaped; the bounded-reap fail-stop
is explicit, not a claim otherwise. Tests do not induce kernel failures or exercise
that final process exit. Linux guardian notification still depends on kernel
signal delivery/scheduling, not a hard wall-clock guarantee. Non-Linux Unix has
ordinary owned Drop cleanup only: abrupt Warden death is NOT covered there.
Non-Unix batch reuse remains disabled. Linux architectures other than the tested
x86_64 host have not been cross-compiled. Helpers escaping the dedicated process group are outside
this normal Git-helper model. Descendant zombies belong to the system reaper, not
Warden (no process-wide subreaper side effects); group kill stops them but cannot
waitpid nonchildren. The Linux fixture documents this distinction explicitly.

Outer filter packet reads/writes and absolute-path normalization are separate seams
and remain unchanged. The historical incident's exact blocked instruction remains
unproven. Full workspace gates are owned by the parent; this evidence is focused.

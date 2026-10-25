# Bound Warden's per-process async runtime

## Observed amplification, not a claim of unique causation

An isolated invocation of the installed old Warden `filter-process`, held before
any request and then closed normally at EOF, reached **18 threads**. Its HOME,
Git config and repository were disposable; no real credential/config/index was
changed. The fixture remains at the path in
`fleet-old-runtime-fixture-2026-10-25.json`. EOF without a protocol handshake
returned1, as expected; this is a thread-count observation, not a filter success.

The sync service has TasksMax512. Its cumulative `pids.events` reported
`max104`; sampled current task counts were far below the ceiling. The browser
provisioning log for `dracon-pre-push.Qma7tJ` records Go `newosproc`, errno11,
with only4 threads already present. Its installer already had
`--concurrent-scripts=1`, and the hook recorded native worker env caps2. These
facts demonstrate encountered resource limits and avoidable per-filter runtime
amplification; they do NOT establish Warden uniquely caused that exact Go failure
or that the thread cap alone resolves host memory/swap pressure.

## Source correction

The actual CLI constructor now explicitly creates a multi-thread Tokio runtime
with **two async workers** and all previous runtime facilities enabled, then
executes the unchanged async command dispatch. Streaming filter processing still
uses its separate blocking task. No security, encryption, hook, storage or
assertion bypass was added; the service task limit was not raised and no editor
or producer was stopped. This does not cap total native/blocking threads.

The constructor regression exercises the same builder main uses (not source text
or a parallel test-only builder): one targeted test passed, raw output in
`fleet-bounded-runtime-test-2026-10-25.log`. Independent current-source review
found no issue in this seam. No new runtime binary has been installed or measured
as a live filter yet. The earlier complete232unit+18integration+2stream pass
belongs to source BEFORE this runtime change; full post-change qualification
and controlled installed-execution evidence remain required.

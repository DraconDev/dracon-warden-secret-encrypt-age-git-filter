# Plaintext environment publication incident — 2026-10-27

## Confirmed exposure (values never recorded)

Both reported commits (`de4dfc6ad0`, `2087841171`) contain unencrypted
assignments and JWT-shaped values in all three platform service `.env.dev`
files. Counts are 13/17/10 assignments respectively. Auth and billing have
zero encryption tags; email has one inline tag but still contains a raw JWT
and is not whole-file encrypted. No current plaintext-sibling hatch exists
for these paths.

Read-only `ls-remote` queries of origin (GitHub) and GitLab both advertised
main `798498bbe7f8aec0aee862e214dc2312d00ee2c2` at observation. Both plaintext
commits and both subsequent repair commits are ancestors of that advertised
tip. Thus later encryption did NOT remove exposed history. Token validity,
revocation, and any unauthorized use have not been checked.

Current HEAD stores full-file ciphertext for all three files. Fresh installed
filter-clean invocations on their working-tree bytes also returned full-file
ciphertext, exit 0, with no stderr. Inputs/outputs were inspected in memory;
no plaintext values were emitted or saved in evidence.

## Relevant prior repair

The encryption-only scope repair was deployed at 09:58:24 UTC, AFTER both
reported leaks at 09:47 and 09:51. Installed Warden SHA-256 still matches that
qualified deployment (`39db331b735b4c71a25e27e2d7c90cf171301406c3b1ca786f5ea207f0fed370`).
Its report explains the disagreement between manual filter attributes and
policy protected-pattern scope. The current passing clean checks support its
coverage of these three paths, not immunity from future configuration drift.
The exact actor/command that created the plaintext commits and whether hooks
were bypassed have not been established.

## Independently reproduced fail-open push guard

The installed global pre-push hook does not check several Git scan and
scratch-output statuses. A failed changed-path scan can yield an empty list,
which is interpreted as nothing to inspect. The changed-content pipeline also
uses `|| true`, masking producer failures. Similar unchecked status handling
exists in added/modified path enumeration and binary classification.

`dracon-warden/scripts/reproduce-prepush-io-failopen.py` creates only disposable
synthetic fixtures outside watched roots and NEVER pushes to a remote. With
the installed hook:
- ordinary synthetic provider-secret change is refused;
- ordinary harmless change passes;
- a simulated failed Git scan returns success (fail-open reproduced).

The candidate source now checks path enumeration, scratch writes/conversion,
diff production and binary classification independently. It preserves
expected grep non-match handling rather than treating every nonzero result as
an error or hiding all errors. Against the candidate, the secret is refused,
harmless change passes, and scan failure is refused. A Rust regression invokes
this same disposable control against the rendered candidate hook.

This is a demonstrated bug relevant to the user's ENOSPC suspicion, NOT proof
that ENOSPC triggered these particular commits. The inspected sync journal
for today contained zero ENOSPC / no-space / disk-quota strings. That limited
absence does not establish whether other processes or earlier dates ran out
of space. At triage, root had ~198 GiB free and 90% free inodes.

## Containment and limitations

- Issued `dracon-sync pause`; service was NOT stopped.
- Set global `auto_push = false` because pause watchdog/TTL is temporary.
  Original policy is privately backed up under
  `~/.local/state/dracon-sync/security-incident-20261027T145429Z/`, mode 0700.
  The policy backup is NOT copied into repository evidence.
- A later health check showed freeze off; freeze was reasserted at ~15:10 UTC.
  Persistent auto_push=false was still present. No git-push process was
  observed in the corresponding process checks. No claim is made that this
  setting prevents other agents/humans from issuing their own manual pushes.
- No history rewrite, deletion of secrets/checkouts, manual recovery push,
  hook bypass on a real repository, or credential rotation was performed.
- Exposed tokens still require revocation/rotation with operator approval.

## Verification and remaining work

Warden package: 243 unit + 18 integration + 2 storage-stream + 4 write-fence
tests passed (267 total), zero failures/ignored. Strict package all-target
Clippy passed. Raw package outputs and redacted controls are adjacent.

The candidate hook is NOT installed by this incident work yet. Whole-workspace
qualification and installed-execution checks remain outstanding. Further
hardening is required for remaining masking/matching pipelines and for the
shape scanner's coverage gap: its current provider regex does not cover
Turso JWTs. A protected-environment blob guard should not depend solely on
provider token shapes, and needs positive/negative controls covering mixed
plaintext/tag content, commit history, and I/O failures before deployment.
Do not re-enable automatic publication merely because these three HEAD blobs
are encrypted. The YouTube receipt work is deferred; sync/Warden safety is
the active investigation.

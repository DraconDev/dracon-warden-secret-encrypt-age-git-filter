# Verification evidence — completion-audit round 2 (2026-09-16)

Goal: close auditor objections (post-checkout dirty status, fixture
literals, F4 provider-format deferrals) and deploy the correction.
Release: dracon-security **0.3.5** + dracon-warden **0.113.10**
(commit `bb19cb5`, tag `dracon-warden-v0.113.10`, release commit
ancestry `e07a21d → bb19cb5 → 713ea01` on both forges).

All commands executed in the parent session against the INSTALLED binary
`~/.local/bin/dracon-warden` unless noted. Captured output is quoted
verbatim; PASS/FAIL markers are per-check.

## 1. Installed binary version — PASS
```
$ ~/.local/bin/dracon-warden --version
dracon-warden 0.113.10
```

## 2. Fixture contract on installed binary — PASS
```
$ dracon-warden/scripts/verify-install.sh
✓ OK: dracon-warden honors protected_patterns (Tier-2-only content
  untouched outside protected paths, Tier-1 token encrypted everywhere,
  protected file encrypted)
```

## 3. Git lifecycle on installed binary — PASS
```
$ python3 scripts/verify-filter-lifecycle.py ~/.local/bin/dracon-warden
{"binary": "/home/dracon/.local/bin/dracon-warden", "fixtures": 8,
 "encrypted_blobs": 6, "roundtrips": "byte-exact",
 "post_checkout_status": "clean", "real_edit": "detected and encrypted"}
```
8 fixtures (Stripe/GCP/OpenAI/PKCS#8/ENCRYPTED-PKCS#8/NUL-context
tokens, innocent slug, invalid-UTF-8 marker): 6 encrypted in committed
blobs, all 8 smudge round-trips byte-exact, `git status --porcelain`
EMPTY after checkout, genuine edit still flagged + re-encrypted.

## 4. No live-format literals — PASS
```
$ rg -n 'sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{25,}|AKIA[A-Z0-9]{12,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . --glob '!*.md'   # in dracon-warden/
(0 matches; exit 1)
```
The four `sk_live_1111222233334444` literals from auditor round 1 are
now runtime `concat!` in `tests/{keys_json,creds_json}_full_encrypt.rs`.

## 5. No tracked hatches — PASS
```
$ git -C dracon-warden ls-files | grep 'plaintext$'
(0 matches; exit 1)
```

## 6. Focused regression suites — PASS (19 tests, 0 failed)
```
$ cargo test -p dracon-security --locked --test tier_inventory \
    --test index_reuse --test tier1_source_encrypt \
    --test keys_json_full_encrypt --test creds_json_full_encrypt
test result: ok. 3 passed (index_reuse: reuse/upgrade/new-secret guards)
test result: ok. 3 passed (creds_json_full_encrypt: concat! fixtures)
test result: ok. 2 passed (keys_json_full_encrypt: concat! fixtures)
test result: ok. 9 passed (tier1_source_encrypt: F2/F3/F4 boundaries)
test result: ok. 2 passed (tier_inventory: no-drift + overlong negatives)
```
Full-suite status this round: `cargo test -p dracon-security -p
dracon-warden --locked` — 24 suites, all `test result: ok`, 0 failed.

## 7. Clippy — PASS
```
$ cargo clippy -p dracon-security -p dracon-warden --locked -- -D warnings
Finished `dev` profile (no warnings)
```

## 8. Formatting — PASS
```
$ cargo fmt -p dracon-security -p dracon-warden --check
FMT_OK
```

## 9. crates.io publication — PASS
```
$ cargo info dracon-warden   # from outside the workspace
version: 0.113.10
$ cargo info dracon-security
version: 0.3.5
```
Security-first publish order honored: 0.3.5 uploaded before warden's
release script ran its publish-order gate.

## 10. Forge refs (github AND gitlab) — PASS
```
$ git ls-remote origin refs/heads/main refs/tags/dracon-warden-v0.113.10
713ea01273ecb4d2faafe89cbef4ec471761e802  refs/heads/main
bb19cb55beddc9737315a6fa9aa8e4a7be6e4c2d  refs/tags/dracon-warden-v0.113.10
$ git ls-remote gitlab … (same two refs)
```
main `713ea01` is a descendant of release commit `bb19cb5`; the tag
points at `bb19cb5` on both remotes; GitHub release
`dracon-warden-v0.113.10` created by release.sh step 7.

## 11. Audit disposition updated — PASS
`audit/eager-encryption-2026-09-16.md` lines 156–190: round-1 gaps
recorded, F1 DEPLOYED (0.113.9 → carried into 0.113.10), F2–F5 CLOSED
with evidence, live probe section cites installed 0.113.10 lifecycle
result. CHANGELOG `## [0.113.10]` entry present.

## 12. Working trees clean — PASS
```
$ git -C dracon-warden status --porcelain; git -C .. status --porcelain
(both empty)
```

## 13. Tier-2 no-false-positive preserved (installed binary) — PASS
```
$ echo 'password = "t1er2-only-fixture-value-ok"' | dracon-warden filter-clean work/notes.txt
password = "t1er2-only-fixture-value-ok"   (byte-identical, not encrypted)
```

## 14. Overlong-token negative (installed binary) — PASS
```
source: const T: &str = "sk-or-v1-<66 hex>";
$ dracon-warden filter-clean src/x.rs  →  output unchanged (not encrypted)
```
Full adjacent-boundary checks reject bodies exceeding the 64-hex spec
(the 0.113.9 binary encrypted this input; fixed in 0.113.10).

## Root cause of round-1 dirty-status failure
The `* filter=dracon` catch-all routes every blob through clean. Random
AES-GCM nonces made `clean(smudge(blob)) ≠ blob`, so every encrypted
file showed `M` right after checkout. 0.113.10 clean reuses the stage-0
index blob ONLY when authenticated decryption proves the indexed
ciphertext equals the incoming worktree bytes, current policy still
demands the same encryption shape, and nothing new was detected.
Randomized encryption unchanged; no plaintext hashes; no persistent
cache. Guards pinned by `tests/index_reuse.rs`.

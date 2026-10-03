# dracon-warden v0.113.15 (2026-10-03)

ROUND3 audit remediation (1 MEDIUM, 3 LOW), on top of the unreleased
ROUND2 batch, media-protection patterns, and LLM-dump defaults already
in the changelog. Requires dracon-security 0.4.0 (published alongside).

- The pre-commit hook strips `#` comments before probing filter state:
  commented-out `filter=dracon` lines neither mark a repo managed nor
  satisfy the enforcement gate (behavioral tests both directions).
- The registered merge driver quotes `%O`/`%A`/`%B` so space-containing
  paths no longer word-split it; hardened repos migrate on next pass.
- `git merge-file` exit codes above 1 propagate as hard errors — only
  exit 1 means conflict — leaving stages in the index instead of
  overwriting the worktree file with possibly-empty stdout.
- The pre-push blob-novelty check enumerates remote objects once per
  push (lazy, still fail-closed) instead of once per added file.

Validation: workspace gates green, 37 hook/merge behavioral tests pass
including the once-per-push enumeration proof and the exit-2 regression.

Install:

```bash
cargo install dracon-warden --version 0.113.15 --locked
```

[Full changelog](https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter/compare/dracon-warden-v0.113.14...dracon-warden-v0.113.15)

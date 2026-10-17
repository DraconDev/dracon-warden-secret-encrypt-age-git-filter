# dracon-warden v0.113.16 (2026-10-17)

Git filter encryption and repository hardening for secrets at rest.

## What's Changed

- Bump version to 0.113.16
- (See CHANGELOG.md for the full list of changes in this release)

## Install

```bash
cargo install dracon-warden --version 0.113.16
```

## Usage as a git filter (smudge/clean)

The filter is installed by warden's hardening pass — no manual
`git config filter.*` lines needed (the old template documented
non-existent `init`/`clean`/`smudge` subcommands and a wrong
`filter.dracon-warden.*` name; the real filter is `filter.dracon.*`,
written by `once` via ensure_repo_filter_config):

```bash
# One-time, per machine: install the global hooks (pre-commit /
# pre-push / pre-rebase) and generate this machine's keypair.
dracon-warden setup-hooks
dracon-warden keygen

# Per repo you want to encrypt: harden it — writes the managed
# .gitattributes filter=dracon block + .gitignore block, configures
# filter.dracon.process (long-running filter driver; legacy
# clean/smudge keys are migrated away automatically), and scrubs
# plaintext markers.
dracon-warden once <repo>
```

**Full Changelog**: https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter/compare/dracon-warden-v0.113.15...dracon-warden-v0.113.16

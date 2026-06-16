# Dracon Warden

Secret, encrypt, age, git-filter — repository hardening and smudge/clean encryption for Dracon workspaces.

This repository is the **canonical "main"** for `dracon-warden` on GitHub,
GitLab, and Codeberg. It contains the actual source code (mirrored from the
[`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
monorepo), the `Cargo.toml`, tests, examples, and the per-utility README.
You can build and install this utility directly from this repo.

## Quick start (standalone build)

```bash
# Clone this repo
git clone https://github.com/DraconDev/dracon-warden-secret-encrypt-age-git-filter.git
cd dracon-warden-secret-encrypt-age-git-filter

# Clone required siblings (path-dep layout)
git clone https://github.com/DraconDev/dracon-libs.git ../dracon-libs
# dracon-warden also needs the monorepo for the security kit
git clone https://github.com/DraconDev/dracon-utilities.git ../dracon-utilities

# Build
cargo build --release

# Install (binary lands in target/release/)
sudo cp target/release/dracon-warden /usr/local/bin/
```

## What is in this repo

- `src/` — utility source code
- `tests/` — integration tests (if present)
- `Cargo.toml` — standalone build manifest with path-dep siblings
- `README.md` — this file (the per-utility README from the monorepo is at `monorepo-README.md`)
- `BLUEPRINT.md` — design notes
- `dracon-warden.example.toml` — example config
- `No systemd service; enforced through global git hooks.` — systemd user-service unit
- `LICENSE`, `SECURITY.md`, `.gitignore`, `.github/` — repo metadata
- `docs/SOURCE_OF_TRUTH.md` — architecture + invariants

## Relationship to the monorepo

| Boundary | Decision |
|----------|----------|
| Source code | Mirrored from `dracon-utilities/dracon-warden` via `scripts/regenerate_facade_repos.py` on every monorepo commit |
| Source of truth | `dracon-utilities` monorepo (the auto-sync is one-way) |
| Feature surface | This repo (canonical main for `dracon-warden`) |
| Shared libraries | Sibling `dracon-libs` workspace (`../dracon-libs`) |
| Operational policy | `~/.dracon/utilities/` TOML files |

## Why this name?

The descriptive name is a deliberate choice for Codeberg/Forgejo, where
descriptive repo names get upvotes and free attention because readers
immediately know what the project does. The full word list (no fillers, no
audience/UX claims) is documented in
[`docs/design/github-feature-repos.md`](https://github.com/DraconDev/dracon-utilities/blob/main/docs/design/github-feature-repos.md).

## Purpose

Encrypts secret-shaped content at rest in git while preserving normal plaintext files in the working tree. Uses age encryption and git smudge/clean filters plus a pre-commit hook for plaintext-secret prevention.

## Runtime

- Binary: `dracon-warden`
- Service: No systemd service; enforced through global git hooks.
- Example policy: `dracon-warden/dracon-warden.example.toml`
- Common commands: `dracon-warden status · dracon-warden keygen · dracon-warden setup-hooks --global · dracon-warden scrub-markers`

## Maintenance

When the monorepo changes the utility source code, README, or example config,
the monorepo's `post-commit` hook calls `scripts/regenerate_facade_repos.py`
which mirrors the changes to this repo. The `dracon-sync` daemon picks up
the local change in `/home/dracon/Dev/facade-repos/dracon-warden-secret-encrypt-age-git-filter` and
auto-pushes to the 3 remotes (github, gitlab, codeberg). No manual
`--apply` or `--push-all-remotes` invocation is needed in the normal flow.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

# Dracon Warden

**Git filter + repo hardening tool.** Secret, encrypt, age, git-filter — repository hardening and smudge/clean encryption. Encrypts secrets at rest in git while keeping plaintext in your working tree. Uses git hooks (not a daemon) as the primary enforcement layer.

![`dracon-warden status` output](https://raw.githubusercontent.com/DraconDev/dracon-utilities/main/dracon-warden/docs/status-output.png)

This page is the user guide for `dracon-warden` (also rendered on
crates.io). The canonical source is the `dracon-warden/` directory of the
[`dracon-utilities`](https://github.com/DraconDev/dracon-utilities) monorepo
on `main`; the standalone GitHub/GitLab repos are frozen mirrors.

## Install

```bash
cargo install dracon-warden
```

The binary lands at `~/.cargo/bin/dracon-warden` (version 0.113.6 on
crates.io). Or build the locked source artifact from the monorepo:

```bash
git clone https://github.com/DraconDev/dracon-utilities.git
cd dracon-utilities/dracon-warden
cargo build --release --locked
```

## Mental Model (Important)

- **Working tree is plaintext**: `filter.smudge` decrypts so your app can read normal config/secrets.
- **Git blobs are ciphertext**: `filter.clean` encrypts so secrets are encrypted-at-rest in history.

To verify what is stored in git (not your working tree), use:

```sh
git show HEAD:path/to/file
```

If encryption is active for that path, you should see marker payloads like `[DRACON_SECRET:...]`
in the `git show` output (even though your working tree file is plaintext).

## Features

### Age-Based Encryption
- Uses [age](https://age-encryption.org/) encryption with x25519 keys
- Secrets encrypted with per-repo keys
- Team key distribution for collaboration
- Master key hierarchy for key recovery

### Secret Scanning
- Comprehensive regex patterns for AWS, GCP, Azure, GitHub, Slack, etc.
- Scans for API keys, tokens, passwords, private keys
- Configurable allowlists for legitimate plaintext patterns
- Prevents accidental secret exposure in git history

### Clean/Smudge Filter Pipeline
- `filter.clean`: Encrypts secrets when staging files
- `filter.smudge`: Decrypts secrets when checking out files
- Idempotent operations (safe to run multiple times)
- Handles binary files, large files, already-encrypted content

### Repo Hardening
- Sets up git filter configuration
- Publishes repo public keys
- Manages `.gitattributes` for encryption patterns
- Creates encryption manifests

### Team Collaboration
- Owner keys for repo authorization
- Team keys for shared access
- Registry credentials management
- Key rotation support

### Plaintext-Sibling Escape Hatch (Opt-In)
- Some files contain values that should never be encrypted (public example
  keys, fixture data, benchmark datasets)
- Touch a `<file>.plaintext` sibling to opt a specific file in to plaintext
  storage — the clean filter returns it unchanged, the pre-push hook
  silently skips it
- Revocation: `rm <file>.plaintext` and the next commit re-encrypts
- The hatch is per-file; the rest of the repo is unaffected
- See `docs/design/warden-plaintext-sibling.md` for threat model and
  what the hatch does NOT protect against
- Default install behaviour is unchanged: no `.plaintext` sibling → encryption

## Installation

### Quick Install

Run the repository installer from the repository root:

```bash
cd dracon-utilities
./install.sh
```

This will:
1. Build the release binary
2. Install to `~/.local/bin/dracon-warden`
3. Install git hooks globally via `dracon-warden setup-hooks --global`

The per-utility directories do not contain standalone installers; use the root `install.sh` for all utilities.

### Manual Install

```bash
# Build the locked release artifact
cargo build --release --locked

# Install atomically (GNU/Linux)
install -d "$HOME/.local/bin"
tmp="$(mktemp "$HOME/.local/bin/.dracon-warden.XXXXXX")"
install -m 0755 target/release/dracon-warden "$tmp"
mv -f -- "$tmp" "$HOME/.local/bin/dracon-warden"

# Verify the installed binary, then install git hooks globally
# (run from the monorepo root; from inside dracon-warden/ drop the prefix)
dracon-warden/scripts/verify-install.sh "$HOME/.local/bin/dracon-warden"
dracon-warden setup-hooks --global
```

## Usage

### Commands

```bash
# Show resolved policy path and repo roots
dracon-warden status

# Run one hardening pass and exit
dracon-warden once
dracon-warden once <repo>

# Generate new age keypair (never overwrites an existing key — back it up;
# losing it means losing every secret it encrypted)
dracon-warden keygen

# Git filter operations (used by git automatically)
dracon-warden filter-clean   # stdin -> stdout
dracon-warden filter-smudge  # stdin -> stdout

# Git merge driver (invoked by git via `merge.dracon.driver`, not by hand)
dracon-warden merge

# Recovery tools
dracon-warden scrub-markers   # Scan DRACON_SECRET markers
dracon-warden scrub-markers --apply  # Fix markers in JSON

# Fix ciphertext stuck in working tree
dracon-warden resmudge
dracon-warden resmudge --apply

# System-wide repair pass
dracon-warden repair
dracon-warden repair --dry-run
dracon-warden repair --strict

# Install git hooks globally (primary enforcement layer:
# pre-commit blocks unconfigured filters, pre-push scans for secrets)
dracon-warden setup-hooks --global
```

## Configuration

The live config lives at `~/.dracon/utilities/warden/dracon-warden.toml`.
The annotated template is `dracon-warden.example.toml` in this repo
(`dracon-warden/dracon-warden.example.toml` from the monorepo root).
Only these keys exist — anything else is silently ignored, so do not invent
new ones:

```toml
# Directories to scan for git repos (canonical field)
repo_roots = ["~/.dracon", "~/Dev"]

# Additional discovery roots (optional; if omitted, repo_roots is used)
# discover_roots = ["~/extra-search-root"]

# Glob patterns for files that MUST be encrypted (age filter + gitattributes).
# Empty keeps the legacy scan-everything posture; a non-empty list is
# default-deny (only listed patterns are encrypted).
protected_patterns = []

# Glob patterns for files that must remain plaintext (excluded from encryption).
# Tight validator allowlist only (build artifacts, binaries, *.pub keys,
# Cargo.lock, events jsonl) — e.g. ["Cargo.lock", "*.pub"].
plaintext_patterns = []

# Hygiene globs (files that should NOT exist in repos). Omitted = the narrow
# machine-local defaults; the shipped example extends them with
# product-specific regeneratable paths.
hygiene_patterns = ["**/.pi*", "**/chrometrace.log", "**/.cache/"]
```

`~` and `~/...` in `repo_roots`, the deprecated `watch_roots` alias, and
`discover_roots` resolve against the current `HOME` before missing roots are
filtered out. Discovery recursively walks those roots, including nested
checkouts and `.git` pointer-file repositories, while skipping `.git` metadata
directories.

## Safety Defaults

- `plaintext_patterns` is for files that must remain plaintext in git (lockfiles, public keys, etc).
- `plaintext_patterns` **must not include secret-ish patterns** (like `.env` or `secrets/**`).
  dracon-warden will refuse to run if the policy tries to disable encryption for those.

## Key Management

### Key Hierarchy

```
~/.dracon/identity.age          — Master x25519 private key
~/.dracon/master.age           — Sovereign master key
~/.dracon/keys/*.age           — Additional identities
~/.dracon/data/keys/machine_*.age — Machine-level secret keys
~/.dracon/data/keys/owner_*.pub  — Owner anchors or marked machine mesh recipients
```

Repository `.dracon/data/keys/` files are not trusted by filename alone:
public recipients participate only with an owner-authenticated proof bound
to the exact filename, recipient, and repository-key commitment. Legacy
pairs without a proof must be explicitly re-authorized by the operator.

### Key Generation

```bash
# Generate new age keypair
dracon-warden keygen

# Keypair saved to:
# - ~/.dracon/data/keys/machine_<hostname>.age (private)
# - ~/.dracon/data/keys/owner_<hostname>.pub (public, marked machine recipient)
```

Back the key up. Loss means permanent data loss.

### Team Keys

Team keys allow multiple users to access the same encrypted secrets:

1. Each user generates their own keypair
2. An operator with the repository key runs the team-member authorization API
3. The API writes the public recipient, encrypted delegation, and authenticated
   `.auth` proof; all three files must remain present
4. Secrets are encrypted to all verified team keys
5. Any authorized team member can decrypt secrets

A contributor may propose or push a `.pub` file, but cannot authorize a new
recipient merely by choosing an alias.

## How It Works

### Encryption Flow

1. User edits `.env` file (plaintext in working tree)
2. `git add` triggers `filter.clean`
3. dracon-warden scans for secrets
4. Secrets are encrypted with age encryption
5. Encrypted content stored as `[DRACON_SECRET:base64_age_ciphertext]`
6. Commit contains encrypted blobs

### Decryption Flow

1. `git checkout` triggers `filter.smudge`
2. dracon-warden detects encrypted markers
3. Secrets are decrypted with local private key
4. Plaintext written to working tree
5. App reads normal `.env` file

### Secret Detection

dracon-warden scans for:
- AWS access keys, secret keys, session tokens
- GCP API keys, OAuth tokens, service accounts
- Azure storage keys, shared access signatures
- GitHub tokens, SSH keys
- Slack webhooks, bot tokens
- Database connection strings
- Private keys (RSA, EC, ED25519)
- And many more patterns

## Recovery Tools

### scrub-markers

Fixes cases where marker tokens accidentally land in plaintext JSON:

```bash
# Scan for markers
dracon-warden scrub-markers

# Fix markers
dracon-warden scrub-markers --apply
```

### resmudge

Fixes ciphertext stuck in working tree:

```bash
# Dry run
dracon-warden resmudge

# Apply fixes
dracon-warden resmudge --apply
```

### repair

System-wide repair pass:

```bash
# Dry run
dracon-warden repair

# Apply fixes
dracon-warden repair --apply

# Strict mode (more checks)
dracon-warden repair --strict
```

## Security Considerations

### What's Encrypted
- Files matching `protected_patterns` in policy (empty list = legacy scan-everything)
- Files containing detected secrets

### What's NOT Encrypted
- Files matching `plaintext_patterns` in policy
- Lock files (Cargo.lock, package-lock.json)
- Public keys (*.pub)
- Configuration files without secrets

### Key Storage
- Private keys stored in `~/.dracon/`
- Keys are never committed to git
- Backup your keys! Loss means permanent data loss

## What Is in This Repo

- `src/` — utility source code (plus the embedded `src/security` crate)
- `tests/` — integration tests
- `Cargo.toml` — standalone build manifest with registry dependencies
- `README.md` — this utility's user guide
- `dracon-warden.example.toml` — example config
- `scripts/` — install-verification tooling
- `LICENSE`, `SECURITY.md`, `.gitignore`, `.github/` — repo metadata
- Architecture + invariants: [`docs/SOURCE_OF_TRUTH.md`](https://github.com/DraconDev/dracon-utilities/blob/main/dracon-warden/docs/SOURCE_OF_TRUTH.md)
- Design notes: [`BLUEPRINT.md`](https://github.com/DraconDev/dracon-utilities/blob/main/dracon-warden/BLUEPRINT.md)

## Relationship to the Monorepo

| Boundary | Decision |
|----------|----------|
| Source code | The `dracon-warden/` directory of the `dracon-utilities` monorepo (`main` branch) |
| Source of truth | The `dracon-utilities` monorepo; the standalone repos are frozen mirrors |
| Workspace integration | Included by the `dracon-utilities` meta workspace when checked out under `dracon-warden/` |
| Shared libraries | Embedded `src/security` crate plus registry dependencies |
| Operational policy | `~/.dracon/utilities/` TOML files |

## Why This Name?

The descriptive name is a deliberate choice for Codeberg/Forgejo, where
descriptive repo names get upvotes and free attention because readers
immediately know what the project does. The full word list (no fillers, no
audience/UX claims) is documented in
[`docs/design/github-feature-repos.md`](https://github.com/DraconDev/dracon-utilities/blob/main/docs/design/github-feature-repos.md).

## Purpose

Encrypts secret-shaped content at rest in git while preserving normal plaintext files in the working tree. Uses age encryption and git smudge/clean filters, a pre-commit hook for plaintext-secret prevention, a pre-push secret scan, and a merge driver for encrypted files.

## Machine-Local Hygiene Defaults

When `hygiene_patterns` is omitted, Warden supplies the narrow machine-local
baseline used by the fleet: `**/.pi*`, `**/chrometrace.log`, and regeneratable
frontend caches (`**/.svelte-kit/`, `**/.vite/`, `**/.turbo/`, and `**/.cache/`).
These paths are ignored by the managed `.gitignore` block so harness state,
trace output, and build caches do not become repository content. An explicit
`hygiene_patterns = []` remains a supported operator override; Warden does not
add broad `*.log` matching by default.

## Runtime

- Binary: `dracon-warden`
- Service: No systemd service; enforced through global git hooks (`setup-hooks --global`).
- Example policy: `dracon-warden.example.toml` in this repo
  (`dracon-warden/dracon-warden.example.toml` from the `dracon-utilities` monorepo root);
  the live config lives at `~/.dracon/utilities/warden/dracon-warden.toml`
- Key management: `dracon-warden keygen` writes the machine age keypair and
  never overwrites an existing key — back the key up; losing it means losing
  every secret it encrypted.
- Encryption scope: `protected_patterns` selects which globs get encrypted
  (empty keeps the legacy scan-everything posture); `plaintext_patterns` is a
  tight allowlisted escape hatch (see the example policy).
- Common commands: `dracon-warden status · dracon-warden once <repo> · dracon-warden keygen · dracon-warden setup-hooks --global · dracon-warden scrub-markers`;
  also `repair`, `resmudge`, `filter-clean`/`filter-smudge`, `merge` — full list at `dracon-warden --help`

## Maintenance

Changes are made in the `dracon-utilities` monorepo (`dracon-warden/` on `main`).
The standalone repos are frozen mirrors of that tree.

## Version

```bash
dracon-warden --version
```

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

---

*Part of the [Dracon](https://dracon.uk) developer workspace.*

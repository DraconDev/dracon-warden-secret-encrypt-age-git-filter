# dracon-warden

**Git filter + repo hardening tool.** Encrypts secrets at rest in git while keeping plaintext in your working tree. Uses git hooks (not a daemon) as the primary enforcement layer.

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
# Build
cargo build --release

# Copy binary
cp target/release/dracon-warden ~/.local/bin/

# Install git hooks globally
dracon-warden setup-hooks --global
```

## Usage

### Commands

```bash
# Show resolved policy path and repo roots
dracon-warden status

# Run one hardening pass and exit
dracon-warden once

# Generate new age keypair
dracon-warden keygen

# Git filter operations (used by git automatically)
dracon-warden filter-clean   # stdin -> stdout
dracon-warden filter-smudge  # stdin -> stdout

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

# Install git hooks globally (primary enforcement layer)
dracon-warden setup-hooks --global
```

## Configuration

Create `~/.dracon/utilities/warden/dracon-warden.toml`:

```toml
# Directories to scan for git repos (canonical field)
repo_roots = ["/home/user/Dev"]

# Additional discovery roots (optional; if omitted, repo_roots is used)
discovery_roots = ["/home/user/Dev"]

# Exclude specific directories
exclude_dir_names = ["node_modules", "target", ".venv"]

# Plaintext patterns (files that must remain plaintext in git)
# WARNING: Must not include secret-ish patterns like .env or secrets/**
plaintext_patterns = [
    "*.lock",
    "*.pub",
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
]

# Secret marker (default: DRACON_SECRET)
secret_marker = "DRACON_SECRET"

# Encryption version (1 or 2)
encryption_version = 2

# Allow V1 fallback (for migration)
allow_v1_fallback = false

# Team keys (for shared access)
team_keys = [
    "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
]

# Registry credentials
[[registries]]
registry = "ghcr.io"
username = "username"
# Password stored in secrets file

# Owner key (for repo authorization)
owner_key = "~/.dracon/keys/owner.age"
```

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
~/.dracon/data/keys/owner_*.pub  — Owner key for repo authorization
```

### Key Generation

```bash
# Generate new age keypair
dracon-warden keygen

# Keypair saved to:
# - ~/.dracon/keys/machine_<hostname>.age (private)
# - ~/.dracon/keys/machine_<hostname>.age.pub (public)
```

### Team Keys

Team keys allow multiple users to access the same encrypted secrets:

1. Each user generates their own keypair
2. Public keys are added to the repo's team keys list
3. Secrets are encrypted to all team keys
4. Any team member can decrypt secrets

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
- `.env` files
- Files matching `secret_patterns` in policy
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

## Version

```bash
dracon-warden --version
```

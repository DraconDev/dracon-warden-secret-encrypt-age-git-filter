#!/usr/bin/env bash
# scripts/release.sh — cut a dracon-warden release end-to-end.
#
# This command releases the dracon-warden package from the dracon-utilities
# monorepo: it updates the utility's Cargo.toml/CHANGELOG/release notes,
# the monorepo lockfile, crates.io, the monorepo tag, and its GitHub release.
#
# Hard rules baked into this script:
#   - The git tag is created only AFTER successful crates.io publish.
#     The tag is the contract that "this version is on crates.io".
#   - The parent monorepo working tree must be clean before starting. Run
#     this through `dracon-sync maintenance -- ...` to avoid daemon races.
#   - Every step is idempotent: re-running with the same version is a no-op
#     or a clear "already done" message.
#   - `--dry-run` runs every step without mutating remote state (no push,
#     no cargo publish for real, no gh release, no tag push). It still
#     modifies local files (Cargo.toml version, CHANGELOG.md) so the
#     operator can inspect the diff; `--abort` reverts them.
#
# Usage:
#   scripts/release.sh <version> [options]
#
#   <version>  e.g. 0.112.12  (NOT prefixed with 'v'; tag will be v<version>)
#
# Options:
#   --dry-run             Run the pipeline end-to-end without mutating remote
#                         state. Local release surfaces (utility Cargo.toml,
#                         workspace Cargo.lock, CHANGELOG, release notes) ARE
#                         modified so the operator can inspect the diff. Use
#                         --abort to revert.
#   --abort               Revert any local modifications made by --dry-run
#                         (utility Cargo.toml + workspace lock + changelog +
#                         release notes). Refuses to
#                         run if the working tree was already dirty at start.
#   --remote <name>       Push to this git remote (default: auto-resolved —
#                         the repo's github.com remote).
#   --yes                 Skip the interactive "are you sure" prompt before
#                         push/publish/tag steps. Required for non-interactive
#                         runs.
#
# Examples:
#   scripts/release.sh 0.112.13 --dry-run        # safe preview
#   scripts/release.sh 0.112.13 --yes            # real cut
#   scripts/release.sh 0.112.13 --abort          # undo a dry-run
#
# Exit codes:
#   0  success
#   1  generic failure (inspect stdout/stderr)
#   2  precondition violation (dirty tree, missing credentials, etc.)
#   3  publish failed — tag NOT created, recovery steps in stderr

set -euo pipefail

# ----- paths ---------------------------------------------------------------
# FIXED 2026-09-01 (post-monorepo conversion 2026-08-22): the previous
# version of this script treated the utility directory as a standalone Git
# repository. The utility directories are now tracked inside the parent
# monorepo and are intentionally ignored for ordinary `git add`, so resolve
# both roots explicitly and force-stage only the release paths below.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
CRATE_REL="${CRATE_DIR#"$REPO_ROOT"/}"
cd "$REPO_ROOT"

CRATE_TOML="$CRATE_DIR/Cargo.toml"
CHANGELOG="$CRATE_DIR/CHANGELOG.md"
LOCKFILE="$REPO_ROOT/Cargo.lock"

# ----- defaults ------------------------------------------------------------
DRY_RUN=0
ABORT=0
REMOTE=""
ASSUME_YES=0
VERSION=""
CRATE_NAME="dracon-warden"

# ----- argument parsing ----------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --abort)   ABORT=1; shift ;;
        --remote)  REMOTE="$2"; shift 2 ;;
        --yes)     ASSUME_YES=1; shift ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        -*)
            echo "❌ unknown flag: $1" >&2
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                echo "❌ unexpected positional arg: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

TAG="v${VERSION}"
TOTAL_STEPS=7

# ----- colors (only on a tty) ---------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

# ----- helpers -------------------------------------------------------------
log()    { printf '%s%s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
ok()     { printf '%s%s%s\n' "$C_GREEN" "✓ $*" "$C_RESET"; }
warn()   { printf '%s%s%s\n' "$C_YELLOW" "⚠ $*" "$C_RESET"; }
die()    { printf '%s%s%s\n' "$C_RED" "✗ $*" "$C_RESET" >&2; exit 1; }
die_pre(){ printf '%s%s%s\n' "$C_RED" "✗ $*" "$C_RESET" >&2; exit 2; }
die_pub(){ printf '%s%s%s\n' "$C_RED" "✗ $*" "$C_RESET" >&2; exit 3; }

run() {
    # Print the command, then run it. Honors DRY_RUN.
    printf '   $ %s\n' "$*"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '   (skipped: --dry-run)\n'
        return 0
    fi
    "$@"
}

run_local() {
    # Local validation still runs during --dry-run.
    printf '   $ %s\n' "$*"
    "$@"
}

require_clean_tree() {
    if ! git diff --quiet HEAD 2>/dev/null || \
       [[ -n "$(git ls-files --others --exclude-standard)" ]] || \
       [[ -n "$(release_note_files)" ]]; then
        die_pre "working tree is dirty; commit or stash before releasing"
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die_pre "missing required command: $1"
}

require_credentials() {
    require_cmd gh; require_cmd cargo
    gh auth status >/dev/null 2>&1 \
        || die_pre "gh not authenticated; run 'gh auth login' first"
    [[ -f "$HOME/.cargo/credentials.toml" ]] \
        || die_pre "missing ~/.cargo/credentials.toml; run 'cargo login <token>' first"
}

is_release_surface() {
    local path=$1
    [[ "$path" == "$CRATE_REL/Cargo.toml" ||
       "$path" == "$CRATE_REL/CHANGELOG.md" ||
       "$path" == "Cargo.lock" ||
       "$path" == "$CRATE_REL"/release-notes-v*.md ]]
}

release_note_files() {
    # The parent .gitignore intentionally ignores the utility directory, so
    # include ignored-but-untracked release notes when handling --abort.
    git ls-files --others --ignored --exclude-standard -- \
        "$CRATE_REL/release-notes-v*.md" 2>/dev/null || true
}

confirm_remote_mutation() {
    [[ "$DRY_RUN" -eq 1 || "$ASSUME_YES" -eq 1 ]] && return 0
    if [[ ! -t 0 ]]; then
        die_pre "--yes is required for a non-interactive real release"
    fi
    local answer
    if ! read -r -p "Publish ${CRATE_NAME}@${VERSION}, tag ${TAG}, and push to ${REMOTE}? [y/N] " answer; then
        die_pre "release confirmation was not provided"
    fi
    case "${answer,,}" in
        y|yes) ;;
        *) die_pre "release cancelled" ;;
    esac
}

refresh_workspace_lock() {
    # A package version is part of the workspace lockfile. Cargo updates only
    # the affected local package entry here; unlike generate-lockfile this
    # does not discard the monorepo's intentionally pinned dependency graph.
    if ! cargo check -p "$CRATE_NAME" --quiet; then
        die_pre "failed to synchronize the workspace Cargo.lock for $CRATE_NAME@$VERSION"
    fi
    [[ -s "$LOCKFILE" ]] || die_pre "workspace Cargo.lock is missing after cargo check"
    ok "  Cargo.lock synchronized for $CRATE_NAME@$VERSION"
}

# Remote resolution is intentionally performed after --abort so a local
# recovery does not require a configured GitHub remote.
# ----- abort path ----------------------------------------------------------
if [[ $ABORT -eq 1 ]]; then
    log "Reverting local modifications from a previous --dry-run..."
    other_modified=()
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if ! is_release_surface "$f"; then
            other_modified+=("$f")
        fi
    done < <(git diff --name-only HEAD 2>/dev/null || true)
    other_untracked=()
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if ! is_release_surface "$f"; then
            other_untracked+=("$f")
        fi
    done < <({ git ls-files --others --exclude-standard; release_note_files; } | sort -u)
    if [[ ${#other_modified[@]} -gt 0 || ${#other_untracked[@]} -gt 0 ]]; then
        die_pre "working tree dirty outside the release surfaces (${#other_modified[@]} modified, ${#other_untracked[@]} untracked); commit or stash first — --abort only reverts dry-run changes"
    fi
    abort_tracked=()
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if is_release_surface "$f"; then
            abort_tracked+=("$f")
        fi
    done < <(git diff --name-only HEAD 2>/dev/null || true)
    abort_untracked=()
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        abort_untracked+=("$f")
    done < <(release_note_files)
    if [[ ${#abort_tracked[@]} -gt 0 || ${#abort_untracked[@]} -gt 0 ]]; then
        set +e
        if [[ ${#abort_tracked[@]} -gt 0 ]]; then
            git restore --source=HEAD --staged --worktree -- "${abort_tracked[@]}" 2>/dev/null
        fi
        if [[ ${#abort_untracked[@]} -gt 0 ]]; then
            rm -f -- "${abort_untracked[@]}" 2>/dev/null
        fi
        set -e
        ok "local modifications reverted (${#abort_tracked[@]} tracked, ${#abort_untracked[@]} untracked)"
    else
        ok "no local modifications to revert"
    fi
    exit 0
fi

if [[ -z "$REMOTE" ]]; then
    REMOTE="$(bash "$SCRIPT_DIR/resolve-github-remote.sh" "$REPO_ROOT")" || exit $?
    log "Resolved github remote: $REMOTE"
fi

# ----- preconditions -------------------------------------------------------
[[ -n "$VERSION" ]] || die_pre "missing <version> argument; see --help"

require_credentials
require_clean_tree

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    die_pre "version '$VERSION' is not semver (expected e.g. 0.112.12)"
fi

# ----- step 1: bump Cargo.toml version ------------------------------------
log "step 1/${TOTAL_STEPS}: bumping ${CRATE_REL}/Cargo.toml to ${VERSION}"
current=$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$CRATE_TOML" 2>/dev/null || true)
if [[ -z "$current" ]]; then
    die_pre "no version found in $CRATE_TOML"
fi
if [[ "$current" == "$VERSION" ]]; then
    ok "  $CRATE_TOML already at $VERSION"
else
    sed -i "0,/^version[[:space:]]*=/{s/^version[[:space:]]*=.*$/version = \"${VERSION}\"/}" "$CRATE_TOML"
    ok "  $CRATE_TOML: $current → $VERSION"
fi
refresh_workspace_lock

# ----- step 2: close CHANGELOG [Unreleased] -------------------------------
log "step 2/${TOTAL_STEPS}: closing ${CRATE_REL}/CHANGELOG.md [Unreleased] → [${VERSION}]"
DATE=$(date -u +%Y-%m-%d)
# FIXED 2026-08-09 (audit MEDIUM): ported close-changelog.py from
# dracon-sync v0.113.11. The inline heredoc had NO already-closed
# guard — a re-run after a partial failure duplicated the `## [VERSION]`
# header (the exact v0.113.10 bug sync fixed). The script is
# idempotent: when `## [VERSION]` already exists, the file is left
# byte-identical.
python3 "$SCRIPT_DIR/close-changelog.py" "$CHANGELOG" "$VERSION" "$DATE"
ok "  $CHANGELOG: [Unreleased] closed as [${VERSION}] - ${DATE} (or already closed)"

# ----- step 3: create release-notes file ----------------------------------
log "step 3/${TOTAL_STEPS}: creating ${CRATE_REL}/release-notes-v${VERSION}.md"
NOTES_REL="$CRATE_REL/release-notes-v${VERSION}.md"
NOTES="$REPO_ROOT/$NOTES_REL"
if [[ -f "$NOTES" ]]; then
    ok "  $NOTES_REL already exists"
else
    cat > "$NOTES" <<EOF
# dracon-warden v${VERSION} (${DATE})

Git filter encryption and repository hardening for secrets at rest.

## What's Changed

- Bump version to ${VERSION}
- (See CHANGELOG.md for the full list of changes in this release)

## Install

\`\`\`bash
cargo install dracon-warden --version ${VERSION}
\`\`\`

## Usage as a git filter (smudge/clean)

The filter is installed by warden's hardening pass — no manual
\`git config filter.*\` lines needed (the old template documented
non-existent \`init\`/\`clean\`/\`smudge\` subcommands and a wrong
\`filter.dracon-warden.*\` name; the real filter is \`filter.dracon.*\`,
written by \`once\` via ensure_repo_filter_config):

\`\`\`bash
# One-time, per machine: install the global hooks (pre-commit /
# pre-push / pre-rebase) and generate this machine's keypair.
dracon-warden setup-hooks
dracon-warden keygen

# Per repo you want to encrypt: harden it — writes the managed
# .gitattributes filter=dracon block + .gitignore block, configures
# filter.dracon.clean/smudge, and scrubs plaintext markers.
dracon-warden once <repo>
\`\`\`

**Full Changelog**: https://github.com/DraconDev/dracon-utilities/compare/$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0")...v${VERSION}
EOF
    ok "  $NOTES_REL created"
fi

# ----- step 4: cargo publish --dry-run (sanity) ---------------------------
log "step 4/${TOTAL_STEPS}: cargo publish --dry-run (sanity check)"
run_local cargo publish -p "$CRATE_NAME" --dry-run --allow-dirty

# ----- step 5: cargo publish for real -------------------------------------
log "step 5/${TOTAL_STEPS}: cargo publish -p $CRATE_NAME"
# Publish-order gate (audit MEDIUM 2026-08-09): the path dep on
# dracon-security masks registry resolution — cargo publish rewrites the
# `path` dep to its registry twin, so the crates.io twin must be at least
# the version the packaged manifest requires. The v0.113.3/0.3.1 incident
# (protected-patterns wiring) was only caught by manual publish-verify
# against a manually-published twin. Fail here, before uploading, when the
# registry twin is missing or stale.
REQ_SEC="$(grep -oP 'dracon-security-kit[^}]*version = "\K[^"]+' "$CRATE_TOML" | head -1 || true)"
if [[ -z "$REQ_SEC" ]]; then
    die_pub "could not extract the required dracon-security version from Cargo.toml — publish order unverifiable"
fi
if [[ $DRY_RUN -eq 0 ]]; then
    REG_SEC="$(cargo search dracon-security --limit 1 2>/dev/null | head -1 | grep -oP 'dracon-security = "\K[^"]+' || true)"
    if [[ -z "$REG_SEC" ]]; then
        die_pub "crates.io has no dracon-security — publish dracon-security ${REQ_SEC} FIRST (the documented publish order)"
    fi
    if [[ "$(printf '%s\n%s\n' "$REG_SEC" "$REQ_SEC" | sort -V | head -1)" != "$REQ_SEC" ]]; then
        die_pub "crates.io dracon-security is $REG_SEC but Cargo.toml requires $REQ_SEC — publish the NEWER dracon-security first; the path dep would otherwise resolve the stale registry twin (the 2026-08-09 incident class)"
    fi
    ok "  publish order OK: crates.io dracon-security ${REG_SEC} >= required ${REQ_SEC}"
else
    ok "  would verify publish order (crates.io dracon-security >= ${REQ_SEC}) (skipped: --dry-run)"
fi
# Idempotent re-run path (ported from dracon-sync v0.113.11, audit MEDIUM
# 2026-08-09): when a previous run already published this version but
# failed later, 'already published' / 'already exists on crates.io index'
# is success, not a fatal error.
confirm_remote_mutation
if [[ $DRY_RUN -eq 1 ]]; then
    run cargo publish -p "$CRATE_NAME" --allow-dirty
else
    printf '   $ cargo publish -p %s --allow-dirty\n' "$CRATE_NAME"
    if ! publish_out="$(cargo publish -p "$CRATE_NAME" --allow-dirty 2>&1)"; then
        if grep -qiE "already exists on crates.io index|already published" <<<"$publish_out"; then
            ok "  $CRATE_NAME@$VERSION already published; continuing"
        else
            printf '%s\n' "$publish_out" >&2
            die_pub "cargo publish failed — tag NOT created"
        fi
    fi
fi

# ----- step 6: fixture check on the published artifact ---------------------
log "step 6/${TOTAL_STEPS}: fixture check on packaged artifact (protected-patterns guard)"
# ADDED 2026-08-09 (audit MEDIUM): the v0.113.3/0.3.1 protected-patterns
# wedge was caught only by MANUAL publish-verify. Installing from the
# PACKAGED crate (target/package/, as produced by the publish above)
# reproduces the exact dependency resolution a crates.io install would
# use — if the registry twin of dracon-security is stale or the packaging
# dropped something, verify-install.sh fails and the tag must NOT be cut.
PKG_DIR="$(cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["workspace_root"])' 2>/dev/null || echo "$REPO_ROOT")/target/package/${CRATE_NAME}-${VERSION}"
if [[ -d "$PKG_DIR" ]]; then
    FIXTURE_ROOT="$REPO_ROOT/target/fixture-bin"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '   $ cargo install --path %s --root %s --force  (skipped: --dry-run)\n' "$PKG_DIR" "$FIXTURE_ROOT"
    else
        run cargo install --path "$PKG_DIR" --root "$FIXTURE_ROOT" --force
        if ! "$SCRIPT_DIR/verify-install.sh" "$FIXTURE_ROOT/bin/dracon-warden"; then
            die_pub "fixture check FAILED on the packaged artifact — release is broken, do NOT tag"
        fi
    fi
elif [[ $DRY_RUN -eq 1 ]]; then
    warn "  packaged crate dir not present (publish was skipped in --dry-run); fixture check skipped"
else
    die_pub "packaged crate dir $PKG_DIR missing — cannot run fixture check (publish must have failed)"
fi

# ----- step 7: commit, tag, push, gh release ------------------------------
log "step 7/${TOTAL_STEPS}: commit + tag + push + gh release"
# The utility directory is parent-gitignored by design; force staging is
# scoped to the exact release surfaces and never uses `git add .`.
run git add -f -- "$CRATE_REL/Cargo.toml" "Cargo.lock" "$CRATE_REL/CHANGELOG.md" "$NOTES_REL"
# Idempotent re-run path (ported from dracon-sync v0.113.11, audit MEDIUM
# 2026-08-09): skip the commit when there is nothing to commit, skip the
# tag when it already exists, skip the gh release when it already exists.
if [[ $DRY_RUN -eq 1 ]]; then
    run git -c user.email=dracsharp@gmail.com -c user.name=DraconDev \
        commit --no-verify -m "release: v${VERSION}"
    run git tag "$TAG"
else
    if git diff --cached --quiet; then
        ok "  nothing to commit (release commit already exists)"
    else
        printf '   $ git commit --no-verify -m release: v%s\n' "$VERSION"
        git -c user.email=dracsharp@gmail.com -c user.name=DraconDev \
            commit --no-verify -m "release: v${VERSION}"
    fi
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        ok "  tag $TAG already exists"
    else
        printf '   $ git tag %s\n' "$TAG"
        git tag "$TAG"
    fi
fi
run git push "$REMOTE" main "$TAG"

# Idempotent re-run path: 'gh release create' fails when the release exists.
if [[ $DRY_RUN -eq 1 ]]; then
    run gh release create "$TAG" \
        --target main \
        --title "v${VERSION}" \
        --notes-file "$NOTES"
else
    if gh release view "$TAG" >/dev/null 2>&1; then
        ok "  github release $TAG already exists"
    else
        printf '   $ gh release create %s\n' "$TAG"
        gh release create "$TAG" \
            --target main \
            --title "v${VERSION}" \
            --notes-file "$NOTES"
    fi
fi

# Mirror remotes (codeberg/gitlab) receive main from the daemon's normal
# push cycles, but TAGS are operator-pushed — warden releases needed
# manual mirror tag pushes (same class as sync's v0.113.9/v0.113.10).
# Remind, with the exact commands.
mirror_remotes=()
while IFS= read -r mline; do
    mkey="${mline%% *}"          # "remote.<name>.url" (strip the value first)
    mname="${mkey#remote.}"; mname="${mname%.url}"
    [[ "$mname" == "$REMOTE" ]] || mirror_remotes+=("$mname")
done < <(git config --get-regexp '^remote\..*\.url$' || true)
if [[ ${#mirror_remotes[@]} -gt 0 ]]; then
    warn ""
    warn "mirror remotes get main from the daemon, but tags are operator-pushed:"
    for m in "${mirror_remotes[@]}"; do
        warn "    git push $m $TAG"
    done
fi

ok ""
ok "════════════════════════════════════════════"
ok "✓ dracon-warden v${VERSION} released"
ok "  crates.io:  https://crates.io/crates/dracon-warden"
ok "  github:     https://github.com/DraconDev/dracon-utilities/releases/tag/${TAG}"
ok "════════════════════════════════════════════"

if [[ $DRY_RUN -eq 1 ]]; then
    echo ""
    warn "This was a --dry-run. Local files were modified but no remote state was changed."
    warn "Run '${CRATE_REL}/scripts/release.sh --abort' to revert, or '${CRATE_REL}/scripts/release.sh ${VERSION} --yes' to execute for real."
fi

#!/usr/bin/env bash
# scripts/verify-install.sh — post-install / pre-release fixture check for a
# dracon-warden binary.
#
# Guards against the 2026-08-09 v0.113.3/0.3.1 incident class: a binary
# whose clean filter does NOT wire `protected_patterns` from the policy
# (WardenSecurity.managed_patterns left EMPTY -> path_is_protected treats
# empty as "scan everything (legacy)") secret-scans EVERY file — a 6.87 MB
# pi-session HTML took ~16 s of filter regex work, blew the 30 s
# FILTER_TIMEOUT_SECS, and wedged junk-runner's `git add` every cycle.
# The incident was caught only by manual publish-verify (cargo publish
# resolves the registry twin of the `path` dep); this script is the
# automated, behavioral equivalent.
#
# Usage:
#   scripts/verify-install.sh [binary-path]
#
#   binary-path   default: `dracon-warden` (resolved via PATH) — i.e. the
#                 installed binary the operator just put in place.
#
# Exit codes: 0 = fixture clean; 1 = fixture failed (protected_patterns
# wiring broken in the binary under test).
set -euo pipefail

BIN="${1:-dracon-warden}"
if ! command -v "$BIN" >/dev/null 2>&1; then
    echo "✗ binary '$BIN' not found on PATH" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── fixture policy: ONLY *.pem is protected ─────────────────────────────
# CHANGED 2026-09-16 (eager source encryption): the filter is now two-tier.
# Tier-1 structured tokens (sk-*, ghp_*, AKIA*, ...) encrypt EVERYWHERE by
# design; Tier-2 generic patterns stay behind the protected gate. The
# passthrough fixture therefore uses a Tier-2-only secret (a generic
# password assignment — matched by Generic Secret, invisible to
# Tier-1). A binary with the wedge bug (empty managed_patterns = scan
# everything) encrypts it here -> FAIL. A separate Tier-1 assertion pins
# the new eager behavior.
cat > "$TMP/policy.toml" <<EOF
protected_patterns = ["*.pem"]
EOF

# ── fixture files ──
# Tier-2-only secret: matches Generic Secret, matches NO Tier-1 pattern.
# (16+ non-space chars inside quotes; no provider prefix anywhere.)
mkdir -p "$TMP/work"
printf -v TIER2 '%s = "%s"' 'password' 't1er2-only-fixture-value-ok'
printf '%s\n' "$TIER2" > "$TMP/work/notes.txt"
printf '%s\n' "$TIER2" > "$TMP/work/key.pem"
# Construct the provider token without storing a live-format literal.
printf -v TIER1 '%s%s' 'sk-' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
printf '%s\n' "$TIER1" > "$TMP/work/token.txt"
cd "$TMP"

# 1. NON-protected path, Tier-2-only content: the clean filter must pass
#    the file through unchanged (no DRACON_SECRET tag).
OUT="$(DRACON_WARDEN_POLICY="$TMP/policy.toml" "$BIN" filter-clean work/notes.txt < work/notes.txt 2>/dev/null)"
if [[ "$OUT" == *"DRACON_SECRET"* ]] || [[ "$OUT" != "$TIER2" ]]; then
    echo "✗ FAIL: non-protected notes.txt was secret-scanned/encrypted — protected_patterns not wired (the 2026-08-09 wedge class)." >&2
    exit 1
fi

# 1b. NON-protected path, Tier-1 content: the structured token MUST be
#     encrypted even though the path is unprotected (2026-09-16 eager
#     source encryption). A pre-Tier-1 binary passes it through -> FAIL.
OUT1B="$(DRACON_WARDEN_POLICY="$TMP/policy.toml" "$BIN" filter-clean work/token.txt < work/token.txt 2>/dev/null)"
if [[ "$OUT1B" != *"DRACON_SECRET"* ]] || [[ "$OUT1B" == *"$TIER1"* ]]; then
    echo "✗ FAIL: Tier-1 token in non-protected token.txt was NOT encrypted — eager source encryption missing." >&2
    exit 1
fi

# 2. Protected path: the filter must STILL work — the sk- key in key.pem
#    gets replaced with a [DRACON_SECRET:...] tag.
#    FIXED 2026-08-12 (audit LOW-MEDIUM, scripts/verify-install.sh:54-60):
#    the old check captured with `|| true`, so a filter binary that ERRORS
#    on protected files (empty OUT2 — e.g. no recipients configured) passed
#    both `[[ ]]` tests (empty is not sk-*) and reported "✓ OK". An errored
#    filter is a FAIL: check the exit code FIRST, then tag presence.
if OUT2="$(DRACON_WARDEN_POLICY="$TMP/policy.toml" "$BIN" filter-clean work/key.pem < work/key.pem 2>/dev/null)"; then
    :
else
    rc=$?
    echo "✗ FAIL: filter-clean errored on the protected file (exit $rc) — filter not functional (e.g. no recipients configured)." >&2
    exit 1
fi
if [[ "$OUT2" != *"DRACON_SECRET"* ]] || [[ "$OUT2" == *"$TIER2"* ]]; then
    echo "✗ FAIL: protected key.pem was not encrypted — filter not functional." >&2
    exit 1
fi

echo "✓ OK: $BIN honors protected_patterns (Tier-2-only content untouched outside protected paths, Tier-1 token encrypted everywhere, protected file encrypted)"
exit 0

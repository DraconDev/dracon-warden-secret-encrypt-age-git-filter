# Dracon Warden Improvement Blueprint

## Status Legend
- [ ] Not started
- [~] In progress
- [x] Completed

---

## CRITICAL Security Vulnerability (Fixed)

### 1. Encryption failure falls back to plaintext
- **Location:** `dracon-security/src/filter.rs:112-117, 180-185, 264-268`
- **Problem:** When encryption fails, secrets were passed through to git UNENCRYPTED. This is a critical security vulnerability.
- **Impact:** Secrets could be committed in plaintext if encryption has any issue
- **Fix:** 
  - Changed `clean_env()` and `clean_env_all()` to return error instead of plaintext fallback
  - Added `scan_and_replace_fallible()` method to `SecretScanner` 
  - Updated `clean()` to use fallible replacement that errors on encryption failure
- **Priority:** Critical
- **Status:** [x]

---

## Code Quality Fixes

### 2. Dead code - unused function
- **Location:** `main.rs:386-389`
- **Problem:** `should_passthrough_filter_path()` always returns `false`, parameter unused
- **Fix:** Marked with `#[allow(dead_code)]` - may be implemented in future
- **Priority:** Low
- **Status:** [x]

### 3. Redundant `let _ =` before `?`
- **Location:** `main.rs:820`
- **Problem:** `let _ = resmudge_repos(...)?` - confusing syntax, `?` already handles the result
- **Fix:** Removed redundant `let _ =`
- **Priority:** Low
- **Status:** [x]

---

## What Warden Does

dracon-warden is a Git filter + repository hardening CLI:

1. **Git Filter Operations**: Implements `clean` (encrypt on commit) and `smudge` (decrypt on checkout) using age encryption
   - Working tree remains plaintext (developers see normal config)
   - Git blobs contain ciphertext with `[DRACON_SECRET:...]` markers

2. **Repository Hardening**: Manages `.gitignore` and `.gitattributes` to enforce encryption policies

3. **Secret Scanning**: Detects AWS keys, OpenAI keys, GitHub tokens, Stripe keys via regex

4. **Recovery Tools**: Commands for scrubbing leaked markers and re-decrypting stuck files

5. **Plaintext-sibling escape hatch** (opt-in): A file with a `<path>.plaintext`
   sibling is intentionally plaintext. The clean filter returns the file
   unchanged, the pre-push hook skips it, and `scrub-markers` / `resmudge`
   leave it alone. See `docs/design/warden-plaintext-sibling.md` for the
   full design, threat model, and revocation story.

---

## Key Files

| File | Purpose |
|------|---------|
| `dracon-warden/src/main.rs` | CLI entry point, hardening logic, hooks |
| `dracon-warden/src/security/src/filter.rs` | clean/smudge filter implementations |
| `dracon-warden/src/security/src/crypto.rs` | age encryption/decryption |
| `dracon-warden/src/security/src/scanner.rs` | Secret pattern detection |
| `dracon-warden/src/security/src/keys.rs` | KeyRing and key management |

---

## Future Improvements

These are implementation notes for maintainers, not release blockers for the current public release.

### 4. Missing context on file write
- **Location:** `main.rs:1041`
- **Status:** [x] Added `.with_context(|| format!("failed writing {}", path.display()))`.

### 5. Inconsistent error handling
- **Location:** `main.rs:393, 403`
- **Status:** [x] Documented as intentional for create-if-missing reads.

### 6. Silent git command failure
- **Location:** `main.rs:979-980`
- **Status:** [x] Added warning message on failure.

---

## Field Naming: `watch_roots` → `repo_roots` (v0.3.0)

### 7. Misleading field name
- **Location:** `WardenPolicy::watch_roots` in `dracon-warden/src/main.rs`
- **Problem:** The field was named `watch_roots`, which suggested filesystem
  watching (inotify-style events). Warden has no daemon mode and does NOT
  watch filesystems in real-time — it only acts on git operations via hooks
  (pre-commit, pre-push) and scans repos on demand when `once`, `repair`,
  or `setup-hooks` is invoked. The old name was misleading.
- **Fix:**
  - Renamed the canonical field to `repo_roots` (it really is a list of
    directories to scan for git repos)
  - Kept `watch_roots` as a deprecated alias that is still accepted, with
    a deprecation warning to stderr AND a yellow ⚠ row in
    `dracon-warden status`
  - When both keys are set, `repo_roots` wins
- **Backwards compat:** The old key works in 0.2.0 and emits a warning;
  it will be removed in a future major release.
- **Priority:** Medium (semantic clarity, not a bug)
- **Status:** [x]

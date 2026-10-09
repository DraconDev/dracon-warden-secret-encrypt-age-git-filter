//! Git clean/smudge filter pipeline for encryption.

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use globset::GlobBuilder;
use std::fs;
use std::path::Path;

use crate::normalize_secret_marker;
use crate::strip_env_version_header;
use crate::MarkerMigrationStats;
use crate::SecretScanner;
use crate::WardenSecurity;
use crate::{is_env_version_managed, make_env_version_header};

const HEADER_V2_MAGIC: &[u8] = b"age-encryption.org/v1";

/// Returns true if a `.plaintext` sibling exists next to `path` in the
/// working tree. Presence of `<path>.plaintext` is the documented opt-in
/// for leaving a file unencrypted. See
/// `docs/design/warden-plaintext-sibling.md`.
///
/// `path` must be repo-relative; it resolves against the caller CWD,
/// so callers MUST run with CWD at the repo root (git's filter
/// protocol guarantees this for the clean/smudge path, the only
/// production caller). Empty, absolute, and `..`-bearing paths return
/// false (fail closed = encrypt): an absolute path or a `..` escape
/// could resolve a sibling OUTSIDE the repo, hatching a file from a
/// directory it was never next to. Use [`is_hatched_in_repo`] when
/// the root is known explicitly (tests, non-filter callers).
pub fn is_hatched(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let p = std::path::Path::new(path);
    // FIXED 2026-10-03 (audit R4-W-08): reject shapes that escape
    // CWD-relative resolution. Previously any absolute path was
    // checked literally, so a future caller passing an unvalidated
    // absolute path could be hatched by a foreign directory.
    if p.is_absolute() {
        return false;
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    let sibling = format!("{}.plaintext", path);
    std::path::Path::new(&sibling).exists()
}

/// Rooted hatch check (ADDED 2026-10-03, audit R4-W-08): `path` may
/// be repo-relative (resolved under `root`) or absolute (accepted
/// only when lexically under `root`). Anything else — empty, missing
/// root, `..` escaping the root, unreadable shapes — returns false.
/// Containment is LEXICAL (no fs canonicalization, so a missing
/// sibling is `false`, not an error): a symlink inside the root
/// pointing out is not contained. That residual matches the threat
/// posture — planting such a link already requires repo write access,
/// which can commit plaintext directly.
pub fn is_hatched_in_repo(root: &std::path::Path, path: &str) -> bool {
    if path.is_empty() || !root.is_absolute() {
        return false;
    }
    let p = std::path::Path::new(path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    };
    let mut norm = std::path::PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                if !norm.pop() {
                    return false;
                }
            }
            std::path::Component::CurDir => {}
            other => norm.push(other.as_os_str()),
        }
    }
    if !norm.starts_with(root) {
        return false;
    }
    let sibling = format!("{}.plaintext", norm.display());
    std::path::Path::new(&sibling).exists()
}

/// ADDED 2026-10-09 (audit D11): hatch lookup rooted to the FILE'S OWN
/// path, not the process CWD. This is what `smart_clean_with_path`
/// actually wants — the filter protocol guarantees CWD = repo root in
/// production, but a library caller (or a future daemon path) may
/// invoke it with a different CWD, and the hatch is a property of the
/// file's repo, not the caller's working directory.
///
/// Rules:
/// * absolute path: walk up the file's directory looking for `.git`;
///   the first `.git` ancestor is the repo root and the lookup goes
///   through `is_hatched_in_repo`, so a stray `.plaintext` sibling
///   outside that root can never hatch the file. If no `.git` is
///   reachable, fail CLOSED (return false) — the file is not in a
///   repo we can verify, so it does not get the plaintext opt-in.
/// * relative path: production (git filter protocol) passes
///   repo-relative paths with CWD = repo root, so anchor to
///   CWD-as-root. Tests that need CWD-different-from-repo pass an
///   absolute path and exercise the rule above.
fn is_hatched_via_path(path_str: &str) -> bool {
    if path_str.is_empty() {
        return false;
    }
    let p = std::path::Path::new(path_str);
    if p.is_absolute() {
        let mut cur = p.parent();
        while let Some(dir) = cur {
            if dir.join(".git").exists() {
                return is_hatched_in_repo(dir, path_str);
            }
            cur = dir.parent();
        }
        return false;
    }
    match std::env::current_dir() {
        Ok(cwd) => is_hatched_in_repo(&cwd, path_str),
        Err(_) => false,
    }
}

/// Returns true if `path_str` matches ANY of the Git-attribute-style glob
/// patterns in `protected_patterns`. This is the gate that determines
/// whether the `SecretScanner` is allowed to run on a file.
///
/// The patterns are evaluated with the same path-component rules as the
/// root `.gitattributes` file generated by `dracon-warden`:
///
/// * a pattern without `/` is matched against the basename at any depth;
/// * a pattern containing `/` is matched against the repository-relative path;
/// * `*` and `?` match within one path component, while `**` can cross
///   directory boundaries.
///
/// In particular, `secrets/*` matches `secrets/api.key` but not
/// `secrets/team/api.key`, and `.ssh/*` matches `.ssh/id_ed25519` but not
/// `.ssh/work/id_ed25519`. Using one `GlobBuilder` configuration here is
/// important: the filter gate must not disagree with the `filter=dracon`
/// entries emitted to `.gitattributes`.
///
/// If `protected_patterns` is empty, the function returns true (legacy: an
/// empty protected list means "scan everything"). This preserves backward
/// compatibility for operators who have not configured the gate.
///
/// A path that does not match any non-empty pattern is treated as not
/// protected (return false), so it is passed through unchanged. This is the
/// default-deny posture: the operator must explicitly add a pattern to
/// `protected_patterns` to opt a file in to encryption.
fn git_attribute_pattern_matches(pattern: &str, path_str: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }

    // Filter paths are repository-relative and use `/`. A leading slash in
    // an attribute pattern anchors it at the repository root; all patterns
    // passed to this function are already relative to that root, so remove
    // the anchor before compiling but retain its anchoring semantics.
    let anchored = pattern.starts_with('/');
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    let normalized_path = path_str.replace('\\', "/");
    let candidate = if anchored || pattern.contains('/') {
        normalized_path.as_str()
    } else {
        // Git attributes patterns without a slash match a basename in every
        // directory. Matching the basename explicitly also keeps `*` from
        // accidentally spanning a directory when the candidate is nested.
        normalized_path.rsplit('/').next().unwrap_or("")
    };

    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true);
    let Ok(glob) = builder.build() else {
        // protected_patterns is operator input. An invalid entry must not
        // make a clean filter panic; it simply cannot opt a path in.
        return false;
    };
    glob.compile_matcher().is_match(candidate)
}

pub fn path_is_protected(path_str: &str, protected_patterns: &[String]) -> bool {
    if protected_patterns.is_empty() {
        return true; // empty list = scan everything (legacy)
    }
    if path_str.is_empty() {
        return false; // empty path = no information
    }
    protected_patterns
        .iter()
        .any(|pattern| git_attribute_pattern_matches(pattern, path_str))
}

/// ADDED 2026-09-27 (audit decision D2): true when `path_str` matches any
/// gitattributes-style pattern in `patterns`.
///
/// Exposed so the warden binary can apply the SAME matcher the generated
/// .gitattributes block implies, rather than a second, subtly different
/// implementation. `path_is_protected` cannot be reused for this: an empty
/// pattern list there means "scan everything" (legacy), whereas an empty
/// list here must mean "nothing is exempt".
pub fn path_matches_any_pattern(path_str: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() || path_str.is_empty() {
        return false;
    }
    patterns
        .iter()
        .any(|pattern| git_attribute_pattern_matches(pattern, path_str))
}

/// ADDED 2026-09-30: true when `filename` (basename, not a path) is an LLM
/// conversation/session export: Muse `conversation-<ts>.txt` and
/// `trajectory-<ts>.json` (`muse export` default, RAW transcript),
/// Pi `pi-session-<ts>_<uuid>.html`, Codex `rollout-<ts>-<uuid>.jsonl`,
/// and the same prefixes with the sibling dump extensions.
///
/// These dumps carry pasted secrets, credentials, internal paths, and PII in
/// free prose, so they get whole-file age encryption rather than inline
/// secret scanning — structure and prose both hidden, with no ~16 s regex
/// bill on a multi-MB HTML dump. The extension gate is load-bearing:
/// `pi-session-retention-purge.service` is a systemd unit that shares the
/// `pi-session-` prefix but must stay plaintext source, and likewise a
/// hypothetical `conversation-service.rs` or a deploy `rollout-plan.md` —
/// only the dump extensions match, and `rollout-` is transcript-only
/// (`.json`/`.jsonl`) because deploy rollout docs share the prefix.
/// Keep in agreement with the warden binary's
/// `default_conversation_protected_patterns` (a cross-crate test pins it).
pub fn is_llm_conversation_dump(filename: &str) -> bool {
    const TEXT_DUMP_EXTS: [&str; 4] = [".txt", ".md", ".json", ".html"];
    const TRANSCRIPT_EXTS: [&str; 2] = [".json", ".jsonl"];
    // Codex session transcripts: data formats only, never prose/docs.
    if filename.starts_with("rollout-") {
        return TRANSCRIPT_EXTS.iter().any(|ext| filename.ends_with(ext));
    }
    let prefix_ok = filename.starts_with("conversation-")
        || filename.starts_with("pi-session-")
        || filename.starts_with("trajectory-");
    prefix_ok && TEXT_DUMP_EXTS.iter().any(|ext| filename.ends_with(ext))
}

impl WardenSecurity {
    pub fn smart_clean(&self, content: &str) -> Result<String> {
        let scanner = SecretScanner::new()?;
        self.smart_clean_with_scanner(content, &scanner)
    }

    pub fn smart_clean_with_path(&self, content: &[u8], path_str: &str) -> Result<Vec<u8>> {
        // 0. Plaintext-sibling escape hatch: if `<path>.plaintext` exists in
        // the working tree, the user has explicitly opted this file in to
        // plaintext storage. Return content unchanged. See
        // `docs/design/warden-plaintext-sibling.md`.
        //
        // CHANGED 2026-10-09 (audit D11): the old CWD-relative
        // `is_hatched(path_str)` made this function unsafe to call from
        // a CWD other than the file's repo (the sibling lookup
        // resolved against the wrong root and a hatch could be missed,
        // or a stray sibling under a foreign CWD could hatch a file
        // that was never opted in). Resolve the hatch against the
        // FILE'S OWN PATH: walk up the file's directory to find the
        // enclosing repo (`.git`), and delegate to
        // `is_hatched_in_repo` so the sibling is strictly under that
        // root. Production (git filter protocol) passes
        // repo-relative paths with CWD at the repo root, so the
        // CWD-anchored fallback still matches. See
        // `is_hatched_via_path` for the full rule.
        if is_hatched_via_path(path_str) {
            return Ok(content.to_vec());
        }

        // 0a. Protected-patterns gate: the `protected_patterns` field in
        // `dracon-warden.toml` enumerates the file globs that are allowed
        // to be scanned / encrypted by the warden. ANY file whose path
        // does NOT match a `protected_patterns` glob is passed through
        // unchanged. This is the "default-skip" for non-protected
        // files and prevents the SecretScanner from encrypting source
        // code (e.g. `*.rs`, `*.ts`, `*.py` test fixtures whose
        // function names or model IDs happen to match a scanner
        // pattern like `mistral-[A-Za-z0-9_-]{20,}`).
        //
        // The matching is Git-attribute-style glob matching. Each entry in
        // `protected_patterns` can be a literal filename (`master.age`), a
        // recursive directory glob (`secrets/**`), a basename glob
        // (`*.env`), or a repository-relative path glob
        // (`config/services.json`). Single-star path components do not cross
        // `/`, matching the generated `.gitattributes` semantics.
        //
        // If NONE of the `protected_patterns` match `path_str`, the
        // file is passed through unchanged and the SecretScanner is
        // NEVER invoked. This is the "default-deny" posture: the
        // operator must explicitly add a file pattern to
        // `protected_patterns` to opt it in to encryption.
        // CHANGED 2026-09-16 (eager source encryption): a non-protected
        // path no longer passes through blind. UTF-8 text gets a Tier-1-
        // only selective clean — structured provider tokens (sk_live_*,
        // ghp_*, AKIA*, PEM blocks, ...) are encrypted wherever they
        // appear, including source files no protected glob covers. The
        // Tier-1 membership bar (fixed prefix + rigid body) keeps the
        // false-positive rate near zero; generic Tier-2 patterns stay
        // behind this gate (2026-06 gibuardien lesson). Non-UTF8 content
        // still passes through: binary in a non-sensitive, non-protected
        // location is never encrypted. The .plaintext hatch above still
        // wins over everything.
        // ADDED (media option): a media-pattern match passes this gate
        // without disturbing the managed-patterns semantics — an empty
        // media list matches nothing (never legacy scan-everything),
        // and a legacy empty managed list still scans everything.
        if !path_is_protected(path_str, &self.managed_patterns)
            && !path_matches_any_pattern(path_str, &self.media_patterns)
        {
            return match std::str::from_utf8(content) {
                Ok(text_content) => {
                    let scanner = SecretScanner::new_tier1()?;
                    Ok(self
                        .smart_clean_with_scanner(text_content, &scanner)?
                        .into_bytes())
                }
                Err(_) => Ok(content.to_vec()),
            };
        }

        // 1. Definition of Sensitive Paths (Still used for binary detection)
        let sensitive_dirs = [
            ".ssh",
            "dracon/keys",
            "dracon/secrets",
            ".aws",
            ".kube",
            ".gnupg",
            ".azure",
            ".config/gcloud",
        ];

        let sensitive_exts = [
            ".age", ".key", ".p12", ".pfx", ".pem", ".crt", ".der", ".asc", ".zip", ".tar", ".gz",
            ".bz2", ".7z", ".rar", ".tgz", ".xz", ".tar.gz", ".tar.bz2", ".tar.xz", ".sqlite",
            ".sqlite3", ".db", ".vmdk", ".img", ".qcow2", ".vdi", ".iso", ".docker", ".oci",
            ".xlsx", ".csv", ".ods", ".kdbx", ".1pif", ".sql", ".apk", ".aab", ".dmg", ".pcap",
            ".pcapng", ".ovpn", ".tfstate", ".tfplan", ".tfvars",
        ];

        let sensitive_filenames = [
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            "id_xmss",
            "master.age",
            "identity.age",
            "owner.age",
            "dracon-key",
            "id_rsa.pub",
            "id_ed25519.pub",
            "credentials",
            ".bash_history",
            ".zsh_history",
            ".sh_history",
            "core",
            "known_hosts",
            "vault.yml",
            ".terraform.lock.hcl",
            "terraform.tfvars",
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.staging",
            ".npmrc",
            ".pypirc",
            "netrc",
            ".pgpass",
            ".my.cnf",
        ];

        let filename = std::path::Path::new(path_str)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // Check if any path component exactly matches a sensitive directory name.
        // Using component-level matching avoids false positives like "my.ssh.config"
        // matching ".ssh" via substring contains.
        let path_components: Vec<&str> = std::path::Path::new(path_str)
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();

        // Single-component matching
        let has_single_component = sensitive_dirs
            .iter()
            .any(|dir| !dir.contains('/') && path_components.contains(dir));
        // Multi-component sequence matching (e.g. ".config/gcloud")
        let has_multi_component = sensitive_dirs.iter().any(|dir| {
            let parts: Vec<&str> = dir.split('/').collect();
            if parts.len() < 2 {
                return false;
            }
            path_components
                .windows(parts.len())
                .any(|window| window == parts.as_slice())
        });

        let is_sensitive_location = has_single_component
            || has_multi_component
            || sensitive_exts.iter().any(|ext| path_str.ends_with(ext))
            || sensitive_filenames.contains(&filename)
            || sensitive_filenames
                .iter()
                .any(|p| filename == *p || filename.starts_with(&format!("{}.", p)))
            || self
                .managed_patterns
                .iter()
                .any(|p| filename == p || path_str.contains(p))
            // ADDED (media option): media-matched binaries whole-file
            // encrypt via the binary arm below. Gitattributes-style
            // matching (empty list matches nothing), not the naive
            // substring rule above.
            || path_matches_any_pattern(path_str, &self.media_patterns);

        // 2. Process based on content type
        match std::str::from_utf8(content) {
            Ok(text_content) => {
                // Full encryption for sensitive files that shouldn't leak structure
                let is_full_encrypt = (is_sensitive_location
                    && (filename.starts_with(".env")
                        || filename == "credentials"
                        || filename.starts_with(".bash_history")
                        || filename.starts_with(".zsh_history")
                        || filename.starts_with(".sh_history")
                        || filename == "vault.yml"))
                    // ADDED 2026-09-15 (warden-showcase probe): a credentials
                    // JSON whose secrets sit under scanner floors (short values,
                    // non-keyword key names like "stripe"/"url") passed through
                    // inline scanning untouched. A file literally named creds.json
                    // declares credentials content, so it gets the same whole-file
                    // treatment as "credentials". This arm stands outside the
                    // is_sensitive_location conjunction because that heuristic's
                    // naive substring check does not understand `**` globs at
                    // depth; reaching this line already proves the path cleared
                    // the protected-patterns gate above.
                    // EXTENDED 2026-09-15 (showcase round 2): same treatment for
                    // keys.json — another credential-declaring filename found
                    // carrying provider secrets in the wild.
                    || filename == "creds.json"
                    || filename == "keys.json"
                    // ADDED 2026-09-30: LLM conversation/session exports
                    // (`conversation-*.txt`, `pi-session-*.html`, ...) carry
                    // pasted secrets and PII in free prose, so the whole file
                    // is encrypted instead of inline-scanning it. Filename
                    // arm like creds.json: reaching this line already proves
                    // the path cleared the protected-patterns gate above
                    // (the shipped conversation defaults opt these in).
                    || is_llm_conversation_dump(filename);
                if is_full_encrypt {
                    // Don't double-encrypt
                    if content.starts_with(HEADER_V2_MAGIC)
                        || self.starts_with_any_secret_tag(content)
                    {
                        return Ok(content.to_vec());
                    }
                    // Add/increment version header for .env files to track changes
                    let content_to_encrypt = if filename.starts_with(".env") {
                        // Managed = the warden header block sits at the top of
                        // the file (NOT any comment mentioning Dracon Warden —
                        // that false-positive yielded wrong/duplicated header
                        // versions, audit LOW 2026-08-10).
                        if is_env_version_managed(text_content) {
                            // Remove old header and add new one with incremented version.
                            // FIXED 2026-08-12 (audit LOW): do NOT `.trim()` the
                            // stripped body — strip_env_version_header already skips
                            // the newlines right after the closing marker, and the
                            // body's own trailing blank lines / leading indentation
                            // must survive re-encryption byte-exact (trim made every
                            // re-encrypt of a .env ending in a newline rewrite the
                            // file).
                            let stripped = strip_env_version_header(text_content);
                            format!("{}\n{}", make_env_version_header(text_content), stripped)
                        } else {
                            // First time encryption - add v1 header
                            format!(
                                "{}\n{}",
                                make_env_version_header(text_content),
                                text_content
                            )
                        }
                    } else {
                        text_content.to_string()
                    };
                    return self.encrypt_v2_to_b64_tag(content_to_encrypt.as_bytes());
                }
                // For identity files (master.age, identity.age), use a scanner that
                // skips age key patterns to avoid encrypting the identity itself,
                // but still catches other embedded secrets like API keys.
                let is_identity_file = filename == "master.age" || filename == "identity.age";
                let cleaned = if is_identity_file {
                    let scanner = SecretScanner::new_without_age_keys()?;
                    self.smart_clean_with_scanner(text_content, &scanner)?
                } else {
                    self.smart_clean(text_content)?
                };
                Ok(cleaned.into_bytes())
            }
            Err(_) => {
                // Binary Data: Only encrypt if it is in a sensitive location
                if is_sensitive_location {
                    // Don't double-encrypt
                    if content.starts_with(HEADER_V2_MAGIC)
                        || self.starts_with_any_secret_tag(content)
                    {
                        return Ok(content.to_vec());
                    }
                    self.encrypt_v2_to_b64_tag(content)
                } else {
                    // Normal binary path -> Passthrough (preserves images, etc)
                    Ok(content.to_vec())
                }
            }
        }
    }

    pub fn smart_smudge(&self, content: &str) -> Result<String> {
        let markers = self.secret_tag_prefixes();
        let mut result = String::new();
        let mut last_end = 0;

        while last_end < content.len() {
            let mut next: Option<(usize, usize)> = None;
            for marker in &markers {
                if let Some(start_idx) = content[last_end..].find(marker) {
                    let absolute_start = last_end + start_idx;
                    let marker_len = marker.len();
                    if next
                        .map(|(best_idx, _)| absolute_start < best_idx)
                        .unwrap_or(true)
                    {
                        next = Some((absolute_start, marker_len));
                    }
                }
            }

            let Some((absolute_start, marker_len)) = next else {
                break;
            };

            result.push_str(&content[last_end..absolute_start]);

            // Find closing bracket
            if let Some(end_offset) = content[absolute_start..].find(']') {
                let absolute_end = absolute_start + end_offset + 1;
                let b64 = &content[absolute_start + marker_len..absolute_end - 1];

                match general_purpose::STANDARD.decode(b64.trim()) {
                    Ok(encrypted) => match self.unlock_payload(&encrypted) {
                        Ok(plaintext) => match String::from_utf8(plaintext) {
                            Ok(text) => result.push_str(&text),
                            // FIXED 2026-10-03 (audit L9): non-UTF8
                            // plaintext can never be represented in
                            // `String` smudge output — the old
                            // `from_utf8_lossy` corrupted it (U+FFFD)
                            // and the next clean re-encrypted the
                            // corruption. Preserve the tag verbatim
                            // (fail closed, like the Err arms).
                            Err(_) => {
                                result.push_str(&content[absolute_start..absolute_end]);
                            }
                        },
                        Err(_) => result.push_str(&content[absolute_start..absolute_end]),
                    },
                    Err(_) => result.push_str(&content[absolute_start..absolute_end]),
                }
                last_end = absolute_end;
            } else {
                // No closing bracket found, treat as normal text
                result.push_str(&content[absolute_start..]);
                last_end = content.len();
            }
        }

        result.push_str(&content[last_end..]);
        Ok(result)
    }

    pub fn migrate_markers_in_path(
        &self,
        root: &Path,
        recursive: bool,
        dry_run: bool,
        from_marker: &str,
        to_marker: &str,
    ) -> Result<MarkerMigrationStats> {
        let from = normalize_secret_marker(from_marker)
            .ok_or_else(|| anyhow::anyhow!("Invalid source marker: {}", from_marker))?;
        let to = normalize_secret_marker(to_marker)
            .ok_or_else(|| anyhow::anyhow!("Invalid target marker: {}", to_marker))?;

        let from_prefix = format!("[{}:", from);
        let to_prefix = format!("[{}:", to);
        let mut stats = MarkerMigrationStats::default();

        if !root.exists() {
            return Err(anyhow::anyhow!("Path does not exist: {:?}", root));
        }

        let mut process_file = |path: &Path| -> Result<()> {
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return Ok(()),
            };
            stats.files_scanned += 1;

            let count = content.matches(&from_prefix).count();
            if count == 0 {
                return Ok(());
            }

            let migrated = content.replace(&from_prefix, &to_prefix);
            if !dry_run {
                fs::write(path, migrated)?;
            }

            stats.files_changed += 1;
            stats.markers_changed += count;
            Ok(())
        };

        if root.is_file() {
            process_file(root)?;
            return Ok(stats);
        }

        let walker = walkdir::WalkDir::new(root)
            .follow_links(false) // FDRACONWARDEN-003 (2026-07-18): don't follow symlinks in migrate walk either.
            .max_depth(if recursive { usize::MAX } else { 1 })
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                if e.path() == root {
                    return true;
                }
                !name.starts_with('.') || name == ".env"
            });

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "⚠️ walk error during marker scan at {}: {}",
                        root.display(),
                        e
                    );
                    stats.walk_errors += 1;
                    continue;
                }
            };
            if entry.file_type().is_file() {
                if let Err(e) = process_file(entry.path()) {
                    eprintln!("⚠️ failed to process {}: {}", entry.path().display(), e);
                }
            }
        }

        if stats.walk_errors > 0 {
            return Err(anyhow::anyhow!(
                "migrate_markers_in_path completed with {} walk error(s)",
                stats.walk_errors
            ));
        }

        Ok(stats)
    }
}

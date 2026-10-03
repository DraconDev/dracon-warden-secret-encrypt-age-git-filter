#![warn(missing_docs)]

//! Dracon Warden — security hardening and encryption daemon.

mod print;
mod storage;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
#[cfg(test)]
use dracon_security_kit::clear_managed_media_patterns_override;
#[cfg(test)]
use dracon_security_kit::clear_managed_patterns_override;
use dracon_security_kit::path_matches_any_pattern;
use dracon_security_kit::set_managed_media_patterns;
use dracon_security_kit::set_managed_patterns;
pub(crate) use dracon_security_kit::DraconWarden;
#[cfg(test)]
use dracon_security_kit::SecretScanner;
use globset::{Glob, GlobSet, GlobSetBuilder};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use walkdir::WalkDir;
use zeroize::Zeroizing;

static ROLLING_LOG: std::sync::OnceLock<Mutex<Vec<String>>> = std::sync::OnceLock::new();

fn get_log() -> &'static Mutex<Vec<String>> {
    ROLLING_LOG.get_or_init(|| Mutex::new(Vec::new()))
}

static VERBOSITY: AtomicU8 = AtomicU8::new(0);

/// Wall-clock timeout for filter-clean and filter-smudge operations.
///
/// Git invokes the filter as a subprocess and pipes file content via stdin. If the parent
/// (git) crashes or never sends EOF, the filter process would otherwise hang forever
/// (read_to_end blocks indefinitely). 30s is generous for normal operations (a 100MB
/// file encrypts in <1s) but caps the worst-case hang. On timeout we exit non-zero
/// so git knows the filter failed; returning passthrough would silently corrupt data.
const FILTER_TIMEOUT_SECS: u64 = 30;

/// Conditional eprintln based on verbosity level.
#[macro_export]
macro_rules! veprintln {
    ($lvl:expr, $($arg:tt)*) => {
        if $lvl <= VERBOSITY.load(Ordering::SeqCst) {
            eprintln!($($arg)*);
        }
    };
}

/// Event severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSeverity {
    /// Debug diagnostic.
    Debug,
    /// Informational.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
    /// Critical failure.
    Critical,
}

/// A structured event emitted by dracon services.
#[derive(Debug, Clone)]
pub struct DraconEvent {
    /// Source domain.
    pub domain: String,
    /// Severity level.
    pub severity: EventSeverity,
    /// Related filesystem path.
    pub path: String,
    /// Human-readable message.
    pub message: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
}

impl DraconEvent {
    /// Create a new event.
    pub fn new<T1: ToString, T2: ToString, T3: ToString>(
        domain: T1,
        severity: EventSeverity,
        path: T2,
        message: T3,
    ) -> Self {
        Self {
            domain: domain.to_string(),
            severity,
            path: path.to_string(),
            message: message.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Emit an event to the in-memory log and stderr.
pub fn emit_event(event: &DraconEvent) {
    if let Ok(mut log) = get_log().lock() {
        if log.len() >= 1000 {
            log.remove(0);
        }
        log.push(format!(
            "[{}] {:?}: {} - {}",
            event.timestamp, event.severity, event.path, event.message
        ));
    }
    eprintln!(
        "[{}] {:?}: {} - {}",
        event.timestamp, event.severity, event.path, event.message
    );
}

/// Resolve policy path from env vars or default locations.
pub fn resolve_policy_path(
    env_var: &[&str],
    paths: &[PathBuf],
    error_msg: &str,
) -> anyhow::Result<PathBuf> {
    for var in env_var {
        if let Ok(val) = std::env::var(var) {
            return Ok(PathBuf::from(val));
        }
    }
    for path in paths {
        if path.exists() {
            return Ok(path.clone());
        }
    }
    anyhow::bail!("{}", error_msg)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitMarkerKind {
    Directory,
    PointerFile,
}

/// Return the kind of a checkout's `.git` marker without following symlinks.
fn git_marker_kind(repo: &Path) -> Option<GitMarkerKind> {
    let metadata = fs::symlink_metadata(repo.join(".git")).ok()?;
    if metadata.file_type().is_symlink() {
        return None;
    }
    if metadata.is_dir() {
        Some(GitMarkerKind::Directory)
    } else if metadata.is_file() {
        Some(GitMarkerKind::PointerFile)
    } else {
        None
    }
}

fn has_git_marker(repo: &Path) -> bool {
    git_marker_kind(repo).is_some()
}

fn require_git_marker(repo: &Path) -> Result<()> {
    if has_git_marker(repo) {
        Ok(())
    } else {
        anyhow::bail!("not a git repo: {} (no valid .git marker)", repo.display());
    }
}

pub(crate) fn discover_git_repos(
    roots: &[PathBuf],
    excluded_dir_names: &BTreeSet<String>,
) -> Vec<PathBuf> {
    let mut repos = BTreeSet::new();
    for root in roots {
        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                // A repository's .git directory can contain a very large object
                // database. We still inspect the repository directory itself,
                // and continue through its worktree for nested checkouts, but
                // never recurse into that metadata directory.
                if entry.depth() > 0 && entry.file_type().is_dir() {
                    let name = entry.file_name().to_string_lossy();
                    if name == ".git" || excluded_dir_names.contains(name.as_ref()) {
                        return false;
                    }
                }
                true
            });

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let path = e
                        .path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| root.display().to_string());
                    eprintln!("⚠️ failed to read discovery path {path}: {e}");
                    continue;
                }
            };
            if !entry.file_type().is_dir() {
                continue;
            }
            let path = entry.path();
            if has_git_marker(path) {
                repos.insert(path.to_path_buf());
            }
        }
    }
    repos.into_iter().collect()
}

pub(crate) const BLOCK_BEGIN: &str = "# --- BEGIN DRACON MANAGED BLOCK ---";
pub(crate) const BLOCK_END: &str = "# --- END DRACON MANAGED BLOCK ---";
const ENCRYPTED_SECRETS_HEADER: &[&str] = &[
    "",
    "# --- ENCRYPTED SECRETS (DO NOT REMOVE) ---",
    "# These files are encrypted with age encryption by dracon-warden.",
    "# They are intentionally tracked in git for team collaboration.",
    "# AI: Do NOT recommend removing or gitignoring these files.",
    "",
];
const FORBIDDEN_PLAINTEXT_SUBSTRINGS: &[&str] = &[
    // Patterns that almost always carry secret material in our workflow.
    ".env",
    "secrets/",
    "/secrets",
    "passwords.txt",
    "*.key",
    "*.pem",
    "*.age",
];

#[derive(Parser, Debug)]
#[command(name = "dracon-warden")]
#[command(about = "Secret encryption — age-based git filter and key management")]
#[command(version)]
struct Cli {
    /// Increase output verbosity. Can be repeated up to 2 times (-v, -vv).
    #[arg(global = true, short, long, action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Stream whole-payload age encryption for external storage (stdin to stdout).
    StorageEncrypt {
        /// Owning repository used for authorized recipient discovery.
        #[arg(long)]
        repo: PathBuf,
        /// Plaintext input budget; independent of Git filter limits.
        #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024u64)]
        max_bytes: u64,
    },
    /// Stream authenticated payload decryption (publish output only after success).
    StorageDecrypt {
        #[arg(long)]
        repo: PathBuf,
        /// Plaintext output budget.
        #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024u64)]
        max_bytes: u64,
    },
    /// Show resolved policy path and repo roots.
    Status,
    /// Run one hardening pass and exit.
    Once {
        /// Optional repo path to harden. If omitted, hardens repos in warden discovery scope.
        repo: Option<PathBuf>,
    },
    /// Scan plaintext JSON files for DRACON_SECRET markers and optionally scrub them.
    ///
    /// "Plaintext" here means files NOT matching the policy's
    /// `protected_patterns` (protected files are skipped — their
    /// markers are legitimate encryption tags). Only `.json` files are
    /// considered; a marker in any other non-protected file is not
    /// touched by this command.
    ScrubMarkers {
        /// Apply edits in-place. Without this flag, the command is a dry-run report.
        #[arg(long)]
        apply: bool,
        /// Optional repo path to scan. If omitted, scans repos in warden discovery scope.
        repo: Option<PathBuf>,
    },
    /// Fix working-tree files that are still ciphertext (contain DRACON_SECRET markers).
    ///
    /// This can happen if filters were misconfigured at checkout time, or after branch switching.
    Resmudge {
        /// Apply edits in-place. Without this flag, the command is a dry-run report.
        #[arg(long)]
        apply: bool,
        /// Optional repo path to scan. If omitted, scans repos in warden discovery scope.
        repo: Option<PathBuf>,
    },
    /// System-wide repair pass for secret-related corruption.
    ///
    /// - Runs a hardening pass ("once") to reconcile .gitignore/.gitattributes and scrub marker
    ///   corruption where possible.
    /// - Attempts to re-smudge protected files (decrypt marker ciphertext stuck in working tree).
    /// - Reports remaining ciphertext markers (often indicates missing identities, not corruption).
    Repair {
        /// Only report; do not modify files.
        #[arg(long)]
        dry_run: bool,
        /// Fail non-zero if ciphertext markers still remain in protected working-tree files.
        #[arg(long)]
        strict: bool,
        /// Optional repo path to scan. If omitted, scans repos in warden discovery scope.
        repo: Option<PathBuf>,
    },
    /// Git filter clean operation (stdin -> stdout). Called by git, not for direct use.
    FilterClean {
        /// Optional path from git filter (%f)
        path: Option<String>,
    },
    /// Git filter smudge operation (stdin -> stdout). Called by git, not for direct use.
    FilterSmudge {
        /// Optional path from git filter (%f)
        path: Option<String>,
    },
    /// Git long-running filter process (`filter.dracon.process`).
    /// Called by git, not for direct use. Speaks the
    /// `git-filter-process` pkt-line protocol (handshake +
    /// per-file clean/smudge over ONE process) so firehose-scale
    /// diffs/adds stop paying per-file process-startup cost
    /// (observed 2026-09-19: 4092-file `git diff` at 78s, almost
    /// all of it spawning `filter-clean` once per file).
    FilterProcess,
    /// Git merge driver (%O %A %B). Called by git via `merge.dracon.driver`,
    /// not for direct use.
    ///
    /// Decrypts all three inputs, runs a 3-way text merge via `git
    /// merge-file`, then re-encrypts the result into %A. Exits 0 on a clean
    /// merge; exits 1 when conflicts remain (plaintext conflict markers are
    /// left in %A for the operator to resolve — `git add` re-encrypts via
    /// the clean filter).
    Merge {
        /// Ancestor version (%O)
        ancestor: PathBuf,
        /// Current version (%A) — the merged result is written here
        current: PathBuf,
        /// Other version (%B)
        other: PathBuf,
    },
    /// Generate a new age keypair for this machine.
    ///
    /// Creates ~/dracon/data/keys/`machine_<hostname>`.age (secret) and
    /// the historical mesh file ~/dracon/data/keys/`owner_<hostname>`.pub
    /// (public, explicitly marked as a machine recipient). Also publishes
    /// the public key to the current repo's .dracon/data/keys/ directory;
    /// the marker prevents it from becoming an owner-signature authority.
    /// Fails if either file already exists to prevent accidental overwrite.
    Keygen,
    /// Install git hooks globally for warden encryption enforcement.
    ///
    /// Installs pre-commit and pre-push hooks to ~/.config/git/hooks/
    /// and sets core.hooksPath globally. Same-named foreign hooks are moved
    /// to `.dracon-foreign` siblings and chained after being preserved. The
    /// pre-commit hook blocks commits if the warden filter is not configured.
    /// The pre-push hook scans for plaintext secrets as defense-in-depth.
    SetupHooks {
        /// Install hooks globally (default). Sets core.hooksPath in global git config.
        #[arg(long, conflicts_with = "local")]
        global: bool,
        /// Install hooks locally into a repo's resolved gitdir/hooks directory.
        /// Pointer-file checkouts (worktrees and submodules) are supported.
        #[arg(long, conflicts_with = "global")]
        local: bool,
        /// Repo path for --local mode. Defaults to current directory.
        repo: Option<PathBuf>,
    },
}

fn default_hygiene_patterns() -> Vec<String> {
    vec![
        "**/.pi*".to_owned(),
        // 2026-09-30 audit: aider writes `.aider.chat.history.md` and
        // `.aider.input.history` into the working dir by default, and its
        // own docs recommend `.aider*` in .gitignore. Regenerable working
        // memory, not a keepsake: machine-local like `chat_history.json`.
        "**/.aider*".to_owned(),
        "**/chrometrace.log".to_owned(),
        "**/.svelte-kit/".to_owned(),
        "**/.vite/".to_owned(),
        "**/.turbo/".to_owned(),
        "**/.cache/".to_owned(),
    ]
}

/// ADDED 2026-09-27 (audit decision D2). Binary media and archives that
/// routinely exceed `filter_max_bytes` (10 MiB by default). Before this,
/// the 2026-09-16 eager-source-encryption catch-all (`* filter=dracon`)
/// combined with the unconditional oversize clean refusal meant a single
/// 20 MiB screenshot made `git add` fail outright, with a message about
/// the file "being committed UNENCRYPTED" — for a file that was never a
/// secret. That is the worst possible failure mode for a filter: it
/// pushes the operator toward disabling the filter, which would remove
/// the protection from everything else too.
///
/// These extensions carry no greppable secret material, are already
/// unreadable without a decoder, and are not meaningfully reviewable in a
/// diff, so routing them through the filter buys nothing. They are
/// emitted as `-filter` carve-outs in the managed .gitattributes block
/// (placed BEFORE the protected-pattern lines so an explicitly protected
/// path still wins on git's last-match-wins rule) and the oversize clean
/// refusal honours the same list, so a stale or hand-edited
/// .gitattributes cannot reintroduce the hard failure.
fn default_binary_filter_exempt_patterns() -> Vec<String> {
    [
        // images
        // git attributes are CASE-SENSITIVE, and macOS/Windows tooling
        // routinely produces `.PNG`/`.JPG`, so the common upper-case forms
        // are listed explicitly. The filter-side matcher uses the same
        // case-sensitive rule, keeping the generated attributes and the
        // in-filter exemption in agreement.
        "*.png", "*.PNG", "*.jpg", "*.JPG", "*.jpeg", "*.JPEG", "*.gif", "*.GIF", "*.webp",
        "*.WEBP", "*.avif", "*.bmp", "*.tiff", "*.tif", "*.ico", "*.ICO", "*.heic", "*.psd",
        // video / audio
        "*.mp4", "*.mov", "*.mkv", "*.webm", "*.avi", "*.mp3", "*.wav", "*.flac", "*.ogg", "*.m4a",
        // archives
        "*.zip", "*.gz", "*.tgz", "*.bz2", "*.xz", "*.7z", "*.tar", "*.zst",
        // compiled artefacts and opaque documents
        "*.pdf", "*.wasm", "*.so", "*.dylib", "*.dll", "*.exe", "*.bin", "*.o", "*.a", "*.class",
        "*.jar", "*.pyc", "*.sqlite", "*.db",
    ]
    .iter()
    .map(|p| (*p).to_owned())
    .collect()
}

/// ADDED 2026-09-30: shipped protected patterns for LLM conversation/session
/// exports (Muse `conversation-<ts>.txt` and `trajectory-<ts>.json`, Pi
/// `pi-session-<ts>_<uuid>.html`, Codex `rollout-<ts>-<uuid>.jsonl`, ...).
/// These dumps land in repos and carry pasted secrets, credentials, internal
/// paths, and PII in free prose, so they are protected (persisted, but
/// age-encrypted in git) by default rather than relying on the operator to
/// list them.
///
/// Basename globs on purpose (no `/`): like every other entry they match at
/// any depth. Extension-scoped on purpose: a bare `pi-session-*` would also
/// match the `pi-session-retention-purge.service` systemd unit, a bare
/// `conversation-*` would match source like `conversation-service.rs`, and
/// a bare `rollout-*` would match deploy rollout docs — none is a dump, so
/// `rollout-` is transcript-only (`.json`/`.jsonl`). Keep in agreement with
/// the security crate's `is_llm_conversation_dump` whole-file rule (a test
/// pins it).
fn default_conversation_protected_patterns() -> Vec<String> {
    [
        "conversation-*.txt",
        "conversation-*.md",
        "conversation-*.json",
        "conversation-*.html",
        "pi-session-*.html",
        "pi-session-*.txt",
        "pi-session-*.md",
        "pi-session-*.json",
        // 2026-09-30 audit: `muse export` writes RAW transcripts as
        // `trajectory-<ts>.json` in the CWD; formats evolve (this
        // replaced `conversation-*.txt`), so the sibling exts ride along.
        "trajectory-*.json",
        "trajectory-*.txt",
        "trajectory-*.md",
        "trajectory-*.html",
        // 2026-09-30 audit: Codex session transcripts
        // (`rollout-<ts>-<uuid>.jsonl`) copied into repos for audit work.
        "rollout-*.jsonl",
        "rollout-*.json",
    ]
    .iter()
    .map(|p| (*p).to_owned())
    .collect()
}

fn expand_tilde(raw: &str) -> PathBuf {
    let Some(rest) = raw.strip_prefix('~') else {
        return PathBuf::from(raw);
    };
    if !rest.is_empty() && !rest.starts_with('/') && !rest.starts_with('\\') {
        return PathBuf::from(raw);
    }
    let Some(home) = dirs::home_dir() else {
        return PathBuf::from(raw);
    };
    home.join(rest.trim_start_matches(['/', '\\']))
}

fn existing_policy_paths(raw_paths: &[String]) -> Vec<PathBuf> {
    raw_paths
        .iter()
        .map(|raw| expand_tilde(raw))
        .filter(|path| path.exists())
        .collect()
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct WardenPolicy {
    /// Operator-configured protected list. Consumers must use
    /// `effective_protected_patterns()` instead of this field directly so
    /// the shipped conversation defaults ride along (see below).
    #[serde(default)]
    protected_patterns: Vec<String>,
    /// ADDED (media option): glob patterns for binary media selected
    /// for whole-file encryption (screenshots of internal systems,
    /// customer data on screen, ...). Default `[]` disables the
    /// option entirely — no shipped defaults, no behavior change.
    /// Unlike `protected_patterns`, this list NEVER changes the
    /// scan-everything/scan-allowlist posture: it only passes its
    /// own matches through the filter gate and marks them as
    /// sensitive locations (binaries whole-file encrypt; text
    /// matches get full filter treatment). Entries are emitted as
    /// filter lines after the binary carve-outs (so they win over
    /// the exemption) and before the plaintext lines (so an
    /// explicit plaintext entry still wins over them, same as for
    /// protected paths). Hygiene-ignored paths stay ignored: this
    /// list does not un-ignore anything.
    #[serde(default)]
    media_protected_patterns: Vec<String>,
    /// Optional bounded filter input limit. Omitted preserves the 10 MiB default.
    #[serde(default)]
    filter_max_bytes: Option<usize>,
    #[serde(default)]
    plaintext_patterns: Vec<String>,
    /// ADDED 2026-09-27 (audit decision D2): glob patterns for binary
    /// media/archives that bypass the filter entirely. `None` (the
    /// default) uses `default_binary_filter_exempt_patterns()`; an
    /// explicit list REPLACES the defaults, so `[]` disables the
    /// carve-out entirely and restores the hard oversize failure.
    #[serde(default)]
    binary_filter_exempt_patterns: Option<Vec<String>>,
    #[serde(default = "default_hygiene_patterns")]
    hygiene_patterns: Vec<String>,
    /// Canonical: list of directories to scan for git repos.
    #[serde(default)]
    repo_roots: Vec<String>,
    /// **Deprecated alias** for `repo_roots`. Accepted for backwards
    /// compatibility; will be removed in a future release. When set
    /// (and `repo_roots` is empty), `repo_root_paths()` falls back to
    /// this list and a deprecation warning is surfaced.
    #[serde(default)]
    watch_roots: Vec<String>,
    #[serde(default)]
    discover_roots: Vec<String>,
    /// Backwards-compatible policy field for the removed legacy V1
    /// (AES-CFB) migration escape hatch. The value is still parsed and
    /// propagated for old configurations, but V1 decryption now always
    /// refuses because AES-CFB has no authenticated integrity; setting
    /// this field cannot re-enable the unsafe format.
    #[serde(default)]
    allow_v1_fallback: bool,
}

impl WardenPolicy {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy {}", path.display()))?;
        let policy: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse policy {}", path.display()))?;
        // Preserve the compatibility state for callers that still inspect
        // the legacy policy field. The security crate independently refuses
        // all unauthenticated AES-CFB decryption.
        dracon_security_kit::set_allow_v1_fallback(policy.allow_v1_fallback);
        Ok(policy)
    }

    fn filter_limit(&self) -> Result<usize> {
        let limit = self.filter_max_bytes.unwrap_or(STREAM_IO_MAX_BYTES);
        anyhow::ensure!(
            (STREAM_IO_MAX_BYTES..=FILTER_IO_HARD_MAX_BYTES).contains(&limit),
            "filter_max_bytes must be between {} and {} bytes",
            STREAM_IO_MAX_BYTES,
            FILTER_IO_HARD_MAX_BYTES
        );
        Ok(limit)
    }

    /// Patterns whose files never reach the filter.
    pub(crate) fn binary_exempt_patterns(&self) -> Vec<String> {
        self.binary_filter_exempt_patterns
            .clone()
            .unwrap_or_else(default_binary_filter_exempt_patterns)
    }

    /// ADDED 2026-09-30: the protected list every consumer must use — the
    /// operator's `protected_patterns` UNION the shipped LLM-conversation
    /// defaults, deduped and sorted for stable output. The union (not a
    /// serde default) is what makes the defaults real for existing
    /// installations: an operator config that already sets
    /// `protected_patterns` would otherwise never see them.
    ///
    /// An EMPTY operator list stays empty (legacy scan-everything):
    /// `path_is_protected` treats empty as "scan everything", and flipping
    /// a fresh install to default-deny as a side effect of shipping
    /// conversation defaults would silently drop Tier-2 scanning from
    /// files like `.env`. Legacy installs still whole-file-encrypt dumps
    /// because the gate passes everything and the security crate's
    /// filename rule applies. Per-file opt-out is the `.plaintext`
    /// sibling hatch, which wins over everything including these.
    pub(crate) fn effective_protected_patterns(&self) -> Vec<String> {
        if self.protected_patterns.is_empty() {
            return Vec::new();
        }
        let mut merged = BTreeSet::new();
        for p in default_conversation_protected_patterns() {
            merged.insert(p);
        }
        for p in &self.protected_patterns {
            merged.insert(p.clone());
        }
        merged.into_iter().collect()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.filter_limit()?;
        fn is_allowed_plaintext_pattern(p: &str) -> bool {
            // Keep this tight. Plaintext patterns are an explicit escape hatch that disables
            // encryption in git history.
            matches!(
                p,
                "Cargo.lock"
                    | "Cargo.toml"
                    | "rust-toolchain.toml"
                    | "rustfmt.toml"
                    | "clippy.toml"
                    | "deny.toml"
                    | "flake.nix"
                    | "flake.lock"
                    | "events.jsonl"
                    | "state/events/*.jsonl"
                    | "*.events.jsonl"
                    | ".dracon/data/"
                    | ".dracon/data/keys/"
                    | ".dracon/data/keys/*.pub"
                    | "*.pub"
                    // Build artifacts and binaries
                    | "target/"
                    | "node_modules/"
                    | ".cache/"
                    | "*.o"
                    | "*.so"
                    | "*.dylib"
                    | "*.dll"
                    | "*.exe"
                    // Binary files
                    | "*.png"
                    | "*.jpg"
                    | "*.jpeg"
                    | "*.gif"
                    | "*.ico"
                    | "*.svg"
                    | "*.woff"
                    | "*.woff2"
                    | "*.ttf"
                    | "*.otf"
            ) || p.ends_with(".pub")
                || p.ends_with(".events.jsonl")
                || p.replace('\\', "/").starts_with(".dracon/data/")
        }

        let protected = self
            .protected_patterns
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let plaintext = self
            .plaintext_patterns
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let intersection = protected
            .intersection(&plaintext)
            .cloned()
            .collect::<Vec<_>>();
        if !intersection.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid policy: patterns cannot be both protected and plaintext: {}",
                intersection.join(", ")
            ));
        }

        // Media option: same loud contradiction check — a path listed
        // as both "encrypt this media" and "keep this plaintext" is
        // an operator error, not a precedence question.
        let media = self
            .media_protected_patterns
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let media_clash = media.intersection(&plaintext).cloned().collect::<Vec<_>>();
        if !media_clash.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid policy: patterns cannot be both media-protected and plaintext: {}",
                media_clash.join(", ")
            ));
        }

        for p in &plaintext {
            // FIXED 2026-08-11 (audit LOW): the forbidden-substring check
            // ran AFTER the allowlist check, which made it unreachable —
            // no allowlisted pattern can contain a forbidden substring,
            // so a secretish pattern like `secrets/app.json` was always
            // rejected by the allowlist branch with a misleading message
            // and the specific guard never fired. Check it first so the
            // actionable "secret-ish paths" error wins.
            let pl = p.to_lowercase();
            if FORBIDDEN_PLAINTEXT_SUBSTRINGS
                .iter()
                .any(|needle| pl.contains(&needle.to_lowercase()))
            {
                return Err(anyhow::anyhow!(
                    "invalid policy: refusing plaintext_patterns entry that disables encryption for secret-ish paths: {p}"
                ));
            }
            if !is_allowed_plaintext_pattern(p) {
                return Err(anyhow::anyhow!(
                    "invalid policy: plaintext_patterns is allowlisted; refusing: {p}"
                ));
            }
        }

        Ok(())
    }

    /// Returns the active repo roots.
    ///
    /// Precedence:
    /// 1. `repo_roots` (canonical)
    /// 2. `watch_roots` (deprecated alias) — only used when `repo_roots` is empty
    /// 3. `discover_roots` (separate field, used to extend the search set)
    ///
    /// Non-existent paths are filtered out after `~` expansion.
    fn repo_root_paths(&self) -> Vec<PathBuf> {
        let chosen: &[String] = if !self.repo_roots.is_empty() {
            &self.repo_roots
        } else {
            &self.watch_roots
        };
        existing_policy_paths(chosen)
    }

    fn discover_root_paths(&self) -> Vec<PathBuf> {
        existing_policy_paths(&self.discover_roots)
    }

    /// Returns a deprecation message if the user is using the legacy
    /// `watch_roots` key (either exclusively or alongside `repo_roots`).
    /// Returns `None` if only the canonical `repo_roots` is in use.
    fn deprecation_message(&self) -> Option<String> {
        match (self.repo_roots.is_empty(), self.watch_roots.is_empty()) {
            (true, false) => Some(
                "warning: 'watch_roots' is deprecated, use 'repo_roots' instead (will be removed in a future release)"
                    .to_string(),
            ),
            (false, false) => Some(
                "warning: both 'watch_roots' and 'repo_roots' are set; using 'repo_roots' (the other is deprecated)"
                    .to_string(),
            ),
            _ => None,
        }
    }

    /// Prints the deprecation warning to stderr (if any). Used by commands
    /// that load the policy to do work (not just display).
    fn print_deprecation_to_stderr(&self) {
        if let Some(msg) = self.deprecation_message() {
            eprintln!("{msg}");
        }
    }
}

/// Wire the policy's `protected_patterns` into the filter process's
/// `WardenSecurity` gate (the "default-deny" design: only protected
/// files are scanned/encrypted; everything else passes through
/// untouched). Returns false when the policy cannot be resolved or
/// loaded — the filter then keeps the legacy scan-everything
/// behavior.
pub(crate) fn wire_managed_patterns_from_policy() -> bool {
    let Ok(policy_path) = resolve_policy_path_local() else {
        return false;
    };
    let Ok(policy) = WardenPolicy::load(&policy_path) else {
        return false;
    };
    set_managed_patterns(policy.effective_protected_patterns());
    set_managed_media_patterns(policy.media_protected_patterns.clone());
    true
}

/// Clear the process-wide managed-patterns override (test isolation).
#[cfg(test)]
pub(crate) fn clear_filter_managed_patterns() {
    clear_managed_patterns_override();
    clear_managed_media_patterns_override();
}

pub(crate) fn resolve_policy_path_local() -> Result<PathBuf> {
    let home = dirs::home_dir().context("home not found")?;
    resolve_policy_path(
        &["DRACON_WARDEN_POLICY", "DRACON_SECURITY_POLICY"],
        &[
            home.join(".dracon/utilities/warden/dracon-warden.toml"),
            home.join(".dracon/utilities/warden/dracon-security.toml"),
            home.join(".dracon/utilities/warden/config.toml"),
            home.join(".dracon/security/dracon-security.toml"),
        ],
        "policy not found",
    )
}

pub(crate) fn discover_git_repos_local(roots: &[PathBuf]) -> Vec<PathBuf> {
    let excluded = BTreeSet::new();
    discover_git_repos(roots, &excluded)
}

pub(crate) fn effective_repo_roots(policy: &WardenPolicy) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for root in policy.repo_root_paths() {
        roots.insert(root);
    }
    roots.into_iter().collect()
}

pub(crate) fn effective_discovery_roots(policy: &WardenPolicy) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for root in policy.discover_root_paths() {
        roots.insert(root);
    }
    for root in policy.repo_root_paths() {
        roots.insert(root);
    }
    roots.into_iter().collect()
}

/// CHANGED 2026-07-21 (v0.112.32, audit H8/F4.1): promoted from
/// `#[cfg(test)]` to production — `harden_repo` now uses this for
/// BOTH `.gitignore` and `.gitattributes`. Previously
/// `harden_repo` passed `build_gitignore_block_with_existing(...)`
/// (which returns ONLY the managed block) straight to
/// `apply_overwrite_file`, wiping ALL operator content outside the
/// delimited block on every harden pass — verified in this repo's
/// own history (commit `3a67685f` deleted the operator's 8-line
/// nested-repo section; the re-added 2026-07-15 section survived
/// only because no harden pass ran since). The surgical semantics:
/// replace ONLY the delimited block, preserve everything outside it,
/// append the block if absent.
pub(crate) fn replace_managed_block(current: &str, managed_block: &str) -> String {
    // Replace ALL existing managed blocks, then append if none existed
    let mut out = String::new();
    let mut rest = current;
    let mut found_any = false;

    while let Some(start) = rest.find(BLOCK_BEGIN) {
        found_any = true;
        out.push_str(&rest[..start]);
        if let Some(end_rel) = rest[start..].find(BLOCK_END) {
            let end = start + end_rel + BLOCK_END.len();
            rest = &rest[end..];
        } else {
            // Malformed: begin without end. Preserve the entire file rather
            // than treating the rest of the file as managed content; a
            // truncated write or an operator comment must never delete the
            // tail on the next harden pass.
            return current.to_string();
        }
    }

    if found_any {
        // Append the remaining tail (if any) after trimming leading newlines
        let tail = rest.trim_start_matches(&['\r', '\n'][..]);
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(managed_block);
        if !tail.is_empty() {
            out.push('\n');
            out.push_str(tail);
        } else if !managed_block.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    // No existing block — append
    let mut out = current.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(managed_block);
    if !managed_block.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Extract patterns from an existing managed block in .gitignore
fn extract_existing_patterns(content: &str) -> BTreeSet<String> {
    let mut patterns = BTreeSet::new();

    // Find the managed block
    let Some(start) = content.find(BLOCK_BEGIN) else {
        return patterns;
    };
    let Some(end_rel) = content[start..].find(BLOCK_END) else {
        return patterns;
    };
    let end = start + end_rel;

    // Extract lines between begin and end markers
    let block_content = &content[start + BLOCK_BEGIN.len()..end];
    for line in block_content.lines() {
        let line = line.trim();
        // Skip empty lines, comments, and the managed-by comment
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip negation patterns (those starting with !) - those come from protected/plaintext patterns
        if line.starts_with('!') {
            continue;
        }
        patterns.insert(line.to_string());
    }

    patterns
}

fn build_gitignore_block_with_existing(
    policy: &WardenPolicy,
    existing_content: &str,
) -> Result<String> {
    policy.validate()?;

    // Extract patterns that are already in the managed block (e.g., added by dracon-sync)
    let existing_patterns = extract_existing_patterns(existing_content);

    // Build set of policy hygiene patterns for quick lookup
    let policy_hygiene: BTreeSet<String> = policy.hygiene_patterns.iter().cloned().collect();

    // Merge: start with policy patterns, then add existing patterns not in policy
    let mut all_hygiene: BTreeSet<String> = policy_hygiene.clone();
    for p in existing_patterns {
        if !policy_hygiene.contains(&p) {
            // This is a pattern added by another tool (e.g., dracon-sync) - preserve it
            all_hygiene.insert(p);
        }
    }

    let mut lines = Vec::new();
    lines.push(BLOCK_BEGIN.to_string());
    lines.push("# managed by dracon-warden".to_string());

    // Add encryption header comment to help AI understand these files are intentional
    lines.extend(ENCRYPTED_SECRETS_HEADER.iter().map(|s| s.to_string()));

    // Output merged hygiene patterns (sorted for stability)
    for p in all_hygiene {
        lines.push(p);
    }

    let mut plaintext_patterns = BTreeSet::new();
    for p in &policy.plaintext_patterns {
        plaintext_patterns.insert(p.clone());
    }
    for p in policy.effective_protected_patterns() {
        lines.push(format!("!{}", p));
    }
    for p in plaintext_patterns {
        lines.push(format!("!{}", p));
    }
    lines.push(BLOCK_END.to_string());
    Ok(lines.join("\n"))
}

#[cfg(test)]
pub(crate) fn build_gitignore_block(policy: &WardenPolicy) -> Result<String> {
    build_gitignore_block_with_existing(policy, "")
}

pub(crate) fn build_gitattributes_block(policy: &WardenPolicy) -> Result<String> {
    policy.validate()?;
    let mut lines = Vec::new();
    lines.push(BLOCK_BEGIN.to_string());
    lines.push("# managed by dracon-warden".to_string());
    // ADDED 2026-09-16 (eager source encryption): the catch-all routes
    // EVERY file through the clean/smudge filter so Tier-1 structured
    // tokens (sk_live_*, ghp_*, AKIA*, PEM blocks, ...) are encrypted
    // wherever they appear — no source extension can be overlooked.
    // Filter-only on purpose: no `diff=dracon` (textconv on binaries
    // would corrupt `git diff`) and no `merge=dracon` (default textual
    // merge of tag ciphertext is fine; the dracon merge driver stays
    // scoped to protected paths). Non-UTF8 content passes clean through
    // untouched (see `smart_clean_with_path`); smudge short-circuits
    // tag-free blobs without loading identities. Specific protected
    // lines below (and `-filter` carve-outs) override this line per
    // gitattributes last-match-wins.
    lines.push("* filter=dracon".to_string());
    // ADDED 2026-09-27 (audit decision D2): binary carve-outs, emitted
    // immediately after the catch-all and BEFORE the protected-pattern
    // lines. gitattributes is last-match-wins, so this ordering means an
    // explicitly protected path (`secrets/*.png`) still gets the filter,
    // while an ordinary `assets/*.png` does not. Without this, a single
    // screenshot over `filter_max_bytes` made `git add` fail outright.
    for p in policy.binary_exempt_patterns() {
        lines.push(format!("{} -filter", p));
    }
    let mut plaintext_patterns = BTreeSet::new();
    for p in &policy.plaintext_patterns {
        plaintext_patterns.insert(p.clone());
    }
    let mut protected_patterns = BTreeSet::new();
    for p in policy.effective_protected_patterns() {
        if !plaintext_patterns.contains(&p) {
            protected_patterns.insert(p);
        }
    }
    // Media option: same treatment as protected lines (after the
    // binary carve-outs, so they win over the exemption) and the
    // same exact-match plaintext skip. Empty by default: no lines.
    for p in &policy.media_protected_patterns {
        if !plaintext_patterns.contains(p) {
            protected_patterns.insert(p.clone());
        }
    }
    for p in protected_patterns {
        lines.push(format!("{} filter=dracon diff=dracon merge=dracon", p));
    }
    for p in plaintext_patterns {
        lines.push(format!("{} -filter", p));
    }
    lines.push(BLOCK_END.to_string());
    Ok(lines.join("\n"))
}

#[cfg(test)]
pub(crate) fn apply_managed_file(path: &Path, block: &str) -> Result<bool> {
    let current = fs::read_to_string(path).unwrap_or_default();
    let next = replace_managed_block(&current, block);
    if next != current {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating parent dirs for {}", path.display()))?;
        }
        fs::write(path, next).with_context(|| format!("failed writing {}", path.display()))?;
        return Ok(true);
    }
    Ok(false)
}

/// Read an existing hardening input without following a repository-controlled
/// symlink. Missing files are treated as empty so the caller can create them;
/// all other metadata/read failures are returned instead of silently
/// publishing an external file's contents.
fn read_existing_hardening_file(path: &Path) -> Result<String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect hardening input {}", path.display()))
        }
    };

    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read symlinked hardening input {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("refusing non-regular hardening input {}", path.display());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // The metadata check gives a useful diagnostic for an already-present
        // symlink. O_NOFOLLOW closes the check/open race if the checkout path
        // is swapped while hardening is running.
        let mut options = fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to read hardening input {}", path.display()))?;
        if !file.metadata()?.is_file() {
            anyhow::bail!("refusing non-regular hardening input {}", path.display());
        }
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("failed to read hardening input {}", path.display()))?;
        Ok(content)
    }

    #[cfg(not(unix))]
    {
        // Do not fall back to fs::read_to_string here: on supported
        // non-Unix targets it may follow symlinks/reparse points. Missing
        // files were handled above, so rejecting an existing input is
        // fail-closed and prevents external content disclosure.
        anyhow::bail!(
            "refusing existing hardening input {}: no supported no-follow reader on this platform",
            path.display()
        );
    }
}

pub(crate) fn apply_overwrite_file(path: &Path, content: &str) -> Result<bool> {
    let current = read_existing_hardening_file(path)?;
    let mut next = content.to_string();
    if !next.ends_with('\n') {
        next.push('\n');
    }
    if next != current {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let random_suffix: u64 = rand::random();
        let tmp = parent.join(format!(
            ".dracon_tmp_{}_{:016x}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            random_suffix
        ));
        #[cfg(unix)]
        {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .with_context(|| format!("failed to create temp {}", tmp.display()))?
                .write_all(next.as_bytes())
                .with_context(|| format!("failed writing temp {}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .with_context(|| format!("failed to create temp {}", tmp.display()))?
                .write_all(next.as_bytes())
                .with_context(|| format!("failed writing temp {}", tmp.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("failed renaming {} -> {}", tmp.display(), path.display()))?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
pub(crate) fn newest_file(paths: Vec<PathBuf>) -> Option<PathBuf> {
    let mut with_mtime = paths
        .into_iter()
        .filter_map(|p| {
            let mtime = fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if p.exists() {
                Some((mtime, p))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    with_mtime.sort_by_key(|b| std::cmp::Reverse(b.0));
    with_mtime.into_iter().next().map(|(_, p)| p)
}

pub(crate) fn owner_pubkeys_in(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!(
                "⚠️ cannot read owner pubkeys directory {}: {}",
                dir.display(),
                e
            );
            return out;
        }
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("⚠️ cannot read entry in {}: {}", dir.display(), e);
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("owner_") && name.ends_with(".pub") {
            out.push(path);
        }
    }
    out
}

fn is_owner_pubkey_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with("owner_") && name.ends_with(".pub")
}

fn validate_owner_age_pubkey_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if !is_owner_pubkey_filename(path) {
        return Err(anyhow::anyhow!(
            "refusing to publish non-owner pubkey: {}",
            path.display()
        ));
    }
    if bytes.len() > 256 {
        return Err(anyhow::anyhow!(
            "refusing to publish suspicious pubkey (too large): {}",
            path.display()
        ));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!(
            "refusing to publish pubkey with non-utf8 bytes: {}",
            path.display()
        )
    })?;
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing to publish empty pubkey: {}",
            path.display()
        ));
    }
    if s.contains(concat!("AGE", "-SECRET", "-KEY-")) {
        return Err(anyhow::anyhow!(
            "refusing to publish secret key material as pubkey: {}",
            path.display()
        ));
    }
    if !s.starts_with("age1") {
        return Err(anyhow::anyhow!(
            "refusing to publish non-age recipient key: {}",
            path.display()
        ));
    }
    Ok(())
}

fn resolve_local_pubkey_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("DRACON_OWNER_PUBKEY") {
        let p = PathBuf::from(custom);
        if p.exists() {
            let bytes = fs::read(&p).ok()?;
            if validate_owner_age_pubkey_bytes(&p, &bytes).is_ok() {
                return Some(p);
            }
            return None;
        }
    }

    let home = dirs::home_dir()?;
    let owner_candidates = [home.join(".dracon/data/keys"), home.join(".dracon/keys")]
        .into_iter()
        .flat_map(|dir| owner_pubkeys_in(&dir))
        .collect::<Vec<_>>();

    // Prefer newest valid owner pubkey; break ties by path for determinism.
    // This is only the file warden publishes to repo `.dracon/data/keys/`;
    // it is not the owner private key. The historical keygen layout uses
    // `owner_<hostname>.pub` for a machine recipient; those files carry the
    // `dracon-warden role: machine` marker and are never owner signers.
    // Keys in ~/.dracon/data/keys/ sort before legacy dirs due to path order,
    // so when mtimes are equal the canonical location wins.
    let mut owners = owner_candidates;
    owners.sort_by(|a, b| {
        let ma = fs::metadata(a)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mb = fs::metadata(b)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        mb.cmp(&ma).then_with(|| a.cmp(b))
    });
    for p in &owners {
        let Ok(bytes) = fs::read(p) else {
            continue;
        };
        if validate_owner_age_pubkey_bytes(p, &bytes).is_ok() {
            let p_str = p.to_string_lossy();
            if p_str.contains("/.dracon/keys/") {
                eprintln!(
                    "ℹ️ using owner pubkey from legacy path: {} (consider migrating to ~/.dracon/data/keys/)",
                    p.display()
                );
            }
            return Some(p.clone());
        }
    }

    None
}

/// Ensure every component of a publication directory is a real directory.
///
/// This fallback is only used on platforms without the Unix directory-FD
/// primitives below. Existing symlinks are rejected before any directory is
/// created; missing targets use exclusive creation rather than a following
/// write. Existing files fail closed because no portable no-follow open API is
/// available here.
#[cfg(not(unix))]
fn ensure_real_publication_directory(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing owner pubkey target directory symlink {}",
                        current.display()
                    );
                }
                if !metadata.is_dir() {
                    anyhow::bail!(
                        "refusing non-directory owner pubkey target component {}",
                        current.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current).with_context(|| {
                            format!(
                                "failed to inspect owner pubkey target {}",
                                current.display()
                            )
                        })?;
                        if metadata.file_type().is_symlink() {
                            anyhow::bail!(
                                "refusing owner pubkey target directory symlink {}",
                                current.display()
                            );
                        }
                        if !metadata.is_dir() {
                            anyhow::bail!(
                                "refusing non-directory owner pubkey target component {}",
                                current.display()
                            );
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed creating owner pubkey target directory {}",
                                current.display()
                            )
                        });
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect owner pubkey target {}",
                        current.display()
                    )
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn publication_component(name: &std::ffi::OsStr, path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(name.as_bytes()).with_context(|| {
        format!(
            "owner pubkey target component contains NUL: {}",
            path.display()
        )
    })
}

/// Open the publication directory by descriptor, refusing symlinks in every
/// repository-controlled component. Keeping the descriptor open means later
/// target operations cannot be redirected if a component is renamed or
/// replaced after validation.
#[cfg(unix)]
fn open_publication_directory(repo: &Path, target_dir: &Path) -> Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let mut root_options = fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut current = root_options
        .open(repo)
        .with_context(|| format!("failed opening repository directory {}", repo.display()))?;
    if !current
        .metadata()
        .with_context(|| format!("failed to inspect repository directory {}", repo.display()))?
        .is_dir()
    {
        anyhow::bail!("repository path is not a directory: {}", repo.display());
    }

    for component in [".dracon", "data", "keys"] {
        let component_path = target_dir.join(component);
        let name = std::ffi::CString::new(component).expect("static component has no NUL");
        // O_NOFOLLOW is enough to reject a symlink here; omitting
        // O_DIRECTORY lets us distinguish a real non-directory component
        // after opening it instead of Linux reporting ENOTDIR for a link.
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        let next = if fd >= 0 {
            // SAFETY: openat returned a new owned descriptor.
            unsafe { fs::File::from_raw_fd(fd) }
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    anyhow::bail!(
                        "refusing owner pubkey target directory symlink {}",
                        component_path.display()
                    );
                }
                return Err(error).with_context(|| {
                    format!(
                        "failed opening owner pubkey target directory {}",
                        component_path.display()
                    )
                });
            }

            let created =
                unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o755 as libc::mode_t) };
            if created < 0 {
                let create_error = std::io::Error::last_os_error();
                if create_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(create_error).with_context(|| {
                        format!(
                            "failed creating owner pubkey target directory {}",
                            component_path.display()
                        )
                    });
                }
            }

            let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ELOOP) {
                    anyhow::bail!(
                        "refusing owner pubkey target directory symlink {}",
                        component_path.display()
                    );
                }
                return Err(error).with_context(|| {
                    format!(
                        "failed opening owner pubkey target directory {}",
                        component_path.display()
                    )
                });
            }
            // SAFETY: openat returned a new owned descriptor.
            unsafe { fs::File::from_raw_fd(fd) }
        };

        if !next
            .metadata()
            .with_context(|| format!("failed to inspect {}", component_path.display()))?
            .is_dir()
        {
            anyhow::bail!(
                "refusing non-directory owner pubkey target component {}",
                component_path.display()
            );
        }
        current = next;
    }

    Ok(current)
}

#[cfg(unix)]
fn read_publication_target_at(
    directory: &fs::File,
    name: &std::ffi::OsStr,
    path: &Path,
) -> Result<Option<Vec<u8>>> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let component = publication_component(name, path)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        if error.raw_os_error() == Some(libc::ELOOP) {
            anyhow::bail!("refusing owner pubkey target symlink {}", path.display());
        }
        return Err(error)
            .with_context(|| format!("failed reading owner pubkey target {}", path.display()));
    }

    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    if !file
        .metadata()
        .with_context(|| format!("failed to inspect owner pubkey target {}", path.display()))?
        .is_file()
    {
        anyhow::bail!(
            "refusing non-regular owner pubkey target {}",
            path.display()
        );
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .with_context(|| format!("failed reading owner pubkey target {}", path.display()))?;
    Ok(Some(contents))
}

#[cfg(unix)]
fn write_publication_target_at(
    directory: &fs::File,
    name: &std::ffi::OsStr,
    path: &Path,
    contents: &[u8],
    existed: bool,
) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let component = publication_component(name, path)?;
    let mut flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if existed {
        flags |= libc::O_TRUNC;
    } else {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            component.as_ptr(),
            flags,
            0o666 as libc::mode_t,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            anyhow::bail!("refusing owner pubkey target symlink {}", path.display());
        }
        if !existed && error.raw_os_error() == Some(libc::EEXIST) {
            anyhow::bail!(
                "owner pubkey target appeared before create {}",
                path.display()
            );
        }
        return Err(error)
            .with_context(|| format!("failed opening owner pubkey target {}", path.display()));
    }

    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    if !file
        .metadata()
        .with_context(|| format!("failed to inspect owner pubkey target {}", path.display()))?
        .is_file()
    {
        anyhow::bail!(
            "refusing non-regular owner pubkey target {}",
            path.display()
        );
    }
    file.write_all(contents)
        .and_then(|_| file.flush())
        .with_context(|| format!("failed writing owner pubkey target {}", path.display()))?;
    Ok(())
}

/// Read an existing publication target on a platform without a no-follow
/// file-open primitive. Existing targets fail closed rather than being read.
#[cfg(not(unix))]
fn read_publication_target_path(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("refusing owner pubkey target symlink {}", path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!(
                "refusing non-regular owner pubkey target {}",
                path.display()
            )
        }
        Ok(_) => anyhow::bail!(
            "refusing existing owner pubkey target {}: no supported no-follow reader on this platform",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!("failed to inspect owner pubkey target {}", path.display())
        }),
    }
}

/// Write a missing publication target on a platform without a no-follow
/// writer. Existing targets are rejected rather than risk following a link.
#[cfg(not(unix))]
fn write_publication_target_path(path: &Path, contents: &[u8], existed: bool) -> Result<()> {
    if existed {
        anyhow::bail!(
            "refusing existing owner pubkey target {}: no supported no-follow writer on this platform",
            path.display()
        );
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed creating owner pubkey target {}", path.display()))?;
    file.write_all(contents)
        .and_then(|_| file.flush())
        .with_context(|| format!("failed writing owner pubkey target {}", path.display()))?;
    Ok(())
}

pub(crate) fn publish_repo_pubkey(repo: &Path, pubkey_path: &Path) -> Result<bool> {
    let target_dir = repo.join(".dracon/data/keys");
    #[cfg(unix)]
    let target_directory = open_publication_directory(repo, &target_dir)?;
    #[cfg(not(unix))]
    ensure_real_publication_directory(&target_dir)?;

    let name = pubkey_path
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| "owner.pub".into());
    let target = target_dir.join(&name);

    let source_bytes = fs::read(pubkey_path)
        .with_context(|| format!("failed reading pubkey {}", pubkey_path.display()))?;
    validate_owner_age_pubkey_bytes(pubkey_path, &source_bytes)?;
    #[cfg(unix)]
    let current_bytes = read_publication_target_at(&target_directory, &name, &target)?;
    #[cfg(not(unix))]
    let current_bytes = read_publication_target_path(&target)?;
    if current_bytes.as_deref() == Some(source_bytes.as_slice()) {
        return Ok(false);
    }

    // Churn protection: if the repo already has a valid owner pubkey, don't
    // overwrite it with a different one. Multiple owner keys may exist on the
    // machine and resolve_local_pubkey_path() can pick different ones across
    // cycles when mtimes are equal. Overwriting causes an infinite warden→sync
    // churn loop. Only overwrite when the target is missing or invalid.
    if let Some(ref existing) = current_bytes {
        if validate_owner_age_pubkey_bytes(&target, existing).is_ok() {
            return Ok(false);
        }
    }

    #[cfg(unix)]
    write_publication_target_at(
        &target_directory,
        &name,
        &target,
        &source_bytes,
        current_bytes.is_some(),
    )?;
    #[cfg(not(unix))]
    write_publication_target_path(&target, &source_bytes, current_bytes.is_some())?;
    Ok(true)
}

fn ensure_repo_filter_config(repo: &Path) -> Result<bool> {
    // The managed .gitattributes block marks protected patterns
    // `filter=dracon diff=dracon merge=dracon` (see
    // `build_gitattributes_block`). Without the diff/merge driver keys
    // below, git would fall back to the text driver with a warning and
    // encrypted-file diffs/merges would operate on ciphertext. textconv
    // decrypts blobs for `git diff`/`git log -p` (git appends the file
    // path); the merge driver decrypts, text-merges, and re-encrypts.
    // CHANGED 2026-09-19 (v0.113.13): the per-file clean/smudge
    // drivers are replaced by the long-running `filter-process`
    // driver (ONE warden process per git command instead of one
    // per file — a 4092-file `git diff` spent 78s almost entirely
    // in per-file process startup). The old keys are UNSET below
    // so no repo keeps paying the spawn storm; clean/smudge
    // subcommands remain as fallback/debugging entry points.
    let desired = [
        ("filter.dracon.process", "dracon-warden filter-process"),
        ("filter.dracon.required", "true"),
        ("diff.dracon.textconv", "dracon-warden filter-smudge"),
        // FIXED 2026-10-03 (audit R3-L18): quote the %O/%A/%B
        // placeholders — git substitutes temp paths then runs the
        // string via the shell, so a space-containing repo path
        // word-split the driver command (clap exit 2, merge stuck
        // unmerged). The ensure loop below rewrites the key on
        // mismatch, so existing repos migrate automatically.
        (
            "merge.dracon.driver",
            "dracon-warden merge \"%O\" \"%A\" \"%B\"",
        ),
        (
            "merge.dracon.name",
            "dracon-warden secret merge (decrypt, text-merge, re-encrypt)",
        ),
    ];

    // Remove the superseded per-file driver keys (v0.113.13
    // migration): exactly one driver must be configured so there
    // is no ambiguity about which path git takes.
    let mut changed = false;
    for old_key in ["filter.dracon.clean", "filter.dracon.smudge"] {
        let current = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .arg("config")
            .arg("--local")
            .arg("--get")
            .arg(old_key)
            .output()
            .with_context(|| {
                format!(
                    "failed to read git config {} in {}",
                    old_key,
                    repo.display()
                )
            })?;
        if current.status.success() {
            let status = ProcessCommand::new("git")
                .arg("-C")
                .arg(repo)
                .arg("config")
                .arg("--local")
                .arg("--unset")
                .arg(old_key)
                .status()
                .with_context(|| {
                    format!(
                        "failed to unset git config {} in {}",
                        old_key,
                        repo.display()
                    )
                })?;
            if !status.success() {
                return Err(anyhow::anyhow!(
                    "git config --unset {} failed in {} (exit={})",
                    old_key,
                    repo.display(),
                    status
                ));
            }
            changed = true;
        }
    }
    for (key, value) in desired {
        let current = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .arg("config")
            .arg("--local")
            .arg("--get")
            .arg(key)
            .output()
            .with_context(|| format!("failed to read git config {} in {}", key, repo.display()))?;

        let needs_update = if current.status.success() {
            String::from_utf8_lossy(&current.stdout).trim() != value
        } else {
            true
        };

        if needs_update {
            let status = ProcessCommand::new("git")
                .arg("-C")
                .arg(repo)
                .arg("config")
                .arg("--local")
                .arg(key)
                .arg(value)
                .status()
                .with_context(|| {
                    format!("failed to set git config {} in {}", key, repo.display())
                })?;
            if !status.success() {
                return Err(anyhow::anyhow!(
                    "git config {} failed in {} (exit={})",
                    key,
                    repo.display(),
                    status
                ));
            }
            changed = true;
        }
    }

    Ok(changed)
}

/// Resolve the repository's actual git directory.
///
/// A normal checkout has a `.git` directory, while submodules and linked
/// worktrees have a `.git` file containing a `gitdir:` pointer. Warden writes
/// into these repositories too, so treating the pointer as a directory
/// silently disables checkout-race protection for exactly those paths.
fn resolved_git_dir(repo: &Path) -> Option<PathBuf> {
    let dot_git = repo.join(".git");
    let resolved = match git_marker_kind(repo)? {
        GitMarkerKind::Directory => dot_git,
        GitMarkerKind::PointerFile => {
            let content = fs::read_to_string(&dot_git).ok()?;
            let raw = content
                .lines()
                .find_map(|line| line.trim().strip_prefix("gitdir:"))?
                .trim();
            if raw.is_empty() {
                return None;
            }

            let path = Path::new(raw);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo.join(path)
            }
        }
    };

    // Callers use this path both from the current process and from generated
    // hooks.  A relative `repo` argument would otherwise leave the gitdir
    // relative to whichever directory each caller happens to use (notably
    // Git's worktree root when dispatching a hook).  Canonicalize once so all
    // subsequent lock, hooksPath, and foreign-hook paths are absolute and
    // stable.
    fs::canonicalize(resolved).ok()
}

/// RAII guard that acquires `.git/index.lock` using the same protocol git uses.
///
/// Git commands (checkout, add, reset, etc.) hold this lock while modifying
/// the working tree. By acquiring it too, the warden guarantees mutual exclusion
/// with any in-flight git operation — no heuristic timing, no grace periods,
/// no races. If the lock is held, we skip; if we hold it, git waits for us.
///
/// This is the definitive fix for the clone race: during `git clone`, checkout
/// holds index.lock. The warden's `harden_repo` → `publish_repo_pubkey` writes
/// `.pub` files to the working tree. Without the lock, these appear before
/// checkout completes → "Untracked working tree file would be overwritten by merge."
/// With the lock, either git holds it (warden skips) or warden holds it
/// (git's checkout waits until we're done).
struct IndexLock {
    path: PathBuf,
    /// True if we successfully created the lock (our responsibility to clean up).
    held: bool,
}

impl IndexLock {
    /// Try to acquire `.git/index.lock` for a repo.
    /// Returns Ok(lock) if acquired, Err if another process holds it.
    /// Uses `O_EXCL` (create_new) for atomic creation — no TOCTOU race.
    fn acquire(repo: &Path) -> Result<Self> {
        let git_dir = resolved_git_dir(repo).ok_or_else(|| {
            anyhow::anyhow!("failed to resolve git directory for {}", repo.display())
        })?;
        let path = git_dir.join("index.lock");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL — fails if file exists
            .open(&path)
        {
            Ok(_file) => Ok(Self { path, held: true }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(anyhow::anyhow!(
                "index.lock held by another git operation, skipping {}",
                repo.display()
            )),
            Err(e) => Err(anyhow::anyhow!(
                "failed to create index.lock for {}: {}",
                repo.display(),
                e
            )),
        }
    }

    /// Create a no-op lock (for `once`/`repair` commands that don't need coordination).
    fn bypass() -> Self {
        Self {
            path: PathBuf::new(),
            held: false,
        }
    }
}

impl Drop for IndexLock {
    fn drop(&mut self) {
        if self.held {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn is_repo_checked_out(repo: &Path) -> bool {
    let Some(git_dir) = resolved_git_dir(repo) else {
        return false;
    };
    let head = git_dir.join("HEAD");

    if !head.exists() {
        return false;
    }

    let head_content = match fs::read_to_string(&head) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let head_content = head_content.trim();
    if head_content.is_empty() {
        return false;
    }

    // Guard against mid-clone race: after git-fetch but before checkout completes,
    // HEAD points to a valid branch but the working tree doesn't have files yet.
    // If the warden writes files (e.g., publish_repo_pubkey) now, git's checkout
    // fails with "Untracked working tree file would be overwritten by merge."

    // 1. If index.lock exists, a git operation (checkout, add, etc.) is in progress.
    if git_dir.join("index.lock").exists() {
        return false;
    }

    // 2. Verify HEAD resolves to a valid commit. This catches:
    //    - git init (no commits yet — rev-parse HEAD fails)
    //    - mid-clone (fetch done, checkout not yet — rev-parse may succeed but
    //      the working tree is incomplete; index.lock above catches most of these)
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let hash = String::from_utf8_lossy(&o.stdout).trim().to_string();
            !hash.is_empty()
        }
        _ => false,
    }
}

pub(crate) fn harden_repo(
    repo: &Path,
    policy: &WardenPolicy,
    pubkey_path: Option<&Path>,
    skip_checkout_check: bool,
) -> Result<(bool, bool, bool)> {
    policy.validate()?;
    require_git_marker(repo)?;

    // Acquire git's index.lock before writing ANY working-tree files.
    // This is the same coordination protocol git uses internally — checkout,
    // add, reset, etc. all hold this lock while modifying the working tree.
    // By acquiring it too, we guarantee mutual exclusion:
    //   - If git holds it → our acquire fails → we skip (git is mid-checkout)
    //   - If we hold it → git's checkout waits for us → no conflict
    // This eliminates ALL race conditions without heuristics or grace periods.
    //
    // The `once`/`repair` commands skip the lock because the user explicitly
    // requested hardening and may not even have a git operation in progress.
    let _lock = if skip_checkout_check {
        IndexLock::bypass()
    } else if !is_repo_checked_out(repo) {
        // Quick pre-check: if the repo clearly isn't checked out (no HEAD,
        // no commits), skip before even trying the lock. This avoids creating
        // an index.lock in a repo that git init hasn't committed to yet.
        return Ok((false, false, false));
    } else {
        match IndexLock::acquire(repo) {
            Ok(lock) => lock,
            Err(e) => {
                // Another git operation is in progress — skip gracefully.
                // This is normal during clone/checkout and not an error.
                veprintln!(1, "⏳ {}", e);
                return Ok((false, false, false));
            }
        }
    };

    // All working-tree writes below are now safe — we hold index.lock,
    // so no concurrent git checkout can write the same files.
    let gitignore_path = repo.join(".gitignore");
    let gitattributes_path = repo.join(".gitattributes");

    // Read existing dotfiles to preserve patterns added by other tools (e.g.,
    // dracon-sync). The helper rejects symlinks before following them, so a
    // tracked link cannot copy external content into the generated file.
    let existing_gitignore = read_existing_hardening_file(&gitignore_path)?;

    // CHANGED 2026-07-21 (v0.112.32, audit H8/F4.1): surgical merge
    // — `build_gitignore_block_with_existing` returns ONLY the
    // managed block; passing it straight to `apply_overwrite_file`
    // wiped all operator content outside the block (verified in this
    // repo's history: commit `3a67685f`). `replace_managed_block`
    // replaces only the delimited block and preserves everything
    // outside it. `.gitattributes` gets the same treatment
    // (`build_gitattributes_block` never even looked at existing
    // content).
    let existing_gitattributes = read_existing_hardening_file(&gitattributes_path)?;
    let merged_gitignore = replace_managed_block(
        &existing_gitignore,
        &build_gitignore_block_with_existing(policy, &existing_gitignore)?,
    );
    let merged_gitattributes =
        replace_managed_block(&existing_gitattributes, &build_gitattributes_block(policy)?);

    // Build gitignore block while preserving existing non-policy patterns
    let gitignore_changed = apply_overwrite_file(&gitignore_path, &merged_gitignore)?;
    let gitattributes_changed = apply_overwrite_file(&gitattributes_path, &merged_gitattributes)?;
    let filter_cfg_changed = if has_git_marker(repo) {
        ensure_repo_filter_config(repo)?
    } else {
        false
    };
    let key_changed = match pubkey_path {
        Some(pubkey) => publish_repo_pubkey(repo, pubkey)?,
        None => false,
    };

    // Install git hooks if not already present.  Propagate failures: silently
    // dropping this error leaves a repo without the local fallback hooks that
    // the global wrappers may need to chain.
    install_hooks_for_repo(repo)?;

    Ok((
        gitignore_changed,
        gitattributes_changed || filter_cfg_changed,
        key_changed,
    ))
}

fn harden_all(policy: &WardenPolicy, skip_checkout_check: bool) -> Result<()> {
    let roots = effective_discovery_roots(policy);
    let repos = discover_git_repos_local(&roots);
    scrub_markers(policy, &repos, true)?;
    harden_repos(policy, repos, skip_checkout_check)
}

pub(crate) fn harden_repos<I>(
    policy: &WardenPolicy,
    repos: I,
    skip_checkout_check: bool,
) -> Result<()>
where
    I: IntoIterator<Item = PathBuf>,
{
    let pubkey_path = resolve_local_pubkey_path();
    if pubkey_path.is_none() {
        eprintln!("⚠️ no public key found for repo publish; set DRACON_OWNER_PUBKEY to override");
    }
    // ADDED 2026-09-19 (v0.113.13): refresh stale warden-owned
    // GLOBAL hooks once per pass. The fleet runs with a global
    // core.hooksPath whose pre-commit probe gates every commit;
    // per-repo harden cannot leave it stale post-migration.
    // Pure refresh (never fresh install) — no scope change.
    match refresh_global_hooks_if_stale() {
        Ok(true) => eprintln!("🪝 refreshed stale global warden hooks"),
        Ok(false) => {}
        Err(e) => eprintln!("⚠️ global hook refresh failed: {}", e),
    }

    let mut changed = 0usize;
    for repo in repos {
        match harden_repo(&repo, policy, pubkey_path.as_deref(), skip_checkout_check) {
            Ok((a, b, c)) => {
                if a || b || c {
                    changed += 1;
                    println!("🔒 hardened {}", repo.display());
                    emit_event(&DraconEvent::new(
                        "warden",
                        EventSeverity::Info,
                        format!("harden/{}", repo.display()),
                        "repo hardened",
                    ));
                }
            }
            Err(e) => {
                eprintln!("⚠️ harden failed for {}: {}", repo.display(), e);
                emit_event(&DraconEvent::new(
                    "warden",
                    EventSeverity::Error,
                    format!("harden/{}", repo.display()),
                    format!("failed: {e}"),
                ));
            }
        }
    }

    println!("✅ hardening pass complete (repos changed: {})", changed);
    Ok(())
}

pub(crate) fn run_keygen() -> Result<()> {
    let home = dirs::home_dir().context("home directory not found")?;
    refuse_dedicated_master_overwrite(&home)?;

    let keys_dir = home.join(".dracon/data/keys");
    let hostname_raw = hostname::get()
        .context("failed to get hostname")?
        .to_string_lossy()
        .to_string();
    let hostname: String = hostname_raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if hostname.is_empty() {
        return Err(anyhow::anyhow!(
            "hostname contains no valid characters for filename"
        ));
    }
    let secret_path = keys_dir.join(format!("machine_{}.age", hostname));
    let pubkey_path = keys_dir.join(format!("owner_{}.pub", hostname));

    if secret_path.exists() {
        return Err(anyhow::anyhow!(
            "secret key already exists at {}, refusing to overwrite",
            secret_path.display()
        ));
    }
    if pubkey_path.exists() {
        return Err(anyhow::anyhow!(
            "pubkey already exists at {}, refusing to overwrite",
            pubkey_path.display()
        ));
    }

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("failed to create {}", keys_dir.display()))?;

    let current_repo = std::env::current_dir()
        .ok()
        .and_then(|cwd| find_git_repo(&cwd));

    let repo_name = current_repo
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let secret_content = Zeroizing::new(format!(
        "# created by dracon-warden keygen on {}\n# public key: {}\n# machine: {}\n{}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        recipient,
        hostname,
        identity.to_string().expose_secret()
    ));
    // Write secret key with restrictive permissions atomically (no race window)
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret_path)
            .with_context(|| {
                format!(
                    "failed to create {} (file may already exist)",
                    secret_path.display()
                )
            })?;
        f.write_all(secret_content.as_bytes())
            .with_context(|| format!("failed to write {}", secret_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&secret_path, &secret_content)
            .with_context(|| format!("failed to write {}", secret_path.display()))?;
    }

    // Write public key atomically - create_new fails if file already exists
    #[cfg(unix)]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pubkey_path)
            .with_context(|| {
                format!(
                    "failed to create {}, file may already exist",
                    pubkey_path.display()
                )
            })?
            .write_all(format!("{}\n# dracon-warden role: machine\n", recipient).as_bytes())
            .with_context(|| format!("failed to write {}", pubkey_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pubkey_path)
            .with_context(|| {
                format!(
                    "failed to create {}, file may already exist",
                    pubkey_path.display()
                )
            })?;
        f.write_all(format!("{}\n# dracon-warden role: machine\n", recipient).as_bytes())
            .with_context(|| format!("failed to write {}", pubkey_path.display()))?;
    }

    let manifest_path = keys_dir.join("manifest.toml");
    let manifest_entry = format!(
        "# machine_{}.age / owner_{}.pub -> repo: {}\n",
        hostname, hostname, repo_name
    );
    let existing_manifest = fs::read_to_string(&manifest_path).unwrap_or_default();
    if !existing_manifest.contains(&manifest_entry) {
        let mut manifest = existing_manifest;
        if !manifest.ends_with('\n') && !manifest.is_empty() {
            manifest.push('\n');
        }
        manifest.push_str(&manifest_entry);
        fs::write(&manifest_path, &manifest)
            .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    }

    println!("🔐 Generated age keypair:");
    println!("   Secret:    {}", secret_path.display());
    println!("   Public:    {}", pubkey_path.display());
    println!("   Recipient: {}", recipient);

    if let Some(repo) = &current_repo {
        match publish_repo_pubkey(repo, &pubkey_path) {
            Ok(true) => {
                println!("   Published to: {}/.dracon/data/keys/", repo.display());
            }
            Ok(false) => {
                println!("   Already in: {}/.dracon/data/keys/", repo.display());
            }
            Err(e) => {
                eprintln!("   ⚠️ Failed to publish to repo: {}", e);
            }
        }
    }

    Ok(())
}

fn refuse_dedicated_master_overwrite(home: &Path) -> Result<()> {
    let dracon_dir = home.join(".dracon");
    let legacy_master_private = dracon_dir.join("master.age");
    let canonical_master_private = dracon_dir.join("keys").join("master.age");
    let canonical_master_public = dracon_dir.join("data").join("keys").join("master.pub");

    for protected in [
        legacy_master_private.as_path(),
        canonical_master_private.as_path(),
        canonical_master_public.as_path(),
    ] {
        if protected.exists() {
            anyhow::bail!(
                "refusing to run dracon-warden keygen while the dedicated master key exists at {}; \
                 keygen only creates machine_<hostname>.age / marked owner_<hostname>.pub and must never \
                 overwrite the master recipient; use the explicit master-key rotation procedure instead",
                protected.display()
            );
        }
    }

    Ok(())
}

fn find_git_repo(path: &Path) -> Option<PathBuf> {
    let mut cur = path.to_path_buf();
    loop {
        if has_git_marker(&cur) {
            return Some(cur);
        }
        if !cur.pop() {
            break;
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    VERBOSITY.store(cli.verbose, Ordering::SeqCst);

    let storage_encrypt = matches!(&cli.cmd, Command::StorageEncrypt { .. });
    match cli.cmd {
        Command::StorageEncrypt { repo, max_bytes }
        | Command::StorageDecrypt { repo, max_bytes } => {
            // These commands stream local bytes only. They never install hooks,
            // harden a repo, create keys, or invoke Git/network operations.
            let repo = repo
                .canonicalize()
                .context("cannot resolve owning repository")?;
            if !has_git_marker(&repo) {
                anyhow::bail!("owning repository must have a Git marker");
            }
            let security = dracon_security_kit::WardenSecurity::new(Some(&repo))?;
            let mut input = std::io::stdin().lock();
            let mut output = std::io::stdout().lock();
            if storage_encrypt {
                storage::encrypt(&security, &mut input, &mut output, max_bytes)?;
            } else {
                storage::decrypt(&security, &mut input, &mut output, max_bytes)?;
            }
        }
        Command::FilterClean { path } => {
            run_filter_with_timeout(true, "filter-clean", path).await?;
        }
        Command::FilterSmudge { path } => {
            run_filter_with_timeout(false, "filter-smudge", path).await?;
        }
        // No wall-clock timeout: the process driver is long-lived
        // BY DESIGN (git owns its lifecycle — spawns once per git
        // command, kills it when done). A timeout here would abort
        // mid-diff. Per-file work is the same bounded transform as
        // the one-shot path.
        Command::FilterProcess => {
            let code = tokio::task::spawn_blocking(run_filter_process)
                .await
                .map_err(|e| anyhow::anyhow!("filter-process task panicked: {}", e))?;
            std::process::exit(code);
        }
        Command::Merge {
            ancestor,
            current,
            other,
        } => {
            let code = run_merge(&ancestor, &current, &other)?;
            std::process::exit(code);
        }
        Command::Status => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            let repo_roots = effective_repo_roots(&policy);
            // Explicit (user-set) discovery roots only — i.e. those that
            // extend the repo_roots set. Empty if user didn't set discover_roots.
            let explicit_discover: Vec<PathBuf> = policy
                .discover_root_paths()
                .into_iter()
                .filter(|p| !repo_roots.contains(p))
                .collect();
            let pubkey = resolve_local_pubkey_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "NOT_FOUND (set DRACON_OWNER_PUBKEY)".to_string());

            use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, ContentArrangement, Table};
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![Cell::new("KEY"), Cell::new("VALUE")]);
            table.add_row(vec![
                Cell::new("📜 Policy"),
                Cell::new(policy_path.display().to_string()),
            ]);
            // ---- Summary row (one-liner for quick scanning) ----
            let discover_note = if explicit_discover.is_empty() {
                String::new()
            } else {
                format!(
                    " · {} additional discovery root(s)",
                    explicit_discover.len()
                )
            };
            table.add_row(vec![
                Cell::new("📋 Summary"),
                Cell::new(format!(
                    "Policy resolved · {} repo root(s){} · pubkey {}",
                    repo_roots.len(),
                    discover_note,
                    if pubkey.starts_with("NOT_FOUND") {
                        "MISSING"
                    } else {
                        "found"
                    }
                )),
            ]);
            // ---- Section: Roots (single row in the common case) ----
            table.add_row(vec![
                Cell::new("🔍 Repo roots"),
                Cell::new(format!(
                    "{} root(s): {}",
                    repo_roots.len(),
                    repo_roots
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            ]);
            if !explicit_discover.is_empty() {
                table.add_row(vec![
                    Cell::new("🧭 Discovery roots (additional)"),
                    Cell::new(format!(
                        "{} root(s): {}",
                        explicit_discover.len(),
                        explicit_discover
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ]);
            }
            // ---- Deprecation indicator (if old key in use) ----
            if let Some(msg) = policy.deprecation_message() {
                table.add_row(vec![Cell::new("⚠ Deprecated key"), Cell::new(msg)]);
            }
            // ---- Section: Identity ----
            table.add_row(vec![Cell::new("🔑 Pubkey source"), Cell::new(&pubkey)]);
            println!("{table}");
        }
        Command::Once { repo } => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            policy.print_deprecation_to_stderr();
            if let Some(r) = repo {
                scrub_markers(&policy, std::slice::from_ref(&r), true)?;
                harden_repos(&policy, vec![r], true)?;
            } else {
                harden_all(&policy, true)?;
            }
        }
        Command::ScrubMarkers { apply, repo } => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            policy.print_deprecation_to_stderr();
            let roots = effective_discovery_roots(&policy);
            let repos = if let Some(r) = repo {
                vec![r]
            } else {
                discover_git_repos_local(&roots)
            };
            scrub_markers(&policy, &repos, apply)?;
        }
        Command::Resmudge { apply, repo } => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            policy.print_deprecation_to_stderr();
            let roots = effective_discovery_roots(&policy);
            let repos = if let Some(r) = repo {
                vec![r]
            } else {
                discover_git_repos_local(&roots)
            };
            resmudge_repos(&policy, &repos, apply)?;
        }
        Command::Repair {
            dry_run,
            strict,
            repo,
        } => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            policy.print_deprecation_to_stderr();
            let roots = effective_discovery_roots(&policy);
            let repos = if let Some(r) = repo {
                vec![r]
            } else {
                discover_git_repos_local(&roots)
            };

            println!(
                "🛠️  repair (dry_run={dry_run}, strict={strict}) · {} repo(s) in scope",
                repos.len()
            );

            if !dry_run {
                // Hardening (managed blocks + marker scrub)
                scrub_markers(&policy, &repos, true)?;
                harden_repos(&policy, repos.clone(), true)?;
                // Fix ciphertext stuck in worktree (if identities allow).
                resmudge_repos(&policy, &repos, true)?;
                // Backfill .env files with Dracon Warden headers if missing.
                backfill_env_headers_repos(&repos, true)?;
            }

            // Always report remaining ciphertext markers.
            let (found, _changed) = resmudge_repos(&policy, &repos, false)?;
            // Always report .env files missing headers (even in dry_run).
            let (_, _) = backfill_env_headers_repos(&repos, false)?;

            // ---- Summary line ----
            if found == 0 {
                println!("✅ repair complete · no remaining ciphertext in working tree");
            } else {
                println!(
                    "⚠️ repair complete · {found} ciphertext file(s) remain in working tree (pass without --dry-run to resmudge)"
                );
            }

            if strict && found > 0 {
                return Err(anyhow::anyhow!(
                    "ciphertext markers remain in working tree (count={})",
                    found
                ));
            }
        }
        Command::Keygen => {
            run_keygen()?;
        }
        Command::SetupHooks {
            global: _,
            local,
            repo,
        } => {
            let mode = if local {
                HookMode::Local
            } else {
                HookMode::Global
            };
            run_setup_hooks(mode, repo.as_deref())?;
        }
    }

    Ok(())
}

pub(crate) fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        // globset expects / separators
        let pat = p.replace('\\', "/");
        b.add(Glob::new(&pat).with_context(|| format!("invalid glob pattern: {p}"))?);
    }
    Ok(b.build()?)
}

pub(crate) fn is_marker_string(s: &str) -> bool {
    s.contains("[DRACON_SECRET:")
}

pub(crate) fn marker_prefix_at(s: &str, idx: usize) -> Option<&'static str> {
    if s.get(idx..)?.starts_with("[DRACON_SECRET:") {
        Some("[DRACON_SECRET:")
    } else {
        None
    }
}

// Best-effort salvage for invalid JSON where marker tokens were injected as raw values/keys.
// This only touches marker substrings; everything else is preserved.
pub(crate) fn salvage_invalid_json_markers(content: &str) -> Option<String> {
    if !is_marker_string(content) {
        return None;
    }

    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    while i < content.len() {
        if marker_prefix_at(content, i).is_none() {
            // Advance by a complete UTF-8 scalar. The old byte-at-a-time
            // loop both panicked when `marker_prefix_at` sliced at a
            // non-character boundary and emitted mojibake for ordinary
            // non-ASCII text before a marker.
            let ch = content[i..]
                .chars()
                .next()
                .expect("i remains within valid UTF-8 content");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        // Find closing bracket of marker token.
        let Some(end_rel) = content[i..].find(']') else {
            // malformed marker; stop salvage
            return None;
        };
        let end = i + end_rel; // points at ']'

        // Decide whether marker was used as an object key or as a value.
        // If the next non-ws char after ']' is ':', it's being used as a key.
        let mut j = end + 1;
        while j < content.len() && content.as_bytes()[j].is_ascii_whitespace() {
            j += 1;
        }
        let is_key = j < content.len() && content.as_bytes()[j] == b':';

        if is_key {
            out.push_str("\"__scrubbed__\"");
        } else {
            out.push_str("null");
        }

        i = end + 1;
    }

    if out != content {
        Some(out)
    } else {
        None
    }
}

fn scrub_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) if is_marker_string(s) => {
            *v = serde_json::Value::Null;
        }
        serde_json::Value::Array(a) => {
            for it in a {
                scrub_json_value(it);
            }
        }
        serde_json::Value::Object(m) => {
            // Heuristic fix for known nav templates: href_key can be inferred from href.
            let href = m
                .get("href")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let (Some(href), Some(href_key)) = (href, m.get_mut("href_key")) {
                if let serde_json::Value::String(hk) = href_key {
                    if is_marker_string(hk) {
                        let replacement = match href.as_str() {
                            "/products" => Some("public_products"),
                            "/licensing" => Some("public_licensing"),
                            "/products/cortex" => Some("cortex_home"),
                            _ => None,
                        };
                        if let Some(r) = replacement {
                            *href_key = serde_json::Value::String(r.to_string());
                        } else {
                            *href_key = serde_json::Value::Null;
                        }
                    }
                }
            }

            for (_, vv) in m.iter_mut() {
                scrub_json_value(vv);
            }
        }
        _ => {}
    }
}

pub(crate) fn scrub_markers(policy: &WardenPolicy, repos: &[PathBuf], apply: bool) -> Result<()> {
    use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};

    let protected = build_globset(&policy.effective_protected_patterns())?;

    let mut found = 0usize;
    let mut changed = 0usize;
    let mut skipped = 0usize;
    let mut rows: Vec<(String, String, String)> = Vec::new();

    for repo in repos {
        if !has_git_marker(repo) {
            continue;
        }

        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("ls-files")
            .arg("--others")
            .arg("--exclude-standard")
            .arg("--cached")
            .output()
            .with_context(|| format!("git ls-files failed for {}", repo.display()))?;
        if !out.status.success() {
            eprintln!(
                "\u{26a0}\u{fe0f} git ls-files failed for {} (status {})",
                repo.display(),
                out.status
            );
            continue;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        for rel in stdout.lines() {
            if rel.is_empty() {
                continue;
            }
            let rel_norm = rel.replace('\\', "/");
            if protected.is_match(&rel_norm) {
                continue;
            }
            if !rel_norm.ends_with(".json") {
                continue;
            }
            // Plaintext-sibling escape hatch: skip files with a `.plaintext` sibling.
            // Such files are intentionally plaintext; their markers (if any) stay.
            if repo.join(format!("{}.plaintext", rel_norm)).exists() {
                continue;
            }

            let path = repo.join(rel);
            let bytes = match read_tracked_repair_file(&path, None) {
                Ok(TrackedRepairFile::Missing) => continue,
                Ok(TrackedRepairFile::TooLarge(_)) => {
                    unreachable!("scrub marker reads have no size limit")
                }
                Ok(TrackedRepairFile::Contents(bytes)) => bytes,
                Err(error) => {
                    eprintln!("⚠️ skipping marker scrub of {}: {}", path.display(), error);
                    continue;
                }
            };
            let Ok(content) = String::from_utf8(bytes) else {
                continue;
            };
            if !is_marker_string(&content) {
                continue;
            }

            found += 1;
            if !apply {
                let repo_name = repo
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| repo.display().to_string());
                rows.push((repo_name, rel_norm.clone(), "found".to_string()));
                continue;
            }

            let parsed: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => {
                    let Some(salvaged) = salvage_invalid_json_markers(&content) else {
                        skipped += 1;
                        let repo_name = repo
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| repo.display().to_string());
                        rows.push((repo_name, rel_norm.clone(), "invalid JSON".to_string()));
                        continue;
                    };
                    match serde_json::from_str(&salvaged) {
                        Ok(v) => v,
                        Err(_) => {
                            skipped += 1;
                            let repo_name = repo
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| repo.display().to_string());
                            rows.push((repo_name, rel_norm.clone(), "invalid JSON".to_string()));
                            continue;
                        }
                    }
                }
            };
            let mut v = parsed;

            scrub_json_value(&mut v);
            let next = serde_json::to_string_pretty(&v)?;
            if next != content {
                write_tracked_repair_file(&path, next.as_bytes())
                    .with_context(|| format!("failed writing {}", path.display()))?;
                changed += 1;
                let repo_name = repo
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| repo.display().to_string());
                rows.push((repo_name, rel_norm.clone(), "scrubbed".to_string()));
            }
        }
    }

    if !rows.is_empty() {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("REPO"),
                Cell::new("FILE"),
                Cell::new("STATUS"),
            ]);

        for (repo, file, status) in &rows {
            let (status_str, color) = match status.as_str() {
                "scrubbed" => ("\u{2705} scrubbed", Color::Green),
                "invalid JSON" => ("\u{274c} invalid JSON", Color::Red),
                _ => ("\u{26a0}\u{fe0f} found", Color::Yellow),
            };
            table.add_row(vec![
                Cell::new(repo),
                Cell::new(file),
                Cell::new(status_str).fg(color),
            ]);
        }

        println!("{table}");
    }

    if apply {
        if changed == 0 {
            println!(
                "✅ scrub-markers complete · no changes needed (found: {found}, changed: 0, skipped: {skipped})"
            );
        } else {
            println!(
                "✅ scrub-markers complete · {changed} file(s) updated (found: {found}, skipped: {skipped})"
            );
        }
    } else if found == 0 {
        println!(
            "✅ scrub-markers · nothing to do · no DRACON_SECRET markers found in watched files"
        );
    } else {
        println!("🔍 scrub-markers · found {found} marker(s) (dry-run, pass --apply to scrub)");
    }
    Ok(())
}

fn git_ls_files(repo: &Path) -> Result<Vec<String>> {
    let out = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo)
        .arg("ls-files")
        .arg("-z")
        .output()
        .with_context(|| format!("failed to run git ls-files in {}", repo.display()))?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "git ls-files failed in {} (exit={})",
            repo.display(),
            out.status
        ));
    }

    let mut paths = Vec::new();
    for part in out.stdout.split(|b| *b == 0) {
        if part.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(part).with_context(|| {
            format!("git ls-files returned non-utf8 path in {}", repo.display())
        })?;
        paths.push(s.to_string());
    }
    Ok(paths)
}

enum TrackedRepairFile {
    Missing,
    TooLarge(u64),
    Contents(Vec<u8>),
}

/// Read a tracked repair path without following a repository-controlled
/// symlink. The initial `symlink_metadata` check gives a useful diagnostic,
/// while Unix `O_NOFOLLOW` closes the check/open race. Existing inputs are
/// rejected on platforms without a no-follow file-open primitive rather than
/// risking a read through a link.
fn read_tracked_repair_file(path: &Path, max_bytes: Option<usize>) -> Result<TrackedRepairFile> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TrackedRepairFile::Missing)
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect tracked repair path {}", path.display())
            })
        }
    };

    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read tracked symlink {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "refusing to read non-regular tracked path {}",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to read tracked repair path {}", path.display()))?;
        let file_metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect opened repair path {}", path.display()))?;
        if !file_metadata.is_file() {
            anyhow::bail!(
                "refusing to read non-regular tracked path {}",
                path.display()
            );
        }

        if let Some(limit) = max_bytes {
            if file_metadata.len() > limit as u64 {
                return Ok(TrackedRepairFile::TooLarge(file_metadata.len()));
            }
            let mut contents = Vec::new();
            file.take(limit.saturating_add(1) as u64)
                .read_to_end(&mut contents)
                .with_context(|| format!("failed reading {}", path.display()))?;
            if contents.len() > limit {
                return Ok(TrackedRepairFile::TooLarge(contents.len() as u64));
            }
            return Ok(TrackedRepairFile::Contents(contents));
        }

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .with_context(|| format!("failed reading {}", path.display()))?;
        Ok(TrackedRepairFile::Contents(contents))
    }

    #[cfg(not(unix))]
    {
        let _ = max_bytes;
        anyhow::bail!(
            "refusing existing tracked repair path {}: no supported no-follow reader on this platform",
            path.display()
        );
    }
}

/// Write an already-read tracked repair path without following a symlink.
/// Opening the existing file with `O_NOFOLLOW` makes the write safe even if
/// the checkout path is replaced after the read-side metadata check. Missing,
/// non-regular, and non-Unix existing paths fail closed.
fn write_tracked_repair_file(path: &Path, contents: &[u8]) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect tracked repair path {}", path.display())
            })
        }
    };

    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to write tracked symlink {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "refusing to write non-regular tracked path {}",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open tracked repair path {}", path.display()))?;
        if !file
            .metadata()
            .with_context(|| format!("failed to inspect opened repair path {}", path.display()))?
            .is_file()
        {
            anyhow::bail!(
                "refusing to write non-regular tracked path {}",
                path.display()
            );
        }
        file.write_all(contents)
            .and_then(|_| file.flush())
            .with_context(|| format!("failed writing {}", path.display()))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = contents;
        anyhow::bail!(
            "refusing existing tracked repair path {}: no supported no-follow writer on this platform",
            path.display()
        );
    }
}

fn resmudge_repo(repo: &Path, policy: &WardenPolicy, apply: bool) -> Result<(usize, usize)> {
    require_git_marker(repo)?;
    let protected = build_globset(&policy.effective_protected_patterns())?;
    let files = git_ls_files(repo)?;

    let mut found = 0usize;
    let mut changed = 0usize;
    let warden = if apply {
        Some(DraconWarden::new()?)
    } else {
        None
    };

    for rel in files {
        let rel_norm = rel.replace("\\", "/");
        if !protected.is_match(&rel_norm) {
            continue;
        }
        // Plaintext-sibling escape hatch: skip files that are intentionally plaintext.
        // Such files are not encrypted and do not need decryption.
        if repo.join(format!("{}.plaintext", rel_norm)).exists() {
            continue;
        }

        let full = repo.join(&rel);
        let bytes = match read_tracked_repair_file(&full, Some(STREAM_IO_MAX_BYTES)) {
            Ok(TrackedRepairFile::Missing) => continue,
            Ok(TrackedRepairFile::TooLarge(size)) => {
                // CHANGED 2026-09-09 (audit F51): this skip was silent —
                // large ciphertext files stayed unrestored indefinitely with
                // no hint why. Warn so the operator knows to handle them.
                eprintln!(
                    "⚠️ skipping resmudge of {} ({} > {}-byte streaming cap) — restore it manually",
                    full.display(),
                    size,
                    STREAM_IO_MAX_BYTES
                );
                continue;
            }
            Ok(TrackedRepairFile::Contents(bytes)) => bytes,
            Err(error) => {
                eprintln!("⚠️ skipping resmudge of {}: {}", full.display(), error);
                continue;
            }
        };

        if !is_marker_string(&String::from_utf8_lossy(&bytes)) {
            continue;
        }

        found += 1;

        if !apply {
            println!("🔎 ciphertext in worktree: {}", full.display());
            continue;
        }

        let Some(warden) = &warden else {
            continue;
        };

        match warden.smudge(&bytes, Some(&rel_norm)) {
            Ok(out) => {
                if out != bytes {
                    if let Err(e) = write_tracked_repair_file(&full, &out) {
                        eprintln!("⚠️ resmudge write failed {}: {}", full.display(), e);
                        continue;
                    }
                    changed += 1;
                    println!("✅ resmudged: {}", full.display());
                }
            }
            Err(e) => {
                eprintln!("⚠️ resmudge failed {}: {}", full.display(), e);
            }
        }
    }

    Ok((found, changed))
}

pub(crate) fn resmudge_repos(
    policy: &WardenPolicy,
    repos: &[PathBuf],
    apply: bool,
) -> Result<(usize, usize)> {
    policy.validate()?;

    let mut total_found = 0usize;
    let mut total_changed = 0usize;

    for repo in repos {
        match resmudge_repo(repo, policy, apply) {
            Ok((found, changed)) => {
                total_found += found;
                total_changed += changed;
            }
            Err(e) => eprintln!("⚠️ resmudge failed for {}: {}", repo.display(), e),
        }
    }

    if apply {
        if total_changed == 0 {
            println!("✅ resmudge complete · no changes needed (found: {total_found}, changed: 0)");
        } else {
            println!(
                "✅ resmudge complete · {total_changed} file(s) resmudged (found: {total_found})"
            );
        }
    } else if total_found == 0 {
        println!("✅ resmudge · nothing to do · no ciphertext working-tree files found");
    } else {
        println!(
            "🔍 resmudge · found {total_found} ciphertext file(s) (dry-run, pass --apply to resmudge)"
        );
    }

    Ok((total_found, total_changed))
}

pub(crate) fn is_env_file_name(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.ends_with(".env")
        || path_lower.contains(".env.")
        || path_lower.ends_with(".envrc")
        || path_lower.ends_with("/.env")
        || path_lower.ends_with("/.envrc")
}

pub(crate) fn is_encrypted_env_content(content: &str) -> bool {
    let trimmed = content.trim_end_matches('\n');
    trimmed.starts_with("[DRACON_SECRET:") && trimmed.ends_with(']')
}

fn backfill_env_headers_repo(repo: &Path, apply: bool) -> Result<(usize, usize)> {
    require_git_marker(repo)?;
    let files = git_ls_files(repo)?;
    let warden = DraconWarden::new()?;

    let mut found = 0usize;
    let mut changed = 0usize;

    for rel in files {
        let rel_norm = rel.replace("\\", "/");
        if !is_env_file_name(&rel_norm) {
            continue;
        }

        let full = repo.join(&rel);
        let bytes = match read_tracked_repair_file(&full, None) {
            Ok(TrackedRepairFile::Missing) => continue,
            Ok(TrackedRepairFile::TooLarge(_)) => unreachable!("backfill has no read size limit"),
            Ok(TrackedRepairFile::Contents(bytes)) => bytes,
            Err(error) => {
                eprintln!(
                    "⚠️ skipping header backfill of {}: {}",
                    full.display(),
                    error
                );
                continue;
            }
        };

        let content = String::from_utf8_lossy(&bytes);
        if content.contains("Dracon Warden") {
            continue;
        }

        let is_encrypted = is_encrypted_env_content(&content);
        found += 1;

        if !apply {
            if is_encrypted {
                println!(
                    "🔎 .env without header (encrypted, skipping): {}",
                    full.display()
                );
            } else {
                println!("🔎 .env without header: {}", full.display());
            }
            continue;
        }

        if is_encrypted {
            eprintln!(
                "⚠️ refusing to decrypt encrypted file during header backfill: {}",
                full.display()
            );
            continue;
        }

        match warden.smudge(&bytes, Some(&rel_norm)) {
            Ok(out) => {
                if out != bytes {
                    if let Err(e) = write_tracked_repair_file(&full, &out) {
                        eprintln!("⚠️ backfill write failed {}: {}", full.display(), e);
                        continue;
                    }
                    changed += 1;
                    println!("✅ header added: {}", full.display());
                }
            }
            Err(e) => {
                eprintln!("⚠️ backfill failed {}: {}", full.display(), e);
            }
        }
    }

    Ok((found, changed))
}

fn backfill_env_headers_repos(repos: &[PathBuf], apply: bool) -> Result<(usize, usize)> {
    let mut total_found = 0usize;
    let mut total_changed = 0usize;

    for repo in repos {
        match backfill_env_headers_repo(repo, apply) {
            Ok((found, changed)) => {
                total_found += found;
                total_changed += changed;
            }
            Err(e) => eprintln!("⚠️ backfill failed for {}: {}", repo.display(), e),
        }
    }

    if apply {
        println!(
            "✅ backfill complete (found: {}, changed: {})",
            total_found, total_changed
        );
    } else {
        println!("✅ backfill report complete (found: {})", total_found);
    }

    Ok((total_found, total_changed))
}

const STREAM_IO_MAX_BYTES: usize = 10 * 1024 * 1024; // Backwards-compatible default.
const FILTER_IO_HARD_MAX_BYTES: usize = 64 * 1024 * 1024; // Absolute allocation bound.

fn configured_filter_limit() -> Result<usize> {
    match resolve_policy_path_local() {
        Ok(path) => WardenPolicy::load(&path)?.filter_limit(),
        // Preserve legacy scan-everything behavior without an installed policy.
        Err(_) => Ok(STREAM_IO_MAX_BYTES),
    }
}

/// Every input the clean-direction size guard needs, resolved ONCE
/// per process from a single policy load.
///
/// ADDED 2026-09-27 (audit decision D2 follow-up): the first cut of the
/// carve-out called `WardenPolicy::load` — a file read plus a TOML
/// parse — once per request inside the `filter-process` request loop.
/// That driver is the hot path (one process serves an entire firehose
/// `git diff`), so that turned a per-file config load into the new
/// steady-state cost of the whole driver. `configured_filter_limit`
/// was already resolved once by the caller; the other two inputs now
/// ride along with it instead of being re-read per file.
struct CleanGuard {
    limit: usize,
    /// Globs whose files are exempt from the SIZE guard only.
    binary_exempt: Vec<String>,
    /// The policy's `protected_patterns`. Consulted here with the
    /// explicit `path_matches_any_pattern` matcher, NOT with
    /// `path_is_protected`: an empty `protected_patterns` means
    /// "scan everything" to `path_is_protected` (legacy) but must mean
    /// "nothing is protected" to this gate, or every binary would be
    /// exempt by default and the carve-out would stop being opt-in per
    /// directory.
    protected: Vec<String>,
    /// The policy's `media_protected_patterns`. A media path is never
    /// size-exempt either (same fail-closed rule as `protected`).
    media: Vec<String>,
}

fn configured_clean_guard() -> Result<CleanGuard> {
    let Ok(path) = resolve_policy_path_local() else {
        // Preserve legacy scan-everything behavior without an
        // installed policy, matching `configured_filter_limit`.
        return Ok(CleanGuard {
            limit: STREAM_IO_MAX_BYTES,
            binary_exempt: default_binary_filter_exempt_patterns(),
            protected: Vec::new(),
            media: Vec::new(),
        });
    };
    // A policy that exists but does not parse is a hard error, exactly
    // as it is for `configured_filter_limit`: silently falling back to
    // defaults would re-arm the carve-out on a repo whose operator
    // explicitly turned it off.
    let policy = WardenPolicy::load(&path)?;
    Ok(CleanGuard {
        limit: policy.filter_limit()?,
        binary_exempt: policy.binary_exempt_patterns(),
        protected: policy.effective_protected_patterns(),
        media: policy.media_protected_patterns.clone(),
    })
}

fn read_filter_input(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    // Read one sentinel byte beyond the bound, never unbounded stdin.
    reader.take((limit + 1) as u64).read_to_end(&mut input)?;
    Ok(input)
}

/// Run the filter with a wall-clock timeout, preventing indefinite hangs.
///
/// `run_filter` is a sync function that does a blocking `stdin.read_to_end()`. If the
/// parent (git) never sends EOF — e.g. it crashed, was killed, or the file path was
/// deleted while the filter held it open — the process would otherwise hang forever.
/// In a `#[tokio::main]` context, this also keeps the runtime's worker threads alive.
///
/// We run the filter in `spawn_blocking` (so the blocking I/O doesn't stall the
/// runtime's reactor) wrapped in `tokio::time::timeout`. On timeout we log a warning
/// to stderr and exit with status 1 — git treats non-zero exit as filter failure,
/// which is the correct behavior: returning passthrough would silently corrupt data
/// (encrypted content would be written to disk as plaintext, or vice versa).
fn filter_timeout_secs(limit: usize) -> u64 {
    // Preserve the default deadline; larger operator-approved scan bounds get
    // proportional time, capped by the same 64 MiB policy maximum (210s).
    FILTER_TIMEOUT_SECS
        * limit
            .min(FILTER_IO_HARD_MAX_BYTES)
            .div_ceil(STREAM_IO_MAX_BYTES) as u64
}

async fn run_filter_with_timeout(is_clean: bool, label: &str, path: Option<String>) -> Result<()> {
    let timeout_secs = filter_timeout_secs(configured_filter_limit()?);
    let join_result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::task::spawn_blocking(move || run_filter(is_clean, path.as_deref())),
    )
    .await;

    match join_result {
        // spawn_blocking returned Ok(filter returned Ok(()))
        Ok(Ok(Ok(()))) => Ok(()),
        // spawn_blocking returned Ok(filter returned Err)
        Ok(Ok(Err(e))) => Err(e),
        // spawn_blocking itself panicked or was cancelled
        Ok(Err(join_err)) => Err(anyhow::anyhow!("{} task panicked: {}", label, join_err)),
        // Timeout fired
        Err(_elapsed) => {
            eprintln!(
                "dracon-warden: {} timed out after {}s, exiting (parent likely gone)",
                label, timeout_secs
            );
            std::process::exit(1);
        }
    }
}

/// ADDED 2026-07-21 (v0.112.32, audit M31/F4.5): pure refusal
/// predicate for the filter guards. In the CLEAN direction,
/// passthrough for oversized inputs or refused paths means the file
/// is committed UNENCRYPTED (silent plaintext leak into history), so
/// those cases must fail closed. In the SMUDGE direction passthrough
/// is correct (keeps ciphertext as-is), so this always returns None.
/// Returns the refusal reason for logging/erroring.
#[cfg(test)]
fn filter_clean_refusal_reason(
    is_clean: bool,
    input_len: usize,
    path: Option<&str>,
) -> Option<String> {
    filter_clean_refusal_with_limit(
        is_clean,
        input_len,
        path,
        STREAM_IO_MAX_BYTES,
        &default_binary_filter_exempt_patterns(),
        // No policy in this test-only wrapper: nothing is protected,
        // which is the shipped default.
        &[],
        &[],
    )
}

/// A `CleanGuard` for tests that only care about the size limit: the
/// shipped carve-out defaults and no protected patterns (the default
/// configuration). Mirrors what the old bare-`limit` call sites meant.
#[cfg(test)]
pub(crate) fn test_guard(limit: usize) -> CleanGuard {
    CleanGuard {
        limit,
        binary_exempt: default_binary_filter_exempt_patterns(),
        protected: Vec::new(),
        media: Vec::new(),
    }
}

/// Relativize an absolute filter path against its own repo root (R4-01).
///
/// Real git always sends repo-relative `%f`/process paths, so the absolute
/// refusal below is dead code on the git path — but IF another caller
/// (lead claim: cargo/gix on dirty trees; trigger UNVERIFIED) sends an
/// absolute path, the hard refusal aborts every `git add`. Relativize-then-
/// guard instead: an absolute path under its repo root becomes the
/// repo-relative form and flows through the SAME guards and matching as a
/// native relative path (no new reachable state, so no leak); an absolute
/// outside the root, an unresolvable root, or an empty remainder still
/// refuses in the clean direction. Smudge keeps its pass-through shape:
/// outside-root absolutes are returned unchanged so the downstream
/// warn-and-relay arm (not a refusal) still handles them.
///
/// The root is queried with `git -C <parent> rev-parse --show-toplevel`,
/// anchored at the path itself rather than the process CWD, and the strip
/// is lexical (no canonicalization: a symlinked-prefix absolute refuses,
/// fail-closed, exactly as before).
fn normalize_filter_path(path: Option<&str>, is_clean: bool) -> Result<Option<String>> {
    let Some(p) = path else {
        return Ok(None);
    };
    let p_buf = std::path::PathBuf::from(p);
    if !p_buf.is_absolute() {
        return Ok(Some(p.to_string()));
    }
    let root = (|| {
        let parent = p_buf.parent()?;
        let out = ProcessCommand::new("git")
            .arg("-C")
            .arg(parent)
            .arg("rev-parse")
            .arg("--show-toplevel")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if root.is_empty() {
            return None;
        }
        p_buf
            .strip_prefix(&root)
            .ok()
            .map(|rel| rel.to_string_lossy().to_string())
            .filter(|rel| !rel.is_empty())
    })();
    match root {
        Some(rel) => Ok(Some(rel)),
        None if !is_clean => Ok(Some(p.to_string())),
        None => anyhow::bail!(
            "dracon-warden: refusing to clean absolute filter path '{}' (outside any repo root)",
            p
        ),
    }
}

fn filter_clean_refusal_with_limit(
    is_clean: bool,
    input_len: usize,
    path: Option<&str>,
    limit: usize,
    binary_exempt: &[String],
    protected: &[String],
    media: &[String],
) -> Option<String> {
    if !is_clean {
        return None;
    }
    if input_len > limit {
        // ADDED 2026-09-27 (audit decision D2): a known-binary path is
        // not refused for being oversized. The managed .gitattributes
        // already emits `-filter` for these, so git should never invoke
        // clean on them; this keeps a stale or hand-edited
        // .gitattributes from turning a large screenshot into a hard
        // `git add` failure with a message about committing plaintext,
        // which is the failure mode that pushes operators toward
        // disabling the filter for everything.
        //
        // FIXED 2026-09-27 (audit round 1, HIGH): the exemption
        // consulted only the extension list, so an oversize file under
        // a PROTECTED directory — `secrets/big.png` — passed through
        // unencrypted AND unscanned, a fail-open the pre-change code
        // did not have. The .gitattributes ordering does not save it:
        // the protected line does win there, which means git DOES
        // route the file here, and this function then waved it through.
        // A protected path is now never exempt, so an operator who
        // listed `secrets/**` gets a hard failure for an oversize
        // secret regardless of what it is named.
        //
        // Only the SIZE guard is exempted. Every other oversize path
        // (text, source, unknown extension, anything protected) still
        // refuses, and the path-shape guards below still apply to an
        // exempt path.
        //
        // Media option: a media path is never size-exempt either
        // (same fail-closed rule as a protected path — the operator
        // asked for encryption, so oversize must refuse rather than
        // pass through unencrypted).
        let exempt = path.is_some_and(|p| {
            !binary_exempt.is_empty()
                && path_matches_any_pattern(p, binary_exempt)
                && !path_matches_any_pattern(p, protected)
                && !path_matches_any_pattern(p, media)
        });
        if !exempt {
            return Some(format!(
                "dracon-warden: refusing to clean {} bytes (limit {} bytes): the file would be committed UNENCRYPTED. Encrypt it out-of-band (dracon-warden encrypt-file) or .gitignore it. Binary media and archives are exempt via binary_filter_exempt_patterns.",
                input_len,
                limit
            ));
        }
    }
    if let Some(p) = path {
        let p_buf = std::path::PathBuf::from(p);
        if p_buf.is_absolute() {
            return Some(format!(
                "dracon-warden: refusing to clean absolute filter path '{}'",
                p
            ));
        }
        if p_buf
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Some(format!(
                "dracon-warden: refusing to clean filter path '{}' (contains '..')",
                p
            ));
        }
    }
    None
}

/// Read stage zero without invoking filters, writing the index, or falling back
/// to HEAD (which can differ from the staged content). Missing/unmerged entries
/// and Git failures simply disable reuse. Bound both time and captured bytes.
///
/// FIXED 2026-09-27 (audit F95): this file had a local `macro_rules! fdbg`
/// whose name shadowed the std `dbg!` macro, and which gated its output on a
/// `DRACON_FILTER_DEBUG=1` environment variable — a second, undocumented way to
/// turn on diagnostics alongside the CLI's own `-v`/`-vv` verbosity flag. The
/// driver is spawned by git rather than by a shell the operator controls, so
/// that env var was effectively unsettable on the real path. All 14 call sites
/// now use the existing `veprintln!(2, ...)` helper, so every warden
/// diagnostic shares one gate.
fn indexed_filter_blob(path: &str, limit: usize) -> Option<Vec<u8>> {
    use std::process::Stdio;
    let capture = tempfile::NamedTempFile::new().ok()?;
    let mut child = ProcessCommand::new("git")
        .args(["cat-file", "blob", &format!(":0:{path}")])
        .stdin(Stdio::null())
        .stdout(Stdio::from(capture.reopen().ok()?))
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = std::time::Instant::now();
    let success = loop {
        if start.elapsed() >= Duration::from_secs(2)
            || capture
                .as_file()
                .metadata()
                .map(|m| m.len())
                .unwrap_or(u64::MAX)
                > limit as u64
        {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !success {
        return None;
    }
    let bytes = read_filter_input(capture.reopen().ok()?, limit).ok()?;
    (bytes.len() <= limit).then_some(bytes)
}

/// Cap for a single blob drained from the batch child (v0.113.14).
/// The batch reader does not know the caller-supplied filter `limit`,
/// so grossly oversized blobs are discarded here to keep framing;
/// `filter_transform_bytes` still enforces `limit` before use.
/// 64 MiB clears the largest firehose blobs observed (51 MB).
const INDEX_BATCH_BLOB_CAP: usize = 64 * 1024 * 1024;

/// Which index-lookup strategy a clean request uses (v0.113.14).
/// One-shot filters keep the legacy per-file spawn; the process
/// driver carries one persistent batch session.
#[derive(Debug)]
enum IndexLookup {
    OneShot,
    Batch(IndexBatch),
}

/// Persistent `git cat-file --batch` session for the long-running
/// filter driver (ADDED 2026-09-19, v0.113.14). The per-file
/// `indexed_filter_blob` spawn (~10-50 ms: git startup + tempfile +
/// 5 ms poll loop) is invisible on small repos but serializes into
/// 15-50 s on 1000-file firehose diffs — the whole daemon
/// classification budget (ai-auto-writer, 2026-09-19). One batch
/// child serves the driver's lifetime; per-file cost drops to two
/// stats + a pipe round-trip (~0.2 ms measured).
///
/// Correctness contract (outcome-for-outcome with the one-shot path):
/// - The batch reads the caller's index via `:0:path`, exactly what
///   the per-file spawn did. Anything unanswerable (missing,
///   non-blob, oversized, locked, slow) yields `None`, and
///   `clean_reusing_index` treats `None` as "no reusable
///   representation" — always safe, only costs ciphertext churn.
/// - `index.lock` present means our caller (git add) is rewriting
///   the index mid-run: `:0:` reads would race the rewrite, so the
///   batch is dropped and the file goes through with fresh
///   encryption. Faster AND more correct than the old spawn (which
///   happily read a torn index). The lock check is an optimization
///   and common-case guard, not a security boundary: a lock that
///   appears mid-query at worst yields a stale blob, and the
///   `smudge(old) == bytes` comparison in `clean_reusing_index`
///   fails safe back to fresh encryption.
/// - The batch snapshots the index at spawn; if the index mtime
///   moves (a concurrent writer finished between two of our files)
///   the snapshot is stale, so the batch is respawned. One stat per
///   file guards this.
/// - A hung batch (5 s without a response) is killed and the file
///   goes through fresh; the next file respawns. A whole-driver
///   wedge is strictly worse than one slow file, so the timeout
///   fails OPEN toward fresh encryption (policy-valid output —
///   `clean_reusing_index` always computes `fresh` first).
/// - Pathnames come from git verbatim; a `\n` in a name would split
///   the batch framing, so such names skip the lookup (fresh
///   encryption — safe). The one documented narrowing versus the
///   argv spawn, confined to an absurd case.
#[derive(Debug)]
struct IndexBatch {
    /// `.git` dir resolution: `None` = not yet attempted,
    /// `Some(None)` = outside a repo (never try), `Some(Some(_))` =
    /// resolved.
    gitdir: Option<Option<std::path::PathBuf>>,
    live: Option<LiveBatch>,
    /// Spawn the batch child with this cwd instead of inheriting
    /// (tests point it at a fixture repo; production passes `None`
    /// so git discovery matches the driver's own invocation).
    cwd: Option<std::path::PathBuf>,
}

#[derive(Debug)]
struct LiveBatch {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    /// `Some(bytes)` = staged blob, `None` = missing/oversized/non-blob.
    /// Channel close (reader gone) means the child died.
    responses: std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    index_mtime: Option<std::time::SystemTime>,
}

impl Drop for LiveBatch {
    fn drop(&mut self) {
        // Reap, never wedge the driver on a dead child. The reader
        // thread observes EOF and exits on its own (its sender fails
        // once `responses` is dropped with us).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl IndexBatch {
    fn new() -> Self {
        Self {
            gitdir: None,
            live: None,
            cwd: None,
        }
    }

    #[cfg(test)]
    fn with_cwd(path: std::path::PathBuf) -> Self {
        Self {
            gitdir: None,
            live: None,
            cwd: Some(path),
        }
    }

    /// Staged blob for `path`, or `None` when no reusable
    /// representation exists (see the struct contract). Never fails
    /// the caller: every transport problem degrades to fresh
    /// encryption.
    fn lookup(&mut self, path: &str, limit: usize) -> Option<Vec<u8>> {
        if path.contains('\n') {
            return None;
        }
        let dir = match self.gitdir.clone() {
            Some(d) => d,
            None => {
                let resolved = resolve_gitdir(&self.cwd);
                self.gitdir = Some(resolved.clone());
                resolved
            }
        };
        let dir = dir?;
        if dir.join("index.lock").exists() {
            veprintln!(2, "index-batch: index.lock present, skipping lookup");
            self.live = None;
            return None;
        }
        let mtime = std::fs::metadata(dir.join("index"))
            .and_then(|m| m.modified())
            .ok();
        if self.live.as_ref().is_some_and(|l| l.index_mtime != mtime) {
            veprintln!(2, "index-batch: index moved, respawning");
            self.live = None;
        }
        if self.live.is_none() && !self.spawn(&dir, mtime) {
            return None;
        }
        let live = self.live.as_mut()?;
        // A dead-but-unreaped child accepts nothing: EPIPE here
        // means the batch is gone — drop it, go fresh, respawn
        // on the next file.
        if std::io::Write::write_all(&mut live.stdin, format!(":0:{path}\n").as_bytes())
            .and_then(|()| std::io::Write::flush(&mut live.stdin))
            .is_err()
        {
            veprintln!(2, "index-batch: query write failed, dropping batch");
            self.live = None;
            return None;
        }
        match live
            .responses
            .recv_timeout(std::time::Duration::from_secs(5))
        {
            Ok(blob) => {
                let blob = blob?;
                (blob.len() <= limit).then_some(blob)
            }
            Err(_) => {
                veprintln!(
                    2,
                    "index-batch: response timeout/disconnect, dropping batch"
                );
                self.live = None;
                None
            }
        }
    }

    /// Spawn the batch child. `false` = could not spawn (the next
    /// file retries; a missing git binary fails every file fast at
    /// one spawn attempt each — bounded and visible in debug logs).
    fn spawn(&mut self, dir: &std::path::Path, mtime: Option<std::time::SystemTime>) -> bool {
        let mut cmd = ProcessCommand::new("git");
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        let mut child = match cmd
            .args(["cat-file", "--batch"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                veprintln!(2, "index-batch: spawn failed: {}", e);
                return false;
            }
        };
        let stdin = match child.stdin.take() {
            Some(s) => s,
            None => return false,
        };
        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return false,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || index_batch_reader(stdout, tx));
        veprintln!(2, "index-batch: spawned for {}", dir.display());
        self.live = Some(LiveBatch {
            child,
            stdin,
            responses: rx,
            index_mtime: mtime,
        });
        true
    }
}

/// Resolve the repo-local `.git` dir once per driver. `None` =
/// not in a repo (or git missing): lookups stay disabled and every
/// file takes fresh encryption — identical outcome to the old path
/// whose per-file spawn failed the same way.
fn resolve_gitdir(cwd: &Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    let mut cmd = ProcessCommand::new("git");
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let out = cmd
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dir.is_empty() {
        return None;
    }
    let dir = std::path::PathBuf::from(dir);
    // `--absolute-git-dir` prints absolute; belt-and-braces join
    // against the spawn cwd for exotic setups.
    let dir = match cwd {
        Some(c) if dir.is_relative() => c.join(dir),
        _ => dir,
    };
    dir.is_dir().then_some(dir)
}

/// Batch reader thread: owns the child's stdout, delivers one
/// `Option<Vec<u8>>` per query in request order (batch protocol
/// preserves order), exits on EOF/error. The main side abandons a
/// batch wholesale on timeout, so positional matching never
/// diverges: a batch is never reused after a doubt.
fn index_batch_reader(
    stdout: std::process::ChildStdout,
    tx: std::sync::mpsc::Sender<Option<Vec<u8>>>,
) {
    use std::io::BufRead;
    let mut r = std::io::BufReader::new(stdout);
    let mut line = Vec::new();
    loop {
        line.clear();
        // Cap a garbage header line at 1 MiB; overlong means
        // desync — die (main side treats disconnect as batch
        // death and goes fresh).
        let mut capped = r.by_ref().take(1024 * 1024 + 1);
        let n = match capped.read_until(b'\n', &mut line) {
            Ok(0) => return, // clean EOF
            Ok(n) => n,
            Err(_) => return,
        };
        if n > 1024 * 1024 {
            return;
        }
        let header = String::from_utf8_lossy(&line);
        let header = header.trim_end_matches(['\n', '\r']);
        if header.ends_with(" missing") {
            if tx.send(None).is_err() {
                return;
            }
            continue;
        }
        let mut parts = header.split(' ');
        let (typ, size) = match (parts.next(), parts.next(), parts.next()) {
            (Some(_sha), Some(t), Some(s)) => (t, s),
            _ => return, // desync: die
        };
        let size: usize = match size.parse() {
            Ok(n) => n,
            Err(_) => return,
        };
        // Drain framing even for answers we discard (non-blob
        // like a gitlink commit, or over-cap blobs). Past the cap
        // the framing cannot be recovered — die instead.
        let framed = size.checked_add(1); // + trailing newline
        let keep = typ == "blob" && size <= INDEX_BATCH_BLOB_CAP;
        match framed {
            Some(total) if total <= INDEX_BATCH_BLOB_CAP + 1 => {
                let mut buf = vec![0u8; total];
                if std::io::Read::read_exact(&mut r, &mut buf).is_err() {
                    return;
                }
                let body = buf[..size].to_vec();
                if tx.send(keep.then_some(body)).is_err() {
                    return;
                }
            }
            _ => return, // too big to drain: die
        }
    }
}

fn run_filter(is_clean: bool, path: Option<&str>) -> Result<()> {
    // R4-01: relativize an absolute filter path before any guard or
    // matching sees it (refuses outside-root absolutes in clean).
    let owned = normalize_filter_path(path, is_clean)?;
    let path = owned.as_deref();
    // Wire the policy's `protected_patterns` into the filter process
    // (FIX 2026-08-09, warden v0.113.3): the clean-filter gate in
    // `smart_clean_with_path` skips scanning for files that do NOT
    // match a protected pattern, but the gate previously saw an EMPTY
    // pattern list (legacy "scan everything"), so every file was
    // scanned — a 6.87 MB pi-session HTML took ~16 s of regex work,
    // and with git's concurrent filters the 30 s FILTER_TIMEOUT_SECS
    // blew, making `git add` fail every cycle and wedging the sync
    // daemon (junk-runner, 2026-08-09). See
    // docs/design/warden-filter-protected-patterns-wiring-2026-08-09.md.
    wire_managed_patterns_from_policy();
    let guard = configured_clean_guard()?;
    let limit = guard.limit;
    let mut stdin = std::io::stdin().lock();
    let input = read_filter_input(&mut stdin, limit)?;
    // CHANGED 2026-07-21 (v0.112.32, audit M31/F4.5): all three
    // guards (oversized, absolute path, `..` path) now fail closed
    // in the clean direction via the shared predicate. Previously
    // each guard wrote the input back to stdout and exited 0 —
    // committing the file UNENCRYPTED with no warning.
    if let Some(reason) = filter_clean_refusal_with_limit(
        is_clean,
        input.len(),
        path,
        limit,
        &guard.binary_exempt,
        &guard.protected,
        &guard.media,
    ) {
        eprintln!("{}", reason);
        return Err(anyhow::anyhow!("{}", reason));
    }
    if input.len() > limit {
        // Oversize passthrough. The clean direction reaches it only for
        // a size-exempt path (see the binary carve-out above); smudge
        // reaches it for any file. Either way the full content must be
        // preserved, so the bounded prefix is written and the unbounded
        // remainder is copied without ever being buffered.
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&input)?;
        std::io::copy(&mut stdin, &mut stdout)?;
        return Ok(());
    }
    if let Some(p) = path {
        let p_buf = std::path::PathBuf::from(p);
        if p_buf.is_absolute()
            || p_buf
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            eprintln!(
                "dracon-warden: refusing filter path '{}' (smudge passthrough)",
                p
            );
            std::io::stdout().write_all(&input)?;
            return Ok(());
        }
    }

    // FDRACONWARDEN-002 (2026-07-18) path-containment guard: folded
    // into `filter_clean_refusal_reason` above (v0.112.32, audit
    // M31/F4.5) — clean direction fails closed, smudge passes through
    // via the block above.

    let warden = DraconWarden::new()?;
    let output = filter_transform_bytes(
        &warden,
        is_clean,
        path,
        input,
        &guard,
        &mut IndexLookup::OneShot,
    )?;
    std::io::stdout().write_all(&output)?;
    Ok(())
}

/// Pure byte transform shared by the one-shot filter entry points
/// and the long-running `filter-process` driver (v0.113.13). Guards
/// mirror `run_filter` exactly: clean direction fails closed
/// (oversized / absolute / `..` → Err, so git aborts rather than
/// committing plaintext); smudge direction passes through
/// (oversized input echoes — the caller streams the remainder in
/// one-shot mode, while packet mode already holds the whole file).
fn filter_transform_bytes(
    warden: &DraconWarden,
    is_clean: bool,
    path: Option<&str>,
    input: Vec<u8>,
    guard: &CleanGuard,
    lookup: &mut IndexLookup,
) -> Result<Vec<u8>> {
    let limit = guard.limit;
    if let Some(reason) = filter_clean_refusal_with_limit(
        is_clean,
        input.len(),
        path,
        limit,
        &guard.binary_exempt,
        &guard.protected,
        &guard.media,
    ) {
        eprintln!("{}", reason);
        return Err(anyhow::anyhow!("{}", reason));
    }
    if input.len() > limit {
        // Oversize passthrough. Only reachable from the clean direction
        // for a size-exempt path, and from smudge for anything; the
        // whole blob is already in `input` here, so it is returned
        // intact.
        return Ok(input);
    }
    if let Some(p) = path {
        let p_buf = std::path::PathBuf::from(p);
        if p_buf.is_absolute()
            || p_buf
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            eprintln!(
                "dracon-warden: refusing filter path '{}' (smudge passthrough)",
                p
            );
            return Ok(input);
        }
    }
    if is_clean {
        // One-shot filters keep the legacy per-file spawn; the
        // process driver consults its persistent batch session.
        let indexed = match lookup {
            IndexLookup::OneShot => path.and_then(|p| indexed_filter_blob(p, limit)),
            IndexLookup::Batch(b) => path.and_then(|p| b.lookup(p, limit)),
        };
        Ok(warden.clean_with_index(&input, path, indexed.as_deref())?)
    } else {
        Ok(warden.smudge(&input, path)?)
    }
}

/// pkt-line framing for the `git-filter-process` protocol
/// (v0.113.13). Packets are opaque bytes: `4-hex length (including
/// the header) + payload`, `0000` = flush, `0001` = delim (treated
/// as a section boundary like flush). Max payload 65516 bytes.
const PKT_MAX_PAYLOAD: usize = 65516;

/// Largest total packet length expressible in the 4-hex-digit pkt-line
/// header. A payload of exactly 0x10000 - 4 bytes would need five digits.
const PKT_MAX_TOTAL_LEN: usize = 0xFFFF;

/// ADDED 2026-09-27 (audit round 2): hard ceiling on a blob the
/// long-running driver will relay untouched (a size-exempt clean, or an
/// oversize smudge).
///
/// Git's long-running filter protocol gives the driver no flow control:
/// git writes the entire request before reading any of the response, so
/// the response cannot be produced while the request is still arriving
/// (that deadlocks the pipe — see the comment at the accumulation loop).
/// The blob must therefore be held in memory until the request ends, and
/// that hold needs an operator-visible bound rather than trusting a
/// repo-controlled file size.
///
/// Four times `filter_max_bytes` keeps the memory ceiling tied to the
/// operator's own setting (raising `filter_max_bytes` raises this with
/// it) while leaving room for the case the carve-out exists for: a
/// multi-megabyte screenshot or archive several times the scan limit.
/// At the policy maximum of 64 MiB the bound is 256 MiB for one blob;
/// `Vec` growth doubles, so a request that reaches the bound can hold
/// roughly 1.5x that for the duration of the last reallocation.
fn passthrough_ceiling_bytes(limit: usize) -> usize {
    limit.saturating_mul(4).max(STREAM_IO_MAX_BYTES)
}

/// The over-ceiling refusal message, with a direction-appropriate recovery.
///
/// ADDED 2026-10-03 (audit R4-W-04): the smudge hint names the one-shot
/// path, which streams oversize blobs with NO ceiling — the deliberate
/// divergence from this driver, which must buffer-then-emit (consume the
/// whole request before answering) or deadlock the pipe. An over-ceiling
/// blob therefore fails checkout/diff under the installed filter-process
/// driver while remaining recoverable one file at a time.
fn over_ceiling_reason(content_len: usize, ceiling: usize, direction: Option<bool>) -> String {
    let mut reason = format!(
        "dracon-warden: refusing to relay {} (> {} byte passthrough ceiling = 4x filter_max_bytes): \
         git's long-running filter protocol has no flow control, so a blob this large cannot be \
         streamed back without deadlocking the pipe. .gitignore it, or raise filter_max_bytes.",
        content_len.saturating_add(1),
        ceiling
    );
    if direction == Some(false) {
        reason.push_str(
            " Recover an over-ceiling checkout with the one-shot path, which streams without a \
             ceiling: git show HEAD:<path> | dracon-warden filter-smudge <path> > <path>.",
        );
    }
    reason
}

fn pkt_encode(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return b"0000".to_vec();
    }
    // FIXED 2026-09-27 (audit F96): `format!("{:04x}", n)` does not
    // TRUNCATE — for n >= 0x10000 it emits five digits, producing a
    // five-character length header that desynchronises the whole
    // pkt-line stream ("bad packet length" on the next read). Every
    // production caller chunks at PKT_MAX_PAYLOAD so it never bit, but
    // the helper is reachable from tests and any future caller, so the
    // bound is now enforced here rather than left to convention.
    let take = payload.len().min(PKT_MAX_TOTAL_LEN - 4);
    if take != payload.len() {
        debug_assert!(
            false,
            "pkt_encode called with a payload larger than the pkt-line maximum; truncating"
        );
    }
    let mut out = Vec::with_capacity(take + 4);
    out.extend_from_slice(format!("{:04x}", take + 4).as_bytes());
    out.extend_from_slice(&payload[..take]);
    out
}

#[derive(Debug, PartialEq)]
enum Pkt {
    Flush,
    Delim,
    Data(Vec<u8>),
}

/// None = clean EOF at a packet boundary (git closed stdin: done).
/// EOF mid-packet is a protocol error.
fn pkt_read<R: std::io::Read>(r: &mut R) -> Result<Option<Pkt>> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("filter-process header read: {}", e)),
    }
    if &hdr == b"0000" {
        return Ok(Some(Pkt::Flush));
    }
    if &hdr == b"0001" {
        return Ok(Some(Pkt::Delim));
    }
    let hdr_str = std::str::from_utf8(&hdr)
        .map_err(|_| anyhow::anyhow!("filter-process: non-hex packet header"))?;
    let len = usize::from_str_radix(hdr_str, 16)
        .map_err(|_| anyhow::anyhow!("filter-process: bad packet length '{}'", hdr_str))?;
    if len < 4 {
        return Err(anyhow::anyhow!("filter-process: packet length {} < 4", len));
    }
    let mut payload = vec![0u8; len - 4];
    r.read_exact(&mut payload)
        .map_err(|e| anyhow::anyhow!("filter-process payload read: {}", e))?;
    Ok(Some(Pkt::Data(payload)))
}

/// Split a `key=value` protocol line. Returns None for malformed lines.
/// Git appends `\n` to protocol lines (observed git 2.51.2) — strip
/// one trailing newline so both old and new peers parse.
fn pkt_kv(line: &[u8]) -> Option<(&str, &str)> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let s = std::str::from_utf8(line).ok()?;
    let (k, v) = s.split_once('=')?;
    Some((k, v))
}

/// Encode a protocol KEY line the way git sends them (trailing
/// `\n`; observed git 2.51.2). Content packets stay raw.
fn pkt_key_line(s: &str) -> Vec<u8> {
    pkt_encode(format!("{}\n", s).as_bytes())
}

/// Long-running filter driver: one process serves every file in the
/// git command (v0.113.13). Reads requests on stdin, writes
/// responses on stdout, exits 0 on clean EOF. Returns the process
/// exit code (0 = clean EOF; 1 = handshake violation, I/O error,
/// or config failure — all fail closed: git aborts the operation).
/// Timestamped trace line for filter-process forensics, gated on the
/// CLI's `-vv` verbosity flag (stderr — git surfaces driver stderr on
/// failure). Permanent: the driver is otherwise a black box when
/// git reports "remote end hung up".
///
/// CHANGED 2026-09-27 (audit F95): the trace used to be gated on the
/// `DRACON_FILTER_DEBUG=1` environment variable instead. The driver is
/// spawned by git, not by a shell the operator controls, so that env
/// var was effectively unsettable on the real path — the tracing it
/// documents was unreachable in production. All warden's diagnostics
/// now share the `-v`/`-vv` flag that the CLI already documents.
fn run_filter_process() -> i32 {
    veprintln!(2, "start");
    wire_managed_patterns_from_policy();
    veprintln!(2, "patterns wired");
    let guard = match configured_clean_guard() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("dracon-warden: filter-process config failed: {}", e);
            return 1;
        }
    };
    // Constructed ONCE for the whole git command (the one-shot
    // path pays this per file — part of the cost being removed).
    let warden = match DraconWarden::new() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("dracon-warden: filter-process init failed: {}", e);
            return 1;
        }
    };
    veprintln!(2, "warden constructed");
    let mut input = std::io::BufReader::new(std::io::stdin());
    let mut output = std::io::BufWriter::new(std::io::stdout());
    if let Err(e) = filter_process_serve(&mut input, &mut output, &warden, &guard) {
        eprintln!("dracon-warden: filter-process error: {}", e);
        return 1;
    }
    0
}

fn filter_process_serve<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    warden: &DraconWarden,
    guard: &CleanGuard,
) -> Result<()> {
    // --- Handshake: expect `git-filter-client` first, then
    // capabilities until flush. Anything else is a violation.
    // Phase 1: client greeting (`git-filter-client`, version,
    // flush). Some peers append capability lines here; record
    // them but answer in phase 2.
    let mut first = true;
    let mut offered = Vec::new();
    loop {
        match pkt_read(input)? {
            None => return Err(anyhow::anyhow!("EOF during handshake")),
            Some(Pkt::Delim) => continue,
            Some(Pkt::Flush) => break,
            Some(Pkt::Data(line)) => {
                let norm = line.strip_suffix(b"\n").unwrap_or(&line);
                if first && norm != b"git-filter-client" {
                    return Err(anyhow::anyhow!("not a git-filter client"));
                }
                first = false;
                offered.push(norm.to_vec());
            }
        }
    }
    for cap in ["git-filter-server", "version=2"] {
        output.write_all(&pkt_key_line(cap))?;
    }
    output.write_all(b"0000")?;
    output.flush()?;
    // Phase 2: the client sends its capability list (modern git
    // 2.51 sends `clean/smudge/delay` HERE, after reading the
    // greeting — verified by byte capture). Answer with the
    // intersection we actually implement; `delay` is never
    // echoed (no deferred filtering). Then flush.
    //
    // A peer that advertised capabilities in phase 1 may skip
    // straight to requests: if the section holds a `command=`
    // line it IS the first request — serve it instead of
    // answering negotiation.
    let mut want_clean = offered.iter().any(|l| l == b"capability=clean");
    let mut want_smudge = offered.iter().any(|l| l == b"capability=smudge");
    let mut section: Vec<Vec<u8>> = Vec::new();
    loop {
        match pkt_read(input)? {
            None => return Ok(()),
            Some(Pkt::Delim) => continue,
            Some(Pkt::Flush) => break,
            Some(Pkt::Data(line)) => {
                let norm = line.strip_suffix(b"\n").unwrap_or(&line);
                if norm == b"capability=clean" {
                    want_clean = true;
                } else if norm == b"capability=smudge" {
                    want_smudge = true;
                }
                section.push(norm.to_vec());
            }
        }
    }
    veprintln!(
        2,
        "handshake done clean={} smudge={}",
        want_clean,
        want_smudge
    );
    // One batch session for the driver's whole lifetime (v0.113.14):
    // per-file spawns serialize into tens of seconds on firehose
    // repos. Created up front; resolution is lazy inside (first
    // clean request pays one `rev-parse`, non-repo drivers disable
    // silently and take fresh encryption per file).
    let mut lookup = IndexLookup::Batch(IndexBatch::new());
    if section.iter().any(|l| l.starts_with(b"command=")) {
        veprintln!(2, "phase-2 section was a request, serving directly");
        serve_one_request(input, output, warden, guard, &section, &mut lookup)?;
    } else {
        if want_clean {
            output.write_all(&pkt_key_line("capability=clean"))?;
        }
        if want_smudge {
            output.write_all(&pkt_key_line("capability=smudge"))?;
        }
        output.write_all(b"0000")?;
        output.flush()?;
    }
    // --- Request loop until clean EOF.
    loop {
        let mut header: Vec<Vec<u8>> = Vec::new();
        loop {
            match pkt_read(input)? {
                None => return Ok(()),
                // Delim is a no-op separator (git 2.51 emits one
                // around request sections); only flush ends a
                // section.
                Some(Pkt::Delim) => continue,
                Some(Pkt::Flush) => break,
                Some(Pkt::Data(line)) => {
                    header.push(line.strip_suffix(b"\n").unwrap_or(&line).to_vec());
                }
            }
        }
        serve_one_request(input, output, warden, guard, &header, &mut lookup)?;
    }
}

/// Serve one request whose header lines were already collected:
/// parse command/pathname, read content, transform, respond.
/// Delims inside content are skipped (chunks concatenate
/// identically); only flush ends the content section.
fn serve_one_request<R: std::io::Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    warden: &DraconWarden,
    guard: &CleanGuard,
    header: &[Vec<u8>],
    lookup: &mut IndexLookup,
) -> Result<()> {
    let limit = guard.limit;
    let mut command: Option<&str> = None;
    let mut pathname: Option<&str> = None;
    for line in header {
        if let Some((k, v)) = pkt_kv(line) {
            match k {
                "command" => command = Some(v),
                "pathname" => pathname = Some(v),
                _ => {}
            }
        }
    }
    let Some(command) = command else {
        return Err(anyhow::anyhow!("request without command"));
    };
    // Only clean/smudge were advertised; anything else (e.g.
    // list_available_blobs) fails closed per file — the
    // driver stays up to serve the rest. The decision is made from the
    // HEADER (before the body), but the body is still drained below in
    // every case: the pkt-line protocol is positional, so returning
    // early would leave the next request misaligned.
    let direction = match command {
        "clean" => Some(true),
        "smudge" => Some(false),
        other => {
            eprintln!(
                "dracon-warden: filter-process unsupported command '{}'",
                other
            );
            None
        }
    };
    veprintln!(2, "request command={} pathname={:?}", command, pathname);
    let t0 = std::time::Instant::now();
    // FIXED 2026-09-27 (audit F96): this loop used to
    // `content.extend_from_slice(&chunk)` with no length check, so the
    // WHOLE blob was resident in RAM before `filter_transform_bytes`
    // ever consulted `limit`. The one-shot path this replaced
    // deliberately caps its read at `limit + 1` via `reader.take()` and
    // streams the remainder; the bound was lost in the v0.113.13
    // migration, so a repo-controlled multi-GB blob in any repo with
    // `* filter=dracon` drove unbounded RSS in a security-critical
    // process (and the code even documented the asymmetry).
    //
    // Bounded accumulation:
    //   * up to `limit + 1` bytes are buffered, mirroring read_filter_input;
    //   * the clean direction NEVER relays early — a clean refusal must be
    //     able to abort the add, and nothing may reach `output` before the
    //     decision. Packets past the bound are drained and dropped unless
    //     the header already waived the size guard.
    //   * a waived/oversize relay (smudge, or a size-exempt clean) is
    //     buffered up to `passthrough_ceiling_bytes(limit)` and written
    //     only after the request ends — writing early deadlocks against
    //     git, which writes the whole request before it reads. Past the
    //     ceiling the body is drained and dropped and the file is
    //     reported as an error, never as a truncated blob.
    let cap = limit.saturating_add(1);
    // FIXED 2026-09-27 (audit round 1, MED): whether an oversize clean
    // of THIS path would be permitted has to be settled HERE, from the
    // header, before the body loop runs. The loop drops everything past
    // `cap` for the clean direction (a refusal must be able to abort the
    // add, so nothing may reach `output` before the decision), so by the
    // time the oversize branch is reached the tail is already gone and
    // the passthrough could not be emitted.
    //
    // `limit + 1` as the length forces the size branch to be taken, so
    // a `None` here means "size is the only thing that could refuse, and
    // it is waived" — the path-shape guards below are still live.
    let clean_passthrough = direction == Some(true)
        && filter_clean_refusal_with_limit(
            true,
            limit.saturating_add(1),
            pathname,
            limit,
            &guard.binary_exempt,
            &guard.protected,
            &guard.media,
        )
        .is_none();
    // A clean passthrough is handled exactly like smudge: the bytes past
    // the bound must reach the output, so they cannot simply be dropped.
    let deferred = direction == Some(false) || clean_passthrough;
    // ADDED 2026-09-27 (audit round 2, HIGH): the response may NOT be
    // written while the request is still arriving.
    //
    // Measured against real git 2.51.2: the long-running filter protocol
    // makes git write the ENTIRE request before it reads ANY response
    // (the one-shot clean/smudge path is not affected — a 12 MiB
    // oversize smudge streams through `std::io::copy` there without
    // stalling). So a driver that streams the response as it consumes
    // the request deadlocks as soon as the response outgrows the 64 KiB
    // pipe buffer while the request still has bytes to write: git blocks
    // in write(), the driver blocks in write(), and the operation hangs
    // FOREVER. Measured with a 10 MiB limit: an oversize blob 1 KiB over
    // the limit completed, 640 KiB over the limit hung (wchan
    // `anon_pipe_write` on git, driver blocked in write). That is
    // precisely D2's headline case — a 20 MiB screenshot — so the
    // carve-out traded a loud refusal for a silent hang.
    //
    // The pkt-line protocol has no flow control, so the only correct
    // shape is: consume the whole request, THEN emit the response. The
    // body is therefore buffered up to `ceiling` and the response is
    // written after the terminating flush. Memory stays bounded (the
    // ceiling is a small multiple of the operator's own
    // `filter_max_bytes`); a blob beyond the ceiling keeps the stream in
    // sync by draining-and-dropping and is reported as an error rather
    // than silently truncated.
    let ceiling = passthrough_ceiling_bytes(limit);
    let mut content: Vec<u8> = Vec::new();
    let mut oversized = false;
    // Set once a deferred passthrough has buffered more than `ceiling`
    // bytes; the rest of the body is drained and dropped.
    let mut overflowed = false;
    loop {
        match pkt_read(input)? {
            None => return Err(anyhow::anyhow!("EOF mid-content")),
            Some(Pkt::Delim) => continue,
            Some(Pkt::Flush) => break,
            Some(Pkt::Data(chunk)) => {
                let already_oversized = oversized;
                // Bytes of THIS chunk that make it past the bound.
                let accepted = if already_oversized {
                    0
                } else if content.len() + chunk.len() > cap {
                    // Keep exactly `cap` bytes so the oversize decision sees
                    // the same length the one-shot path would have.
                    let take = cap.saturating_sub(content.len());
                    content.extend_from_slice(&chunk[..take]);
                    oversized = true;
                    take
                } else {
                    content.extend_from_slice(&chunk);
                    chunk.len()
                };
                if !oversized {
                    continue;
                }
                if !deferred {
                    // clean (not exempt) + unsupported: drain the rest to
                    // keep the protocol in sync, but never emit it.
                    continue;
                }
                // The tail of the chunk that crossed the bound
                // (`chunk[accepted..]`) belongs to the deferred body too —
                // dropping it would silently truncate every oversize blob.
                if !overflowed {
                    let tail = &chunk[accepted..];
                    if content.len() + tail.len() <= ceiling {
                        content.extend_from_slice(tail);
                    } else {
                        // Past the ceiling: stop buffering, keep draining
                        // so the stream stays in sync, and fail the file
                        // below. The buffered prefix is never emitted, so
                        // there is no truncated content in the object
                        // store.
                        overflowed = true;
                    }
                }
            }
        }
    }
    veprintln!(2, "content {} bytes in {:?}", content.len(), t0.elapsed());
    if overflowed {
        // Every direction: a blob larger than the passthrough ceiling
        // cannot be relayed without risking the pipe deadlock above, and
        // a partial relay would corrupt the object. Report it per file;
        // the driver stays up for the rest of the command. (R4-W-04: the
        // one-shot filter-smudge has NO ceiling and stays the recovery
        // path for an over-ceiling smudge — see over_ceiling_reason.)
        let reason = over_ceiling_reason(content.len(), ceiling, direction);
        eprintln!("{}", reason);
        output.write_all(&pkt_key_line("status=error"))?;
        output.write_all(b"0000")?;
        output.flush()?;
        return Ok(());
    }
    // Unsupported command: the body above has been drained, so the
    // protocol is still in sync. Fail closed for this file only.
    let Some(direction) = direction else {
        output.write_all(&pkt_key_line("status=error"))?;
        output.write_all(b"0000")?;
        output.flush()?;
        return Ok(());
    };
    if oversized {
        // FIXED 2026-09-27 (audit round 1, MED): the clean branch used
        // to `unwrap_or_else` a hard refusal, discarding the `None` case
        // — so a size-exempt binary was refused here even though the
        // one-shot path passed it through, and the three entry points
        // disagreed. `filter.dracon.process` is the driver warden itself
        // installs, i.e. the path every hardened repo uses, so that made
        // the stale-`.gitattributes` case the common one. Both
        // directions now fall through to the same passthrough below; the
        // exemption was already decided from the header, before the
        // body was consumed.
        if direction && !clean_passthrough {
            let reason = filter_clean_refusal_with_limit(
                true,
                cap,
                pathname,
                limit,
                &guard.binary_exempt,
                &guard.protected,
            &guard.media,
            )
            .unwrap_or_else(|| {
                format!(
                    "dracon-warden: refusing to clean more than {} bytes (the file would be committed UNENCRYPTED)",
                    limit
                )
            });
            eprintln!("{}", reason);
            output.write_all(&pkt_key_line("status=error"))?;
            output.write_all(b"0000")?;
            output.flush()?;
            return Ok(());
        }
        // Smudge, or an exempt clean: the whole blob is buffered (the
        // request has been fully consumed by now, so writing cannot
        // deadlock), then the pkt-line response shape: status list,
        // content, mandatory empty terminator lists.
        output.write_all(&pkt_key_line("status=success"))?;
        output.write_all(b"0000")?;
        for framed in content.chunks(PKT_MAX_PAYLOAD) {
            output.write_all(&pkt_encode(framed))?;
        }
        output.write_all(b"0000")?;
        output.write_all(b"0000")?;
        output.flush()?;
        return Ok(());
    }
    let t1 = std::time::Instant::now();
    let r = filter_transform_bytes(warden, direction, pathname, content, guard, lookup);
    veprintln!(2, "transform done in {:?}", t1.elapsed());
    match r {
        Ok(bytes) => {
            // Response shape per gitattributes(5) long-running
            // filter: status list + flush, content + flush,
            // SECOND (here empty) list + flush. Omitting the
            // trailing empty list desyncs git: it keeps reading
            // for the final terminator (observed 2026-09-19:
            // add stalls after the first file).
            output.write_all(&pkt_key_line("status=success"))?;
            output.write_all(b"0000")?;
            for chunk in bytes.chunks(PKT_MAX_PAYLOAD) {
                output.write_all(&pkt_encode(chunk))?;
            }
            output.write_all(b"0000")?;
            output.write_all(b"0000")?;
        }
        Err(e) => {
            // Fail closed: git aborts the diff/add rather than
            // committing unfiltered content.
            eprintln!("dracon-warden: filter-process transform failed: {}", e);
            output.write_all(&pkt_key_line("status=error"))?;
            output.write_all(b"0000")?;
        }
    }
    output.flush()?;
    Ok(())
}

/// Git merge driver implementation (`dracon-warden merge %O %A %B`).
///
/// `.gitattributes` marks protected patterns `merge=dracon`; this is the
/// driver `merge.dracon.driver` registers (see `ensure_repo_filter_config`).
/// Without it git falls back to the text driver and merges CIPHERTEXT — a
/// conflict yields undecryptable garbage. Here all three inputs are
/// decrypted first (whole-file tag, then inline markers; untagged content
/// passes through untouched), `git merge-file` runs a 3-way text merge on
/// the plaintexts, and the merged result is re-encrypted into %A so the
/// index keeps the filter.dracon invariant (index = ciphertext, worktree =
/// plaintext).
///
/// Conflict semantics: git's merge driver contract is exit 0 = merged
/// cleanly, nonzero = conflicts remain. On conflict the PLAINTEXT with
/// conflict markers is left in %A (git marks the path unmerged); the
/// operator resolves in plaintext and `git add` re-encrypts via the clean
/// filter. On success %A holds ciphertext and exit 0 is returned.
fn run_merge(ancestor: &Path, current: &Path, other: &Path) -> Result<i32> {
    let warden = DraconWarden::new()?;
    // CHANGED 2026-09-09 (audit F49): the encrypt closure used to call
    // `warden.clean` with the %A TEMP path, so the protected-patterns
    // gate missed and merged plaintext was committed. Re-encrypt via the
    // path-independent merge clean instead; the ancestor ciphertext
    // carries the whole-file-vs-inline format decision.
    let ancestor_raw = std::fs::read(ancestor).unwrap_or_default();
    run_merge_impl(
        ancestor,
        current,
        other,
        |b, p| warden.smudge(b, p),
        |b, _p| warden.clean_for_merge(b, &ancestor_raw),
    )
}

/// Driver logic with injectable encrypt/decrypt (unit tests inject a fresh
/// `WardenSecurity` with a memory identity instead of the process-global
/// one behind `DraconWarden`).
fn run_merge_impl<D, C>(
    ancestor: &Path,
    current: &Path,
    other: &Path,
    decrypt: D,
    encrypt: C,
) -> Result<i32>
where
    D: Fn(&[u8], Option<&str>) -> Result<Vec<u8>>,
    C: Fn(&[u8], Option<&str>) -> Result<Vec<u8>>,
{
    let read_decrypted = |p: &Path| -> Result<Vec<u8>> {
        let bytes = fs::read(p)?;
        let path_str = p.to_string_lossy().to_string();
        decrypt(&bytes, Some(&path_str))
    };
    // CORRECTED 2026-09-09 (audit F49): %O/%A/%B are TEMP files
    // materialized by git for the driver (NOT worktree files) — the old
    // comment claimed %A/%B were worktree plaintext. %O arrives as raw
    // ciphertext; smudge handles both (tagged decrypts, untagged passes
    // through). Re-encryption must NOT depend on these temp paths (see
    // `run_merge`: path-independent merge clean).
    let ancestor_pt = read_decrypted(ancestor)?;
    let current_pt = read_decrypted(current)?;
    let other_pt = read_decrypted(other)?;
    let (merged, conflicted) = text_merge(&ancestor_pt, &current_pt, &other_pt)?;
    if conflicted {
        fs::write(current, &merged)?;
        return Ok(1);
    }
    let path_str = current.to_string_lossy().to_string();
    let encrypted = encrypt(&merged, Some(&path_str))?;
    fs::write(current, encrypted)?;
    Ok(0)
}

/// 3-way text merge of already-decrypted contents via `git merge-file -p`.
/// Returns (merged bytes, conflicted). Exit 0 from merge-file means a clean
/// merge; exit 1 means conflict markers are present in the output.
/// FIXED 2026-10-03 (audit R3-L19): any OTHER status (exit >1, signal
/// death) is an internal error, NOT a conflict — the old
/// `!success()` mapping took the conflict path and overwrote %A with
/// possibly-empty stdout. Errors propagate (the caller writes %A only
/// on Ok), leaving stages 1/2/3 in the index for `git checkout -m`.
fn text_merge(ancestor: &[u8], current: &[u8], other: &[u8]) -> Result<(Vec<u8>, bool)> {
    let dir = tempfile::tempdir().context("failed to create merge temp dir")?;
    let dir = dir.path();
    let write_tmp = |name: &str, bytes: &[u8]| -> Result<PathBuf> {
        let p = dir.join(name);
        fs::write(&p, bytes)?;
        Ok(p)
    };
    let ancestor_path = write_tmp("ancestor", ancestor)?;
    let current_path = write_tmp("current", current)?;
    let other_path = write_tmp("other", other)?;
    let output = ProcessCommand::new("git")
        .arg("merge-file")
        .arg("-p")
        .arg(&current_path)
        .arg(&ancestor_path)
        .arg(&other_path)
        .output()
        .context("failed to run git merge-file")?;
    match output.status.code() {
        Some(0) => Ok((output.stdout, false)),
        Some(1) => Ok((output.stdout, true)),
        other => Err(anyhow::anyhow!(
            "git merge-file failed (status {:?}): {}",
            other,
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookMode {
    Global,
    Local,
}

/// Marker embedded in every generated hook so foreign hooks that merely
/// mention "Dracon Warden" are not mistaken for managed wrappers.
const WARDEN_HOOK_MARKER: &str = "# dracon-warden-managed-hook-v1";

/// Marker replaced with the absolute path of a preserved foreign hook.
///
/// The empty string is used when no same-name foreign hook was present.
const FOREIGN_HOOK_PLACEHOLDER: &str = "__DRACON_FOREIGN_HOOK__";

/// Quote a value for use as one POSIX shell word.
fn shell_single_quote(value: &Path) -> String {
    let escaped = value.to_string_lossy().replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Hook-only SECRET_RE alternatives (test-only: the freshness check renders
/// the checked-in template line from these plus the token-shape source).
/// Quoted password/secret/api_key assignments plus the bare-password form.
/// assignments plus the bare-password form. These have no Tier-1
/// counterpart (keyword-anchored shapes stay out of Tier-1 by the
/// membership bar); the token shapes come from
/// `SecretScanner::hook_token_shapes_ere`, and `HOOK_PEM_HEADER_ALTERNATIVE`
/// covers the eight multi-line private-key Tier-1 entries the
/// line-oriented hook cannot express. Verbatim shell — the `'\\''` idiom
/// survives POSIX single-quote parsing (2026-08-12), and `\\s`/`[^...]`
/// are `grep -E` escapes, not Rust ones.
#[cfg(test)]
const HOOK_ASSIGNMENT_ALTERNATIVES: &str = "password\\s*=\\s*[\"'\\''][^\"'\\'']+|secret\\s*=\\s*[\"'\\''][^\"'\\'']+|api_key\\s*=\\s*[\"'\\''][^\"'\\'']+|password\\s*=\\s*[^[:space:]\"'']{6,}";
#[cfg(test)]
const HOOK_PEM_HEADER_ALTERNATIVE: &str = "-----BEGIN [A-Z]+ PRIVATE KEY";

/// Render the pre-push hook's SECRET_RE alternation from the single
/// token-shape source (`SecretScanner::hook_token_shapes_ere`, audit M10).
/// The PRE_PUSH_HOOK template carries the checked-in render (the template
/// must stay directly runnable: the behavioral hook tests execute it as a
/// real shell subprocess); `pre_push_hook_secret_re_matches_token_shape_source`
/// fails with the new line to paste whenever the source changes.
#[cfg(test)]
fn hook_secret_re_from_source() -> String {
    let mut alts = vec![HOOK_PEM_HEADER_ALTERNATIVE, HOOK_ASSIGNMENT_ALTERNATIVES];
    alts.extend(
        SecretScanner::hook_token_shapes_ere()
            .into_iter()
            .map(|(_, ere)| ere),
    );
    format!("({})", alts.join("|"))
}

/// Render a hook with an optional preserved foreign global hook path.
fn render_hook(content: &str, foreign_hook: Option<&Path>) -> String {
    let replacement = foreign_hook
        .map(shell_single_quote)
        .unwrap_or_else(|| "''".to_string());
    content.replace(FOREIGN_HOOK_PLACEHOLDER, &replacement)
}

/// Return true when `path` is a hook written by Warden.
fn is_warden_hook(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| content.lines().any(|line| line == WARDEN_HOOK_MARKER))
        .unwrap_or(false)
}

/// Pre-marker warden hooks (v0.113.13 migration): the ancient
/// `init.templateDir` generation carries "Installed by:
/// dracon-warden setup-hooks" but no marker and demands
/// `filter.dracon.clean` — it would block every commit after the
/// process-driver migration. Unambiguously warden's (that string
/// only exists in warden's own old output) and chain-free (the
/// gen-1 template never chained), so wholesale replacement with
/// the current template is safe.
fn is_legacy_warden_hook(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| {
            !content.lines().any(|line| line == WARDEN_HOOK_MARKER)
                && content.contains("Installed by: dracon-warden setup-hooks")
        })
        .unwrap_or(false)
}

/// Rewrite a warden-owned hook when its content drifted from the
/// current template (v0.113.13). Returns true when refreshed.
/// Missing paths and foreign (user) hooks are left alone — the
/// caller handles fresh installs; this only repairs drift.
/// Pre-marker legacy warden hooks are also replaced (they predate
/// chaining, so wholesale replacement loses nothing). A recorded
/// foreign chain is preserved via `rendered_foreign_hook`.
fn refresh_warden_hook_if_stale(path: &Path, template: &str) -> Result<bool> {
    if !path.exists() || (!is_warden_hook(path) && !is_legacy_warden_hook(path)) {
        return Ok(false);
    }
    let rendered = render_hook(template, rendered_foreign_hook(path).as_deref());
    let current = fs::read_to_string(path)
        .with_context(|| format!("failed to read hook {}", path.display()))?;
    if current == rendered {
        return Ok(false);
    }
    write_hook_atomically(path, &rendered)?;
    Ok(true)
}

/// Refresh stale warden-owned hooks in the GLOBAL hooks dir
/// (`~/.config/git/hooks`, v0.113.13). The fleet runs with a
/// global `core.hooksPath`, so the global pre-commit wrapper's
/// driver probe gates EVERY commit — leaving it stale blocks the
/// whole fleet post-migration. Pure refresh: never installs into
/// an empty dir (fresh installs stay behind `setup-hooks`).
/// Returns true when any hook was refreshed.
fn refresh_global_hooks_if_stale() -> Result<bool> {
    let dir = hook_dir(HookMode::Global, None)?;
    if !dir.exists() {
        return Ok(false);
    }
    let mut refreshed = false;
    for (name, template) in [
        ("pre-commit", PRE_COMMIT_HOOK),
        ("pre-push", PRE_PUSH_HOOK),
        ("pre-rebase", PRE_REBASE_HOOK),
    ] {
        refreshed |= refresh_warden_hook_if_stale(&dir.join(name), template)?;
    }
    Ok(refreshed)
}

/// Choose a non-destructive backup path for a foreign global hook.
fn next_foreign_hook_backup(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("hook path has no usable filename: {}", path.display()))?;
    let base = path.with_file_name(format!("{file_name}.dracon-foreign"));
    if !base.exists() {
        return Ok(base);
    }

    let pid = std::process::id();
    for index in 0..10_000u32 {
        let candidate = path.with_file_name(format!("{file_name}.dracon-foreign.{pid}.{index}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow::anyhow!(
        "could not choose a backup path for foreign hook {}",
        path.display()
    ))
}

/// Find the preserved foreign hook that a newly-rendered wrapper should call.
fn existing_foreign_hook_backup(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    let base = path.with_file_name(format!("{file_name}.dracon-foreign"));
    base.is_file().then_some(base)
}

/// Recover the exact foreign-hook path from a previously-rendered wrapper.
///
/// A collision can force `next_foreign_hook_backup` to use a PID/index
/// suffix. Looking only for the unsuffixed sibling on a repeat installation
/// could then silently replace the real backup with an unrelated file.
fn rendered_foreign_hook(path: &Path) -> Option<PathBuf> {
    let content = fs::read_to_string(path).ok()?;
    let value = content
        .lines()
        .find_map(|line| line.strip_prefix("DRACON_FOREIGN_HOOK="))?;
    let quoted = value.strip_prefix('\'')?.strip_suffix('\'')?;
    if quoted.is_empty() {
        return None;
    }
    Some(PathBuf::from(quoted.replace("'\\''", "'")))
}

/// Prepare an executable hook in a same-directory temporary file.
fn prepare_hook(path: &Path, content: &[u8]) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("hook path has no parent: {}", path.display()))?;
    let mut temp = tempfile::Builder::new()
        .prefix(".dracon-hook-")
        .tempfile_in(parent)
        .with_context(|| format!("failed to create temporary hook in {}", parent.display()))?;
    temp.write_all(content)
        .with_context(|| format!("failed to write temporary hook for {}", path.display()))?;
    temp.flush()
        .with_context(|| format!("failed to flush temporary hook for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary hook for {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(temp)
}

/// Restore an executable hook from bytes after a failed multi-hook install.
fn restore_hook_bytes(path: &Path, content: &[u8]) -> Result<()> {
    let temp = prepare_hook(path, content)?;
    temp.persist(path).map_err(|error| {
        anyhow::anyhow!("failed to restore hook {}: {}", path.display(), error.error)
    })?;
    Ok(())
}

/// Replace a hook with a fully-written executable file in one rename.
///
/// Hook installation is security-sensitive: a direct `fs::write` truncates
/// the active hook before the replacement is complete, and a failed write can
/// leave Git with a partial enforcement script. The temporary file lives in
/// the same directory so the final rename is atomic on the supported Unix
/// deployments.
fn write_hook_atomically(path: &Path, content: &str) -> Result<()> {
    let temp = prepare_hook(path, content.as_bytes())?;
    temp.persist(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to atomically install hook {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

/// One staged hook replacement.
struct HookInstallPlan {
    target: PathBuf,
    original: Option<Vec<u8>>,
    foreign_backup: Option<PathBuf>,
    moved_foreign: bool,
    temp: Option<tempfile::NamedTempFile>,
}

/// Install all Warden hooks as one staged operation while preserving same-name
/// foreign hooks under `.dracon-foreign` siblings for explicit chaining.
fn install_hook_set(dir: &Path) -> Result<Vec<PathBuf>> {
    let specs = [
        ("pre-commit", PRE_COMMIT_HOOK),
        ("pre-push", PRE_PUSH_HOOK),
        ("pre-rebase", PRE_REBASE_HOOK),
    ];
    let mut plans = Vec::with_capacity(specs.len());

    // Stage every replacement before changing any live hook. This catches
    // permission, disk, and temp-file failures before the first rename.
    for (name, content) in specs {
        let target = dir.join(name);
        let original = if target.exists() {
            Some(fs::read(&target).with_context(|| {
                format!("failed to read existing global hook {}", target.display())
            })?)
        } else {
            None
        };
        let target_exists = target.exists();
        let target_is_warden = target_exists && is_warden_hook(&target);
        let foreign_backup = if target_exists && !target_is_warden {
            Some(next_foreign_hook_backup(&target)?)
        } else if target_is_warden {
            // Keep chaining the exact backup recorded in the existing wrapper
            // when setup is repeated. This also handles the PID/index suffix
            // chosen by `next_foreign_hook_backup` after a name collision.
            rendered_foreign_hook(&target).or_else(|| existing_foreign_hook_backup(&target))
        } else {
            existing_foreign_hook_backup(&target)
        };
        let rendered = render_hook(content, foreign_backup.as_deref());
        let temp = prepare_hook(&target, rendered.as_bytes())?;
        plans.push(HookInstallPlan {
            target,
            original,
            foreign_backup,
            moved_foreign: false,
            temp: Some(temp),
        });
    }

    let install_result = (|| -> Result<()> {
        for plan in &mut plans {
            if plan.target.exists() && !is_warden_hook(&plan.target) {
                if let Some(backup) = plan.foreign_backup.as_ref() {
                    fs::rename(&plan.target, backup).with_context(|| {
                        format!("failed to preserve foreign hook {}", plan.target.display())
                    })?;
                    plan.moved_foreign = true;
                }
            }
        }

        for plan in &mut plans {
            let temp = plan
                .temp
                .take()
                .expect("every global hook was staged before installation");
            temp.persist(&plan.target).map_err(|error| {
                anyhow::anyhow!(
                    "failed to atomically install hook {}: {}",
                    plan.target.display(),
                    error.error
                )
            })?;
        }
        Ok(())
    })();

    if let Err(error) = install_result {
        // Best-effort rollback keeps a failed setup from leaving a partially
        // installed hook set or losing a preserved foreign hook.
        for plan in plans.iter_mut().rev() {
            if plan.moved_foreign {
                let _ = fs::remove_file(&plan.target);
                if let Some(backup) = plan.foreign_backup.as_ref() {
                    let _ = fs::rename(backup, &plan.target);
                }
            } else if let Some(original) = plan.original.as_deref() {
                let _ = restore_hook_bytes(&plan.target, original);
            } else {
                let _ = fs::remove_file(&plan.target);
            }
        }
        return Err(error.context("hook installation rolled back"));
    }

    Ok(plans
        .into_iter()
        .filter_map(|plan| plan.moved_foreign.then_some(plan.foreign_backup))
        .flatten()
        .collect())
}

/// Install the global hook set. Kept as a named wrapper because the global
/// setup path reports the preserved files separately from local setup.
fn install_global_hooks(dir: &Path) -> Result<Vec<PathBuf>> {
    install_hook_set(dir)
}

fn hook_dir(mode: HookMode, repo: Option<&Path>) -> Result<PathBuf> {
    match mode {
        HookMode::Global => {
            let home = dirs::home_dir().context("could not determine home directory")?;
            Ok(home.join(".config/git/hooks"))
        }
        HookMode::Local => {
            let repo_path = repo.context("--local requires a repo path")?;
            let git_dir = resolved_git_dir(repo_path).ok_or_else(|| {
                anyhow::anyhow!(
                    "not a git repo: {} (no valid .git marker)",
                    repo_path.display()
                )
            })?;
            Ok(git_dir.join("hooks"))
        }
    }
}

const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# dracon-warden-managed-hook-v1
# Dracon Warden — pre-commit hook
# Validates that the warden encryption filter is configured before committing.
# Installed by: dracon-warden setup-hooks

REPO=$(git rev-parse --show-toplevel)

# FIXED 2026-07-26 (audit H-10), two prongs:
# (1) Global core.hooksPath shadows .git/hooks for every repo, which
#     silently disabled husky/pre-commit-framework hooks fleet-wide.
#     Chain to the repository's common-gitdir hook when one exists and is NOT a
#     warden-seeded copy (the header guard prevents infinite
#     recursion through install_hooks_for_repo's seed).
GIT_COMMON_DIR=$(git rev-parse --git-common-dir 2>/dev/null) || exit 1
case "$GIT_COMMON_DIR" in
    /*) ;;
    *) GIT_COMMON_DIR="$REPO/$GIT_COMMON_DIR" ;;
esac
LOCAL_HOOK="$GIT_COMMON_DIR/hooks/pre-commit"
# ADDED 2026-09-19 (v0.113.13): never chain a PRE-MARKER legacy
# warden hook ("Installed by: dracon-warden setup-hooks" without
# the v1 marker). That generation probes `filter.dracon.clean`
# WITHOUT --local, so the machine-global key false-marks EVERY
# repo as managed and blocks the commit; harden replaces legacy
# hooks with the current template on its next pass, and this
# wrapper's own checks below enforce the same policy meanwhile.
# (User hooks — anything without warden's signature — still chain.)
LOCAL_IS_WARDEN=0
grep -qFx '# dracon-warden-managed-hook-v1' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
grep -q 'Installed by: dracon-warden setup-hooks' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
if [ -x "$LOCAL_HOOK" ] && [ "$LOCAL_IS_WARDEN" -eq 0 ]; then
    "$LOCAL_HOOK" "$@" || exit $?
fi

# A previous global hook with the same name is preserved beside this wrapper
# and chained here. Warden never silently discards machine-global policy.
DRACON_FOREIGN_HOOK=__DRACON_FOREIGN_HOOK__
if [ -n "$DRACON_FOREIGN_HOOK" ] && [ -x "$DRACON_FOREIGN_HOOK" ]; then
    "$DRACON_FOREIGN_HOOK" "$@" || exit $?
fi

# Optional storage guard, after both user-hook chains have run. A repo ID
# alone is only an inspection binding; it does not activate storage. Explicit
# guard/driver markers require the pinned operator executable and version-1
# bindings. No PATH fallback, eval, network request or encryption occurs here.
STORAGE_VERSION=$(git -C "$REPO" config --local --get dracon.storageGuardVersion 2>/dev/null || true)
STORAGE_REQUIRED=0
git -C "$REPO" config --local --get dracon.storageGuardVersion >/dev/null 2>&1 && STORAGE_REQUIRED=1
for STORAGE_KEY in filter.dracon-storage.clean filter.dracon-storage.process filter.dracon-storage.required; do
    git -C "$REPO" config --local --get "$STORAGE_KEY" >/dev/null 2>&1 && STORAGE_REQUIRED=1
done
if [ "$STORAGE_REQUIRED" -eq 1 ]; then
    if [ "$STORAGE_VERSION" != 1 ]; then
        echo "pre-commit: storage requires explicit version-1 guard bindings." >&2
        exit 1
    fi
    STORAGE_SYNC=$(git -C "$REPO" config --local --get dracon.storageSyncExecutable 2>/dev/null || true)
    case "$STORAGE_SYNC" in
        /*) ;;
        *) echo "pre-commit: absolute storage guard executable required." >&2; exit 1 ;;
    esac
    if [ ! -f "$STORAGE_SYNC" ] || [ ! -x "$STORAGE_SYNC" ]; then
        echo "pre-commit: configured storage guard executable unavailable." >&2
        exit 1
    fi
    "$STORAGE_SYNC" storage verify-configured-index --repo "$REPO" || exit $?
fi

# (2) The pre-fix hook exited 1 in EVERY repo lacking filter=dracon —
#     hard-blocking commits in third-party clones and scratch repos
#     machine-wide. Only enforce on warden-MANAGED repos (any warden
#     marker present); a repo with NO markers is not warden's
#     business. Drift (some markers present, some missing) still
#     blocks below.
MANAGED=0
# NOTE: the filter.dracon.* check MUST be --local — the operator's
# GLOBAL ~/.gitconfig also carries filter.dracon.clean, so a plain
# `git config` succeeds in every repo on the machine and the
# non-managed early-exit below would be dead code (verified
# 2026-07-26: scratch repo blocked without --local).
git -C "$REPO" config --local filter.dracon.process >/dev/null 2>&1 && MANAGED=1
git -C "$REPO" config --local filter.dracon.clean >/dev/null 2>&1 && MANAGED=1
# FIXED 2026-10-03 (audit R3-M3): strip `#` comments first — a
# commented-out filter line must not mark the repo managed.
grep -v '^[[:space:]]*#' "$REPO/.gitattributes" 2>/dev/null | grep -q "filter=dracon" && MANAGED=1
[ -d "$REPO/.dracon" ] && MANAGED=1
[ "$MANAGED" -eq 0 ] && exit 0

# ----- (1.5) machine-local files must not be TRACKED (2026-09-28) --------
# Ignore rules cannot express this rule, because the failure mode IS the
# tracked file: `.gitignore` only governs UNTRACKED paths, so a path that was
# tracked when the ignore rule landed keeps being committed forever. The
# fleet hit this repeatedly:
#   * `.pi-glla/active.jsonl`  - the 2026-08-16 ignore rule was inert; 1027
#     revisions of a 4.3 MB log in one repo, and 9.83 GiB of new blobs in
#     pi-goal-list-loop-audit in 30 days (97.5% of that repo's growth).
#   * `.pi/chrome-screenshots/` + `audit-*/screenshots/` - same inert-ignore
#     class; 2.50 GiB in hellhunter, the exact recurrence AGENTS.md predicted
#     when it recorded deathrun's 2.85 GiB frame-dump bloat.
#   * `findings.baseline.md` - the audit guard's baseline COPY of the ledger,
#     byte-identical to findings.md (measured 2026-09-28: both 2,044,799
#     bytes) and re-committed on every audit run, 42 times in 24h in
#     hellhunter. The guard needs the file on DISK; it never needed it in git.
#   * `scratch/`, `screenshots/`, `audit-evidence/` - regenerable working
#     material, not deliverables. AGENTS.md is explicit that the .md REPORTS
#     are the deliverable and the captured frames are regeneratable on
#     demand; those three trees were 417 MB on disk in hellhunter alone and
#     regrew 0.59 GiB in 24h.
#
# Placement: after the MANAGED gate, so it only applies to warden-managed
# repos. Both the platform's `.githooks/pre-commit` and the shared nested
# hook (`web/scripts/git-hooks/pre-commit-shared.sh`) chain to THIS hook
# explicitly, because their own `core.hooksPath` shadows it - so this one
# block covers every repo on the machine.
#
# GRANDFATHERING, deliberately: the durable GLLA record surface stays
# tracked - `audit-loop/**/*.md` (the curated ledger, its baseline is
# exempt above, and dated scout reports), `archive/`, `reviews/`, and
# `ledger-segments/`. Only unambiguous machine-local state and regenerable
# frames are refused. Fix a refusal once, forward-only, with
# `git rm --cached -- <path>`; history is never rewritten here.
machine_local_violations=0
staged_names="$(git -C "$REPO" diff --cached --name-only --diff-filter=ACMR 2>/dev/null || true)"
if [ -n "$staged_names" ]; then
    while IFS= read -r staged_path; do
        [ -n "$staged_path" ] || continue
        case "$staged_path" in
            # Durable record surface - intentionally tracked.
            .pi-glla/audit-loop/*.md|*/.pi-glla/audit-loop/*.md|\
            .pi-glla/archive/*|.pi-glla/archive|*/.pi-glla/archive/*|\
            .pi-glla/reviews/*|.pi-glla/reviews|*/.pi-glla/reviews/*|\
            .pi-glla/ledger-segments/*|.pi-glla/ledger-segments|*/.pi-glla/ledger-segments/*) continue ;;
            # Machine-local loop state, regeneratable frame dumps, the
            # ledger's baseline copy, and the loop scratch/evidence trees.
            .pi-glla/active.jsonl|*/.pi-glla/active.jsonl|\
            .pi-glla/audits.jsonl|*/.pi-glla/audits.jsonl|\
            .pi-glla/owner.json|*/.pi-glla/owner.json|\
            .pi-glla/session-owner.json|*/.pi-glla/session-owner.json|\
            .pi-glla/update-check.json|*/.pi-glla/update-check.json|\
            .pi-glla/pending-approval-renders.json|*/.pi-glla/pending-approval-renders.json|\
            .pi-glla/compactor-jobs/*|.pi-glla/compactor-jobs|*/.pi-glla/compactor-jobs/*|\
            .pi-glla/scratch/*|.pi-glla/scratch|*/.pi-glla/scratch/*|\
            .pi/chrome-screenshots/*|.pi/chrome-screenshots|*/.pi/chrome-screenshots/*|\
            audit-*/screenshots/*|*/audit-*/screenshots/*|\
            .pi-glla/audit-loop/findings.baseline.md|*/.pi-glla/audit-loop/findings.baseline.md|\
            scratch/*|scratch|*/scratch/*|\
            screenshots/*|screenshots|*/screenshots/*|\
            audit-evidence/*|audit-evidence|*/audit-evidence/*)
                echo "machine-local file is staged: $staged_path" >&2
                echo "   This is loop bookkeeping, a regeneratable frame dump, or" >&2
                echo "   working material - not repository content. Warden's ignore" >&2
                echo "   rule never took effect because the file was already tracked." >&2
                echo "   Fix once, forward-only:" >&2
                echo "     git rm --cached -- '$staged_path'" >&2
                echo "   History is not rewritten here; only future commits stop." >&2
                machine_local_violations=$((machine_local_violations + 1))
                ;;
        esac
    done <<EOF
$staged_names
EOF
fi
if [ "$machine_local_violations" -gt 0 ]; then
    echo "pre-commit: $machine_local_violations machine-local file(s) blocked." >&2
    exit 1
fi

# Check .gitattributes has filter=dracon patterns
# FIXED 2026-10-03 (audit R3-M3): ignore `#` comments — only an ACTIVE
# filter line satisfies this gate (a commented-out pattern is not a
# filter, and git would not apply it).
if ! grep -v '^[[:space:]]*#' "$REPO/.gitattributes" 2>/dev/null | grep -q "filter=dracon"; then
    echo "❌ Warden filter missing from .gitattributes."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi

# Check git config has a dracon filter driver set — MUST be --local:
# the operator's GLOBAL ~/.gitconfig also carries filter.dracon.*
# (this machine included), so a plain `git config` read succeeds in
# EVERY repo and the check would be dead code — exactly the drift
# class the MANAGED probe above guards against. `once` writes the
# keys locally (ensure_repo_filter_config), so validate the same
# scope. FIXED 2026-08-11 (audit LOW). CHANGED 2026-09-19
# (v0.113.13): the process driver replaces per-file clean/smudge —
# accept either key (legacy clean during migration).
if ! git -C "$REPO" config --local filter.dracon.process >/dev/null 2>&1 && ! git -C "$REPO" config --local filter.dracon.clean >/dev/null 2>&1; then
    echo "❌ Warden filter not configured in local git config."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi

# FIXED 2026-10-03 (audit R4-W-01): required=true must be set —
# without it, git treats a filter error as a no-op passthrough
# instead of aborting, so an oversize refusal or encrypt error
# would commit the file UNENCRYPTED with exit 0.
if ! git -C "$REPO" config --local filter.dracon.required 2>/dev/null | grep -qx "true"; then
    echo "❌ Warden filter.dracon.required is not true in local git config."
    echo "   Without it, filter errors pass files through UNENCRYPTED."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi

# FIXED 2026-10-03 (audit R4-W-03): the diff/merge driver keys must be
# set — without them git falls back to the text driver and diffs/merges
# of encrypted files operate on CIPHERTEXT (an undecryptable conflict
# output). `once` writes all five keys locally
# (ensure_repo_filter_config); only presence is checked here — a MISSING
# key silently degrades, while a changed value either fails loudly in
# git or is operator intent. (merge.dracon.name is display-only and
# deliberately unchecked.)
if ! git -C "$REPO" config --local diff.dracon.textconv >/dev/null 2>&1; then
    echo "❌ Warden diff.dracon.textconv missing from local git config."
    echo "   Without it, diffs of encrypted files show CIPHERTEXT."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi
if ! git -C "$REPO" config --local merge.dracon.driver >/dev/null 2>&1; then
    echo "❌ Warden merge.dracon.driver missing from local git config."
    echo "   Without it, merges of encrypted files operate on CIPHERTEXT."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi

# Check filter binary is on PATH
if ! command -v dracon-warden >/dev/null 2>&1; then
    echo "❌ dracon-warden binary not found on PATH."
    echo "   Install it or add to PATH."
    exit 1
fi
"#;

const PRE_PUSH_HOOK: &str = r##"#!/bin/sh
# dracon-warden-managed-hook-v1
# Dracon Warden — pre-push hook
# Defense-in-depth: scans push for plaintext secrets.
# Catches --no-verify bypass of the pre-commit hook — but is itself
# bypassable (git push --no-verify, core.hooksPath, clones without
# setup-hooks), so this is accident-catching defense-in-depth, not
# enforcement. There is no server-side scan (audit R4-W-02).
# Installed by: dracon-warden setup-hooks
#
# Plaintext-sibling escape hatch: a file with a `<path>.plaintext` sibling
# is treated as intentionally plaintext. Such files are excluded from the
# scan (silent allow). See docs/design/warden-plaintext-sibling.md.
#
# CHANGED 2026-07-21 (v0.112.32, audit M32/F4.6): filenames are
# handled NUL-delimited. The previous
# `for f in $(git diff --name-only "$RANGE")` word-split on
# whitespace: a file named `prod secrets.env` split into `prod` and
# `secrets.env`, neither fragment was scanned, and a plaintext
# secret in a space-containing filename pushed clean. We now iterate
# `git diff --name-only -z` (via `tr '\0' '\n'` + `IFS= read -r`,
# which preserves spaces; the residual newline-in-filename edge is
# accepted as absurd) and pass the accepted files to the second diff
# as arguments via `xargs -0` (no word-splitting, no glob expansion
# of metacharacters; `-r` = --no-run-if-empty on GNU xargs).
# `--pathspec-from-file` was tried first but `git diff` does NOT
# support it (usage error, exit 129 — verified against git 2.51.2).

# Accumulator for the per-ref accepted file list (NUL-delimited).
SCAN_FILES_NUL=$(mktemp)
# Accumulator for added-file paths (newline-delimited) — used by the
# added-blob scan below.
ADDED_FILES=$(mktemp)
# Lazily-populated remote object list for the blob-novelty check
# (R3-L21; assigned inside `remote_blob_is_published`). The EXIT
# trap expands at exit time, so the late assignment is covered.
REMOTE_OBJECTS=""
trap 'rm -f "$SCAN_FILES_NUL" "$ADDED_FILES" "$REFS_FILE" "$REMOTE_OBJECTS"' EXIT

# Secret shapes scanned against added diff lines AND added file blobs
# (see the added-blob scan below). Kept case-sensitive deliberately:
# the warden's own test fixtures contain uppercase `PASSWORD=` forms,
# and the case-insensitive primary gate (SecretScanner) covers
# protected paths. Unquoted `secret=`/`api_key=` values are NOT in the
# hook regex: the warden's own fixture corpus uses exactly those
# shapes (`secret=hunter2` in plaintext_sibling_test,
# `ibm_cloud_api_key = ...` in comprehensive_test), which would
# self-block every future warden push.
#
# FIXED 2026-08-11 (audit MEDIUM): added the unquoted-password
# alternative `password\s*=\s*[^[:space:]"]{6,}`. The pre-fix regex
# required a quote after `=`, so a bare `password = abc` in an added
# line pushed clean.
# FIXED 2026-08-12 (audit LOW follow-up, auditor-verified): the quoted
# branches were written `["''][^"'']` inside a shell single-quoted
# string — POSIX shell collapses each `''` pair to the empty string,
# so the EFFECTIVE regex was `["][^"]+`: single-quoted values
# pushed clean. Use the `'\''` idiom so a real `'` survives shell
# parsing (effective: `["'][^"']+`, verified with sh -x).
# NOTE (extended 2026-08-12, second audit round): this comment must
# contain NO shape the regex can match — not a quoted or unquoted
# password/secret/api-key assignment (quoted value, or a bare
# 6+-character value), not an access-key shape, not a BEGIN PRIVATE
# KEY line, not any provider-token shape below — the hook would
# self-match its own text if the script is ever committed (the
# 2026-08-12 test-harness vacuity). Provider names are spelled out
# (no prefix literals, no bodies) for exactly this reason.
#
# FIXED 2026-10-02 (audit M10): the token-shape alternatives render
# from the single source (`SecretScanner::hook_token_shapes_ere`), the
# POSIX-ERE transliteration of every Tier-1 provider-token shape. The
# hand-written regex tripped only on the access-key shape plus PEM and
# assignments, so all other Tier-1 shapes pushed clean when the filter
# was bypassed. The checked-in line below is that render; the
# freshness test prints the exact line to paste when the source
# changes. Coverage: access-key ID, PEM header, the four assignment
# branches, plus one alternative per Tier-1 provider token (github
# classic/ PAT shapes, gitlab personal/runner, stripe live/test/
# restricted/webhook, slack token/bot/webhook, twilio key/SID,
# sendgrid, mailchimp, npm, openai incl. proj/svcacct plus openrouter,
# groq, resend, gcp/google client secret, digitalocean, shopify token/
# secret, square access/oauth, vault, mws). Private-key bodies stay
# header-only: the hook is line-oriented and cannot span lines.
SECRET_RE='(-----BEGIN [A-Z]+ PRIVATE KEY|password\s*=\s*["'\''][^"'\'']+|secret\s*=\s*["'\''][^"'\'']+|api_key\s*=\s*["'\''][^"'\'']+|password\s*=\s*[^[:space:]"'']{6,}|A{1}KIA[A-Z0-9]{16}|ghp_[A-Za-z0-9_]{36,255}|gho_[A-Za-z0-9_]{36,255}|ghu_[A-Za-z0-9_]{36,255}|ghs_[A-Za-z0-9_]{36,255}|ghr_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{36,255}|glpat-[A-Za-z0-9_-]{20,}|GR1348941[A-Za-z0-9_-]{20,}|sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|rk_test_[0-9a-zA-Z]{24,}|whsec_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}|xoxb-[A-Za-z0-9]{24,68}|SK[a-f0-9]{32}|AC[a-f0-9]{32}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|[0-9a-f]{32}-us[0-9]{1,2}|npm_[A-Za-z0-9]{36}|sk-((proj|svcacct)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})|sk-or-v1-[0-9a-f]{64}|gsk_[A-Za-z0-9]{52}|re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}|AIza[0-9A-Za-z_-]{35}|AIza[0-9A-Za-z_-]{35}|GOCSPX-[A-Za-z0-9_-]{28,}|dop_v1_[a-f0-9]{64}|shpat_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}|sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}|hvs\.[A-Za-z0-9_-]{24,}|amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|https://hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9+/]{43,56})'

# ── Repo-local hook chaining (FIXED 2026-08-11, audit MEDIUM — H-10
#    follow-up) ──────────────────────────────────────────────────────
# Global core.hooksPath shadows .git/hooks for every repo; the H-10
# fix chained repository-local hooks for pre-commit only, leaving THIS hook
# silently shadowing any repository-local pre-push. Chain first, like
# pre-commit: git feeds the push refs on stdin exactly once, so
# buffer them, hand the buffer to the local hook, and reuse it for
# warden's own scan below — a local hook that consumes stdin cannot
# starve the scan. The scan keeps its main-shell form
# (`done < "$REFS_FILE"`, not a pipe): inside a piped subshell `exit
# 1` would exit only the subshell and the hook would return 0,
# silently defeating the guard. The "Dracon Warden" grep skips our
# own seeded copies (no recursion). DRACON_ALLOW_REWRITE does NOT
# gate this: that bypass is scoped to the history guard inside the
# loop; a repo-local hook failure must abort the push regardless.
REFS_FILE=$(mktemp)
cat > "$REFS_FILE"

# Preserve and invoke any pre-existing foreign global pre-push hook. The ref
# stream is buffered so both hooks receive identical Git input.
DRACON_FOREIGN_HOOK=__DRACON_FOREIGN_HOOK__
if [ -n "$DRACON_FOREIGN_HOOK" ] && [ -x "$DRACON_FOREIGN_HOOK" ]; then
    "$DRACON_FOREIGN_HOOK" "$@" < "$REFS_FILE" || exit $?
fi

REPO=$(git rev-parse --show-toplevel)
GIT_COMMON_DIR=$(git rev-parse --git-common-dir 2>/dev/null) || exit 1
case "$GIT_COMMON_DIR" in
    /*) ;;
    *) GIT_COMMON_DIR="$REPO/$GIT_COMMON_DIR" ;;
esac
LOCAL_HOOK="$GIT_COMMON_DIR/hooks/pre-push"
# ADDED 2026-09-19 (v0.113.13): same legacy-warden skip as the
# pre-commit wrapper — a pre-marker local hook lacks the tag-push
# corroboration fix and re-scans history from the empty tree,
# flagging grandfathered fixtures on every tag push (observed:
# blocked the v0.113.13 tag push). Harden replaces it on its next
# pass; this wrapper's own scan below already carries the fix.
LOCAL_IS_WARDEN=0
grep -qFx '# dracon-warden-managed-hook-v1' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
grep -q 'Installed by: dracon-warden setup-hooks' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
if [ -x "$LOCAL_HOOK" ] && [ "$LOCAL_IS_WARDEN" -eq 0 ]; then
    "$LOCAL_HOOK" "$@" < "$REFS_FILE" || exit $?
fi

# Blob-novelty helper (R3-L21): is $1 already on a remote? The remote
# object list is enumerated ONCE per push into $REMOTE_OBJECTS, lazily
# on first use (most pushes never match, so eager enumeration would
# tax every push). Fail closed: enumeration failure (or an empty
# list) answers "not published" and the caller blocks.
remote_blob_is_published() {
    if [ -z "$REMOTE_OBJECTS" ]; then
        REMOTE_OBJECTS=$(mktemp) || return 1
        if ! git rev-list --objects --remotes 2>/dev/null > "$REMOTE_OBJECTS"; then
            rm -f "$REMOTE_OBJECTS"
            REMOTE_OBJECTS=""
            return 1
        fi
    fi
    grep -q "^$1" "$REMOTE_OBJECTS"
}

# Read push info from stdin (remote URL and branch refs)
while read local_ref local_sha remote_ref remote_sha; do
    # ── History-rewrite guard (ADDED 2026-07-25, v0.113.0) ──────
    # A non-fast-forward push means rewritten history (amend/rebase
    # of an already-pushed commit). The 2026-07-25 incident showed
    # agent loops doing exactly this and racing dracon-sync's
    # auto-push, producing permanent divergent-branch churn. GitLab
    # branch protection covers gitlab; this hook is the
    # forge-INVARIANT enforcement (GitHub free-tier private repos
    # cannot be protected server-side). Amending UNPUSHED commits
    # still pushes fine (fast-forward), so normal WIP flow is
    # unaffected. Escape hatch: DRACON_ALLOW_REWRITE=1.
    if [ -z "$DRACON_ALLOW_REWRITE" ]; then
        if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
            echo "❌ dracon-warden: refusing to delete $remote_ref (history guard)." >&2
            echo "   Bypass: DRACON_ALLOW_REWRITE=1" >&2
            exit 1
        fi
        if [ "$remote_sha" != "0000000000000000000000000000000000000000" ]; then
            if ! git merge-base --is-ancestor "$remote_sha" "$local_sha" 2>/dev/null; then
                echo "❌ dracon-warden: refusing non-fast-forward push to $remote_ref (history rewrite)." >&2
                echo "   Merge instead: git pull --no-rebase" >&2
                echo "   Bypass: DRACON_ALLOW_REWRITE=1" >&2
                exit 1
            fi
        fi
    fi

    # Skip branch deletions (only reachable via the escape hatch)
    if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
        continue
    fi

    # Check each newly published commit, not only the endpoint trees: an
    # introduced-then-deleted secret remains reachable in the pushed history.
    # A new tag accompanying a branch to the same target reuses that branch's
    # scan, rather than rechecking grandfathered content from older commits.
    if [ "$remote_sha" = "0000000000000000000000000000000000000000" ] && \
        [ "${local_ref#refs/tags/}" != "$local_ref" ] && \
        awk -v sha="$local_sha" \
            '$1 ~ /^refs\/heads\// && $2 == sha { found=1 } END { exit(found ? 0 : 1) }' \
            "$REFS_FILE"; then
        continue
    fi
    if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
        NEW_COMMITS=$(git rev-list --reverse "$local_sha" --not --remotes 2>/dev/null) || exit 1
    else
        NEW_COMMITS=$(git rev-list --reverse "$local_sha" --not "$remote_sha" 2>/dev/null) || exit 1
    fi
    for scan_commit in $NEW_COMMITS; do
    # Collect non-hatched files (skip files with a `.plaintext` sibling)
    : > "$SCAN_FILES_NUL"
    git diff-tree --root -m -r --no-commit-id --name-only -z "$scan_commit" 2>/dev/null | tr '\0' '\n' | while IFS= read -r f; do
        if [ -f "$f.plaintext" ]; then
            # Hatched file — silently allow
            continue
        fi
        printf '%s\0' "$f" >> "$SCAN_FILES_NUL"
    done

    # Nothing left to scan — push is safe
    if [ ! -s "$SCAN_FILES_NUL" ]; then
        continue
    fi

    # Scan only newly added diff lines. Deletions of old secret-shaped fixtures
    # are safe, while additions still trip the defense-in-depth guard.
    # FIXED 2026-10-03 (audit L10): two precision gaps closed —
    #  * `-M100%`: exact renames surface as R (no content lines) instead
    #    of a D+A pair whose A side re-tripped on grandfathered content.
    #  * `--diff-filter=a`: ADDED files are excluded here — the full-blob
    #    loop below (with its blob-novelty check) judges them once, with
    #    binary safety the diff-line scan lacks.
    DIFF=$(xargs -0 -r git diff-tree --root -m -r --no-commit-id -M100% --diff-filter=a -p --unified=0 "$scan_commit" -- < "$SCAN_FILES_NUL" 2>/dev/null | grep -E '^\+[^+]' || true)
    # CHANGED 2026-07-26 (v0.113.1, audit WARDEN-M2): `\x27` is NOT a
    # hex escape in GNU grep ERE (verified grep 3.12: "stray \ before
    # x" — the class became ["x27], matching literal x/2/7 instead of
    # a single quote), so single-quoted secrets escaped the scan. Use
    # the shell `'`\\`''` idiom to embed a literal single quote.
    if echo "$DIFF" | grep -qE "$SECRET_RE"; then
        echo "⚠️  Possible plaintext secrets detected in push." >&2
        echo "   The warden filter may have been bypassed." >&2
        echo "   Run: dracon-warden once $(git rev-parse --show-toplevel)" >&2
        exit 1
    fi

    # ADDED 2026-08-11 (audit MEDIUM): `git diff --unified=0` emits NO
    # `+` lines for binary files (only "Binary files ... differ"), so
    # binary additions were never scanned. Scan the FULL blob of every
    # ADDED file with `grep -a` (treats binary data as text). For a new
    # file the added content IS the whole file, so this is equivalent
    # to the diff-line scan for text additions and covers binaries for
    # the first time. Modified text files keep the added-lines scan;
    # modified binaries compare secret matches with parent blobs below
    # so unrelated edits do not re-trip on grandfathered matches.
    git diff-tree --root -m -r --no-commit-id -M100% --name-only --diff-filter=A -z "$scan_commit" 2>/dev/null | tr '\0' '\n' > "$ADDED_FILES"
    while IFS= read -r af; do
        # Skip files hatched via a `.plaintext` sibling, matching the
        # text scan above.
        [ -f "$af.plaintext" ] && continue
        if git cat-file blob "$scan_commit:$af" 2>/dev/null | grep -aqE "$SECRET_RE"; then
            # FIXED 2026-10-03 (audit L10): blob-novelty check — a blob
            # already present on a remote is grandfathered, not a new
            # leak (republished content). Pure renames never reach here
            # (`-M100%` above lists them as R, not A). Fail closed: any
            # lookup failure falls through to the block below.
            # CHANGED 2026-10-03 (audit R3-L21): enumerate remote
            # objects ONCE per push (lazily, inside the helper) instead
            # of one O(history) `rev-list` per added file.
            BLOB_SHA=$(git rev-parse "$scan_commit:$af" 2>/dev/null || true)
            if [ -n "$BLOB_SHA" ] && remote_blob_is_published "$BLOB_SHA"; then
                continue
            fi
            echo "⚠️  Possible plaintext secrets detected in added file $af (binary-safe scan)." >&2
            echo "   The warden filter may have been bypassed." >&2
            echo "   Run: dracon-warden once $(git rev-parse --show-toplevel)" >&2
            exit 1
        fi
    done < "$ADDED_FILES"

    # Binary modifications have no added text lines. Reject newly introduced
    # secret shapes, while allowing exact matches inherited from parent blobs.
    git diff-tree --root -m -r --no-commit-id --name-only --diff-filter=M -z "$scan_commit" 2>/dev/null | tr '\0' '\n' > "$ADDED_FILES"
    PARENTS=$(git show -s --format=%P "$scan_commit") || exit 1
    while IFS= read -r bf; do
        [ -f "$bf.plaintext" ] && continue
        if ! git diff-tree --root -m -r --no-commit-id --numstat "$scan_commit" -- "$bf" |
            awk '$1 == "-" && $2 == "-" { binary=1 } END { exit(binary ? 0 : 1) }'; then
            continue
        fi
        OLD_MATCHES=$(for parent in $PARENTS; do
            git cat-file blob "$parent:$bf" 2>/dev/null | grep -aoE "$SECRET_RE" || true
        done)
        NEW_MATCHES=$(git cat-file blob "$scan_commit:$bf" 2>/dev/null | grep -aoE "$SECRET_RE" || true)
        printf '%s\n' "$NEW_MATCHES" | while IFS= read -r candidate; do
            [ -z "$candidate" ] && continue
            if ! printf '%s\n' "$OLD_MATCHES" | grep -qFx -- "$candidate"; then
                echo "⚠️  Possible plaintext secrets detected in changed binary file." >&2
                exit 1
            fi
        done || exit 1
    done < "$ADDED_FILES"

    done

    # ADDED 2026-07-21 (v0.112.33, audit H2/F0.1 follow-up): reject
    # pushes containing commits authored by known TEST identities.
    # The F0.1 incident showed a test writing `user.email = test@test`
    # into a LIVE repo's config (via a positional `git config` arg),
    # after which the daemon committed with the poisoned identity and
    # the poisoned commit landed on all mirrors. Only the PUSHED
    # range is scanned, so historical commits are unaffected.
    #
    # CHANGED 2026-07-27 (v0.113.2): for TAG pushes (`remote_sha = 0`,
    # i.e. the ref is brand new) the old `git log empty..tag-sha` range
    # covered the ENTIRE repo history reachable from the tag object,
    # not just the NEW commits — a test-identity commit reachable only
    # via a non-first-parent merge of a feature branch then blocked the
    # tag push even though the first-parent history is clean. Now the
    # scan distinguishes:
    #
    #   * existing-ref update (branch push, remote_sha != 0):
    #     `git rev-list "$LOCAL_SHA" --not "$REMOTE_SHA"` — only the
    #     new commits being added to the branch tip.
    #
    #   * new-ref push (tag or new branch, remote_sha == 0):
    #     `git rev-list "$LOCAL_SHA" --not --remotes` — only commits
    #     reachable from the tag object that are NOT already on ANY
    #     remote-tracking branch. Anything already published (and
    #     therefore already accepted by a prior scan) is excluded.
    #
    # This is the correct F0.1 defense surface: only NEWLY-PUBLISHED
    # commits need scrutiny. A test-identity commit on a side branch
    # merge that was already pushed to all mirrors in a prior commit
    # cannot be retroactively un-published, so re-scanning it on a
    # later tag push is wasted and prone to false positives. Defense
    # in depth is preserved for the new push itself.
    if [ -n "$NEW_COMMITS" ]; then
        BAD_AUTHORS=$(printf '%s\n' "$NEW_COMMITS" | xargs -I{} git log -1 --format='%ae%n%ce' {} 2>/dev/null | sort -u | grep -Eix '^test@test$|^test@test\.com$|^test@example\.com$' || true)
        if [ -n "$BAD_AUTHORS" ]; then
            echo "⚠️  Push contains commits authored by a test identity:" >&2
            echo "$BAD_AUTHORS" | sed 's/^/   /' >&2
            echo "   Amend the author identity before pushing (git commit --amend --reset-author)." >&2
            exit 1
        fi
    fi
done < "$REFS_FILE"
"##;

/// ADDED 2026-07-25 (v0.113.0): refuse rebases that would rewrite
/// commits already published to any remote-tracking branch. The
/// pre-push guard blocks the PUSH side; this blocks the rewrite at
/// the source, before the branch diverges. Rebasing unpushed local
/// work (including `git pull --rebase` of commits not yet pushed)
/// is unaffected. Escape hatch: DRACON_ALLOW_REWRITE=1.
///
/// CAVEAT 2026-10-03 (audit L11): the check consults LOCAL
/// remote-tracking refs — published-but-unfetched commits escape when
/// refs are stale. The hook warns (never blocks) when a remote exists
/// and FETCH_HEAD is missing or older than 24h; daemon-managed repos
/// stay fresh via auto-fetch.
const PRE_REBASE_HOOK: &str = r#"#!/bin/sh
# dracon-warden-managed-hook-v1
# Dracon Warden — pre-rebase hook
# Refuse rebases that rewrite already-published history.
# Installed by: dracon-warden setup-hooks
# Bypass deliberately: DRACON_ALLOW_REWRITE=1 git rebase ...
if [ -n "$DRACON_ALLOW_REWRITE" ]; then exit 0; fi

# FIXED 2026-08-11 (audit MEDIUM — H-10 follow-up): global
# core.hooksPath shadows .git/hooks for every repo; pre-commit got
# chaining in H-10 but pre-push and pre-rebase silently shadowed any
# repository-local hook. Chain the common-gitdir pre-rebase when one exists
# (the "Dracon Warden" grep skips our own seeded copies — no
# recursion). Placed after the bypass so DRACON_ALLOW_REWRITE=1
# disables hook interference entirely, matching the hook's
# documented escape hatch.
REPO=$(git rev-parse --show-toplevel)
GIT_COMMON_DIR=$(git rev-parse --git-common-dir 2>/dev/null) || exit 1
case "$GIT_COMMON_DIR" in
    /*) ;;
    *) GIT_COMMON_DIR="$REPO/$GIT_COMMON_DIR" ;;
esac
LOCAL_HOOK="$GIT_COMMON_DIR/hooks/pre-rebase"
# ADDED 2026-09-19 (v0.113.13): same legacy-warden skip as the
# pre-commit wrapper — the pre-marker generation must never run
# via the global chain (see comment there).
LOCAL_IS_WARDEN=0
grep -qFx '# dracon-warden-managed-hook-v1' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
grep -q 'Installed by: dracon-warden setup-hooks' "$LOCAL_HOOK" 2>/dev/null && LOCAL_IS_WARDEN=1
if [ -x "$LOCAL_HOOK" ] && [ "$LOCAL_IS_WARDEN" -eq 0 ]; then
    "$LOCAL_HOOK" "$@" || exit $?
fi

# Preserve and invoke any pre-existing foreign global pre-rebase hook.
DRACON_FOREIGN_HOOK=__DRACON_FOREIGN_HOOK__
if [ -n "$DRACON_FOREIGN_HOOK" ] && [ -x "$DRACON_FOREIGN_HOOK" ]; then
    "$DRACON_FOREIGN_HOOK" "$@" || exit $?
fi

upstream="$1"
[ -z "$upstream" ] && exit 0

# FIXED 2026-07-26 (audit H-11 + M-15):
# - Range tip is $2 when given (`git rebase <upstream> <branch>`
#   rebases $2, not HEAD — the pre-fix HEAD-only range was EMPTY in
#   that form, silently passing while published $2 commits were
#   rewritten).
# - Remote containment is ancestor-closed: if the OLDEST commit in
#   the range is not contained in any remote-tracking branch, no
#   newer commit can be. The pre-fix `head -100` checked the NEWEST
#   100 commits (rev-list is newest-first), letting published commits
#   deeper than 100 escape — exactly the incident class this guard
#   exists to prevent. Check only the boundary commit; this also
#   removes the up-to-100 `git branch -r` subprocess spawns.
tip="${2:-HEAD}"
oldest=$(git rev-list "$upstream".."$tip" 2>/dev/null | tail -1)
[ -z "$oldest" ] && exit 0

# DOCUMENTED 2026-10-03 (audit L11): containment is checked against
# LOCAL remote-tracking refs. Published-but-unfetched commits escape
# when refs are stale. A fetch inside the hook was rejected (breaks
# offline rebases, slows every rebase); warn instead. Daemon-managed
# repos auto-fetch constantly so their refs stay fresh; manual clones
# should `git fetch` first. Warning-only: never blocks the rebase.
if git remote 2>/dev/null | grep -q .; then
    FETCH_HEAD_FILE="$GIT_COMMON_DIR/FETCH_HEAD"
    if [ ! -f "$FETCH_HEAD_FILE" ] || [ -n "$(find "$FETCH_HEAD_FILE" -mmin +1440 2>/dev/null)" ]; then
        echo "⚠️  dracon-warden: remote-tracking refs may be stale (no fetch in 24h); the published-commit check may miss recently pushed commits." >&2
        echo "   Run: git fetch" >&2
    fi
fi

if [ -n "$(git branch -r --contains "$oldest" 2>/dev/null)" ]; then
    echo "❌ dracon-warden: refusing rebase — $oldest is already published on a remote." >&2
    echo "   Rebasing it would rewrite pushed history and diverge the fleet mirrors." >&2
    echo "   Merge instead: git pull --no-rebase" >&2
    echo "   Bypass: DRACON_ALLOW_REWRITE=1" >&2
    exit 1
fi
exit 0
"#;

fn run_setup_hooks(mode: HookMode, repo: Option<&Path>) -> Result<()> {
    let dir = hook_dir(mode, repo)?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create hook directory: {}", dir.display()))?;

    let preserved_foreign_hooks = match mode {
        HookMode::Global => install_global_hooks(&dir)?,
        HookMode::Local => {
            // Use the same staged installer as global setup. Local setup must
            // preserve a pre-existing hook too: for a submodule the resolved
            // gitdir is also the common hooks directory, so overwriting it
            // would otherwise make the foreign hook impossible to chain.
            install_hook_set(&dir)?
        }
    };

    let pre_commit_path = dir.join("pre-commit");
    let pre_push_path = dir.join("pre-push");
    let pre_rebase_path = dir.join("pre-rebase");

    for name in [
        "pre-commit.pre-dracon",
        "pre-push.pre-dracon",
        "pre-rebase.pre-dracon",
    ] {
        let stale = dir.join(name);
        if stale.exists() {
            if let Err(e) = fs::remove_file(&stale) {
                eprintln!(
                    "⚠️ failed to remove stale warden hook artifact {}: {}",
                    stale.display(),
                    e
                );
            }
        }
    }

    for path in &preserved_foreign_hooks {
        let scope = match mode {
            HookMode::Global => "global",
            HookMode::Local => "local",
        };
        println!("   preserved foreign {scope} hook = {}", path.display());
    }

    // Set executable permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&pre_commit_path, perms.clone())?;
        fs::set_permissions(&pre_push_path, perms.clone())?;
        fs::set_permissions(&pre_rebase_path, perms)?;
    }

    // Set core.hooksPath
    match mode {
        HookMode::Global => {
            let output = std::process::Command::new("git")
                .args([
                    "config",
                    "--global",
                    "core.hooksPath",
                    &dir.to_string_lossy(),
                ])
                .output()
                .context("failed to run git config")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!(
                    "failed to set core.hooksPath: {}",
                    stderr.trim()
                ));
            }
            // ---- 3-line summary ----
            println!("🪝 setup-hooks (global) · installed to {}", dir.display());
            println!("   core.hooksPath  = {}", dir.display());
            println!("   pre-commit hook = blocks commits if warden filter is missing");
            println!("   pre-push hook   = scans secrets + blocks non-ff (history guard)");
            println!("   pre-rebase hook = blocks rebasing published commits (history guard)");
            println!();
            println!("   Next: commit a file with secrets to test the encryption filter");
        }
        HookMode::Local => {
            let repo_path = repo.context("--local requires a repo path")?;
            let output = std::process::Command::new("git")
                .args(["-C"])
                .arg(repo_path)
                // FIXED 2026-07-21 (v0.112.32, audit M30/F4.4): the
                // previous args were `config local core.hooksPath <dir>`
                // (no `--`), which git parses as
                // `git config <name> <value> <pattern>` and rejects
                // with "key does not contain a section: local" — the
                // command ALWAYS failed (after the hook files were
                // already written, leaving a partial application).
                // Same bug class as the dracon-sync test-config
                // incident the same week, but in production code.
                .args([
                    "config",
                    "--local",
                    "core.hooksPath",
                    &dir.to_string_lossy(),
                ])
                .output()
                .context("failed to run git config")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!(
                    "failed to set local core.hooksPath: {}",
                    stderr.trim()
                ));
            }
            // ---- 3-line summary ----
            println!(
                "🪝 setup-hooks (local) · installed to {} for {}",
                dir.display(),
                repo_path.display()
            );
            println!("   core.hooksPath  = {}", dir.display());
            println!("   pre-commit hook = blocks commits if warden filter is missing");
            println!("   pre-push hook   = scans for plaintext secrets (defense-in-depth)");
            println!();
            println!("   Next: commit a file with secrets to test the encryption filter");
        }
    }

    Ok(())
}

/// Resolve the hooks directory Git will actually dispatch for `repo`.
///
/// A global `core.hooksPath` shadows `.git/hooks`; the global wrappers already
/// chain foreign local hooks explicitly, so seeding Warden copies into the
/// shadowed directory is both inactive and a source of confusing recursion
/// guards.  Keep local seeding only when Git's effective hooks directory is
/// the repository's own `.git/hooks`.
fn effective_hooks_dir(repo: &Path) -> Result<PathBuf> {
    let output = ProcessCommand::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .with_context(|| format!("failed to resolve git hooks path for {}", repo.display()))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "failed to resolve git hooks path for {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let raw = String::from_utf8(output.stdout)
        .context("git returned a non-UTF-8 hooks path")?
        .trim()
        .to_owned();
    if raw.is_empty() {
        return Err(anyhow::anyhow!(
            "git returned an empty hooks path for {}",
            repo.display()
        ));
    }

    let path = PathBuf::from(raw);
    Ok(if path.is_absolute() {
        path
    } else {
        repo.join(path)
    })
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn common_hooks_dir(repo: &Path) -> Option<PathBuf> {
    let git_dir = resolved_git_dir(repo)?;
    let common_dir = match fs::read_to_string(git_dir.join("commondir")) {
        Ok(raw) => {
            let path = Path::new(raw.trim());
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                git_dir.join(path)
            }
        }
        Err(_) => git_dir,
    };
    Some(common_dir.join("hooks"))
}

fn install_hooks_for_repo(repo: &Path) -> Result<()> {
    let Some(local_hooks_dir) = common_hooks_dir(repo) else {
        return Ok(());
    };
    if !local_hooks_dir.exists() {
        return Ok(());
    }

    let effective_hooks = effective_hooks_dir(repo)?;
    // ADDED 2026-09-19 (v0.113.13): refresh stale warden-owned
    // LOCAL hooks BEFORE the guards below. The local hooks execute
    // even when a global core.hooksPath is active (the global
    // wrapper chains $LOCAL_HOOK), so skipping them here would
    // leave migrated repos with commit-blocking stale hooks. This
    // is pure refresh (never fresh install, never user hooks).
    refresh_warden_hook_if_stale(&local_hooks_dir.join("pre-commit"), PRE_COMMIT_HOOK)?;
    refresh_warden_hook_if_stale(&local_hooks_dir.join("pre-push"), PRE_PUSH_HOOK)?;
    refresh_warden_hook_if_stale(&local_hooks_dir.join("pre-rebase"), PRE_REBASE_HOOK)?;
    if !same_path(&effective_hooks, &local_hooks_dir) {
        // Global or repo-local core.hooksPath is active.  Do not seed files
        // into an inactive directory; the effective wrapper is responsible
        // for chaining any pre-existing foreign local hooks.
        return Ok(());
    }

    let hooks_dir = effective_hooks;

    let pre_commit_path = hooks_dir.join("pre-commit");
    let pre_push_path = hooks_dir.join("pre-push");
    let pre_rebase_path = hooks_dir.join("pre-rebase");

    // Only install if not already present (don't overwrite user hooks)
    if pre_commit_path.exists() && pre_push_path.exists() && pre_rebase_path.exists() {
        return Ok(());
    }

    fs::create_dir_all(&hooks_dir).with_context(|| {
        format!(
            "failed to create repository hooks directory {}",
            hooks_dir.display()
        )
    })?;

    if !pre_commit_path.exists() {
        write_hook_atomically(&pre_commit_path, &render_hook(PRE_COMMIT_HOOK, None))?;
    }
    if !pre_push_path.exists() {
        write_hook_atomically(&pre_push_path, &render_hook(PRE_PUSH_HOOK, None))?;
    }
    // ADDED 2026-07-25 (v0.113.0): history-rewrite guard, rebase side.
    if !pre_rebase_path.exists() {
        write_hook_atomically(&pre_rebase_path, &render_hook(PRE_REBASE_HOOK, None))?;
    }
    // NOTE (v0.113.13): stale-refresh of warden-owned hooks
    // happens at the top of this function (before the
    // all-present early-return and regardless of
    // core.hooksPath), so no second refresh is needed here.

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        if pre_commit_path.exists() {
            fs::set_permissions(&pre_commit_path, perms.clone())?;
        }
        if pre_push_path.exists() {
            fs::set_permissions(&pre_push_path, perms.clone())?;
        }
        if pre_rebase_path.exists() {
            fs::set_permissions(&pre_rebase_path, perms)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
// end-to-end test: 2026-06-21T12:26:19Z — verify daemon still auto-pushes after .gitignore change

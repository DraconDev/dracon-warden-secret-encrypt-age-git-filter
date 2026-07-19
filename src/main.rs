#![warn(missing_docs)]

//! Dracon Warden — security hardening and encryption daemon.

mod print;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
pub(crate) use dracon_security_kit::DraconWarden;
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

pub(crate) fn discover_git_repos(
    roots: &[PathBuf],
    excluded_dir_names: &BTreeSet<String>,
) -> Vec<PathBuf> {
    let mut repos = Vec::new();
    for root in roots {
        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("⚠️ failed to read watch root {}: {}", root.display(), e);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("⚠️ failed to read entry in {}: {}", root.display(), e);
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if excluded_dir_names.contains(name.as_ref()) {
                continue;
            }
            if path.join(".git").exists() {
                repos.push(path);
            }
        }
    }
    repos
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
    ".env", "secrets/", "/secrets", "*.key", "*.pem", "*.age",
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
    /// Show resolved policy path and repo roots.
    Status,
    /// Run one hardening pass and exit.
    Once {
        /// Optional repo path to harden. If omitted, hardens repos in warden discovery scope.
        repo: Option<PathBuf>,
    },
    /// Scan plaintext JSON files for DRACON_SECRET markers and optionally scrub them.
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
    /// Generate a new age keypair for this machine.
    ///
    /// Creates ~/dracon/data/keys/`machine_<hostname>`.age (secret) and
    /// ~/dracon/data/keys/`owner_<hostname>`.pub (public). Also publishes
    /// the public key to the current repo's .dracon/data/keys/ directory.
    /// Fails if either file already exists to prevent accidental overwrite.
    Keygen,
    /// Install git hooks globally for warden encryption enforcement.
    ///
    /// Installs pre-commit and pre-push hooks to ~/.config/git/hooks/
    /// and sets core.hooksPath globally. The pre-commit hook blocks commits
    /// if the warden filter is not configured. The pre-push hook scans for
    /// plaintext secrets as defense-in-depth.
    SetupHooks {
        /// Install hooks globally (default). Sets core.hooksPath in global git config.
        #[arg(long, conflicts_with = "local")]
        global: bool,
        /// Install hooks locally into a specific repo's .git/hooks/ directory.
        #[arg(long, conflicts_with = "global")]
        local: bool,
        /// Repo path for --local mode. Defaults to current directory.
        repo: Option<PathBuf>,
    },
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct WardenPolicy {
    #[serde(default)]
    protected_patterns: Vec<String>,
    #[serde(default)]
    plaintext_patterns: Vec<String>,
    #[serde(default)]
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
}

impl WardenPolicy {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy {}", path.display()))?;
        let policy: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse policy {}", path.display()))?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<()> {
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

        for p in &plaintext {
            if !is_allowed_plaintext_pattern(p) {
                return Err(anyhow::anyhow!(
                    "invalid policy: plaintext_patterns is allowlisted; refusing: {p}"
                ));
            }
            let pl = p.to_lowercase();
            if FORBIDDEN_PLAINTEXT_SUBSTRINGS
                .iter()
                .any(|needle| pl.contains(&needle.to_lowercase()))
            {
                return Err(anyhow::anyhow!(
                    "invalid policy: refusing plaintext_patterns entry that disables encryption for secret-ish paths: {p}"
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
    /// Non-existent paths are filtered out.
    fn repo_root_paths(&self) -> Vec<PathBuf> {
        let chosen: &[String] = if !self.repo_roots.is_empty() {
            &self.repo_roots
        } else {
            &self.watch_roots
        };
        chosen
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    }

    fn discover_root_paths(&self) -> Vec<PathBuf> {
        self.discover_roots
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
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

#[cfg(test)]
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
            // Malformed: begin without end — consume rest
            rest = &rest[start + BLOCK_BEGIN.len()..];
            break;
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
    for p in &policy.protected_patterns {
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
    let mut plaintext_patterns = BTreeSet::new();
    for p in &policy.plaintext_patterns {
        plaintext_patterns.insert(p.clone());
    }
    let mut protected_patterns = BTreeSet::new();
    for p in &policy.protected_patterns {
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

pub(crate) fn apply_overwrite_file(path: &Path, content: &str) -> Result<bool> {
    let current = fs::read_to_string(path).unwrap_or_default();
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
    // it is not the owner private key. The current layout has legacy names
    // such as `owner_nixos.pub`, which is actually the public half of the
    // machine_nixos identity, so docs must describe the ambiguity instead of
    // treating this file as a dedicated main key.
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

pub(crate) fn publish_repo_pubkey(repo: &Path, pubkey_path: &Path) -> Result<bool> {
    let target_dir = repo.join(".dracon/data/keys");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed creating {}", target_dir.display()))?;

    let name = pubkey_path
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| "owner.pub".into());
    let target = target_dir.join(name);

    let source_bytes = fs::read(pubkey_path)
        .with_context(|| format!("failed reading pubkey {}", pubkey_path.display()))?;
    validate_owner_age_pubkey_bytes(pubkey_path, &source_bytes)?;
    let current_bytes = fs::read(&target).ok();
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

    fs::write(&target, source_bytes)
        .with_context(|| format!("failed writing {}", target.display()))?;
    Ok(true)
}

fn ensure_repo_filter_config(repo: &Path) -> Result<bool> {
    let desired = [
        ("filter.dracon.clean", "dracon-warden filter-clean %f"),
        ("filter.dracon.smudge", "dracon-warden filter-smudge %f"),
        ("filter.dracon.required", "true"),
    ];

    let mut changed = false;
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
        let path = repo.join(".git").join("index.lock");
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
    let git_dir = repo.join(".git");
    let head = git_dir.join("HEAD");

    if !head.exists() {
        return false;
    }

    let head_content = match fs::read_to_string(&head) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let head_content = head_content.trim();
    if !head_content.starts_with("ref: refs/heads/") {
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

    // Read existing .gitignore content to preserve patterns added by other tools (e.g., dracon-sync)
    let existing_gitignore = fs::read_to_string(&gitignore_path).unwrap_or_default();

    // Build gitignore block while preserving existing non-policy patterns
    let gitignore_changed = apply_overwrite_file(
        &gitignore_path,
        &build_gitignore_block_with_existing(policy, &existing_gitignore)?,
    )?;
    let gitattributes_changed =
        apply_overwrite_file(&gitattributes_path, &build_gitattributes_block(policy)?)?;
    let filter_cfg_changed = if repo.join(".git").exists() {
        ensure_repo_filter_config(repo)?
    } else {
        false
    };
    let key_changed = match pubkey_path {
        Some(pubkey) => publish_repo_pubkey(repo, pubkey)?,
        None => false,
    };

    // Install git hooks if not already present
    let _ = install_hooks_for_repo(repo);

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
            .write_all(format!("{}\n", recipient).as_bytes())
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
        f.write_all(format!("{}\n", recipient).as_bytes())
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
                 keygen only creates machine_<hostname>.age / owner_<hostname>.pub and must never \
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
        if cur.join(".git").exists() {
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

    match cli.cmd {
        Command::FilterClean { path } => {
            run_filter_with_timeout(true, "filter-clean", path).await?;
        }
        Command::FilterSmudge { path } => {
            run_filter_with_timeout(false, "filter-smudge", path).await?;
        }
        Command::Status => {
            let policy_path = resolve_policy_path_local()?;
            let policy = WardenPolicy::load(&policy_path)?;
            policy.validate()?;
            let repo_roots = effective_repo_roots(&policy);
            // Explicit (user-set) discovery roots only — i.e. those that
            // extend the repo_roots set. Empty if user didn't set discover_roots.
            let explicit_discover: Vec<PathBuf> = policy
                .discover_roots
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.exists())
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
            let _ = resmudge_repos(&policy, &repos, apply)?;
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
    if s[idx..].starts_with("[DRACON_SECRET:") {
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
    let bytes = content.as_bytes();
    while i < content.len() {
        if marker_prefix_at(content, i).is_none() {
            out.push(bytes[i] as char);
            i += 1;
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

    let protected = build_globset(&policy.protected_patterns)?;

    let mut found = 0usize;
    let mut changed = 0usize;
    let mut skipped = 0usize;
    let mut rows: Vec<(String, String, String)> = Vec::new();

    for repo in repos {
        if !repo.join(".git").exists() {
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
            let Ok(content) = fs::read_to_string(&path) else {
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
                fs::write(&path, &next)
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

fn resmudge_repo(repo: &Path, policy: &WardenPolicy, apply: bool) -> Result<(usize, usize)> {
    let protected = build_globset(&policy.protected_patterns)?;
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
        if let Ok(meta) = fs::metadata(&full) {
            if meta.len() as usize > STREAM_IO_MAX_BYTES {
                continue;
            }
        }
        let bytes = match fs::read(&full) {
            Ok(b) => b,
            Err(_) => continue,
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
                    if let Err(e) = fs::write(&full, out) {
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
        let bytes = match fs::read(&full) {
            Ok(b) => b,
            Err(_) => continue,
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
                    if let Err(e) = fs::write(&full, &out) {
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

const STREAM_IO_MAX_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

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
async fn run_filter_with_timeout(is_clean: bool, label: &str, path: Option<String>) -> Result<()> {
    let join_result = tokio::time::timeout(
        Duration::from_secs(FILTER_TIMEOUT_SECS),
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
                label, FILTER_TIMEOUT_SECS
            );
            std::process::exit(1);
        }
    }
}

fn run_filter(is_clean: bool, path: Option<&str>) -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    if input.len() > STREAM_IO_MAX_BYTES {
        std::io::stdout().write_all(&input)?;
        return Ok(());
    }

    // FDRACONWARDEN-002 (2026-07-18): defensively verify the path git
    // gave us stays inside the working repo. Git invokes the filter
    // with CWD = repo root and `%f` = repo-relative path, but a
    // malicious `.gitattributes` or a misconfigured submodule could
    // pass a path that escapes the repo. We refuse absolute paths
    // and any path containing a `..` component that would walk above
    // CWD after canonicalisation.
    if let Some(p) = path {
        let p_buf = std::path::PathBuf::from(p);
        if p_buf.is_absolute() {
            eprintln!(
                "dracon-warden: refusing filter path '{}' (absolute paths not allowed)",
                p
            );
            std::io::stdout().write_all(&input)?;
            return Ok(());
        }
        for comp in p_buf.components() {
            if matches!(comp, std::path::Component::ParentDir) {
                eprintln!(
                    "dracon-warden: refusing filter path '{}' (contains '..')",
                    p
                );
                std::io::stdout().write_all(&input)?;
                return Ok(());
            }
        }
    }

    let warden = DraconWarden::new()?;
    let output = if is_clean {
        warden.clean(&input, path)?
    } else {
        warden.smudge(&input, path)?
    };
    std::io::stdout().write_all(&output)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookMode {
    Global,
    Local,
}

fn hook_dir(mode: HookMode, repo: Option<&Path>) -> Result<PathBuf> {
    match mode {
        HookMode::Global => {
            let home = dirs::home_dir().context("could not determine home directory")?;
            Ok(home.join(".config/git/hooks"))
        }
        HookMode::Local => {
            let repo_path = repo.context("--local requires a repo path")?;
            let git_dir = repo_path.join(".git");
            if !git_dir.exists() {
                return Err(anyhow::anyhow!(
                    "not a git repo: {} (no .git directory)",
                    repo_path.display()
                ));
            }
            Ok(git_dir.join("hooks"))
        }
    }
}

const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# Dracon Warden — pre-commit hook
# Validates that the warden encryption filter is configured before committing.
# Installed by: dracon-warden setup-hooks

REPO=$(git rev-parse --show-toplevel)

# Check .gitattributes has filter=dracon patterns
if ! grep -q "filter=dracon" "$REPO/.gitattributes" 2>/dev/null; then
    echo "❌ Warden filter missing from .gitattributes."
    echo "   Run: dracon-warden once $REPO"
    exit 1
fi

# Check git config has filter.dracon.clean set
if ! git -C "$REPO" config filter.dracon.clean >/dev/null 2>&1; then
    echo "❌ Warden filter not configured in git config."
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

const PRE_PUSH_HOOK: &str = r#"#!/bin/sh
# Dracon Warden — pre-push hook
# Defense-in-depth: scans push for plaintext secrets.
# Catches --no-verify bypass of pre-commit hook.
# Installed by: dracon-warden setup-hooks
#
# Plaintext-sibling escape hatch: a file with a `<path>.plaintext` sibling
# is treated as intentionally plaintext. Such files are excluded from the
# scan (silent allow). See docs/design/warden-plaintext-sibling.md.

# Read push info from stdin (remote URL and branch refs)
while read local_ref local_sha remote_ref remote_sha; do
    # Skip branch deletions
    if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
        continue
    fi

    # Determine the diff range to scan
    if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
        # New branch — scan the entire local commit history being pushed.
        # Use the empty-tree SHA so `git diff` always has a valid left side,
        # even if the remote ref hasn't been created yet.
        RANGE="4b825dc642cb6eb9a060e54bf8d69288fbee4904..$local_sha"
    else
        # Existing branch — scan commits being pushed
        RANGE="$remote_sha..$local_sha"
    fi

    # Collect non-hatched files (skip files with a `.plaintext` sibling)
    SCAN_FILES=""
    for f in $(git diff --name-only "$RANGE" 2>/dev/null); do
        if [ -f "$f.plaintext" ]; then
            # Hatched file — silently allow
            continue
        fi
        SCAN_FILES="$SCAN_FILES $f"
    done

    # Nothing left to scan — push is safe
    if [ -z "$SCAN_FILES" ]; then
        continue
    fi

    # Scan only newly added diff lines. Deletions of old secret-shaped fixtures
    # are safe, while additions still trip the defense-in-depth guard.
    DIFF=$(git diff --unified=0 "$RANGE" -- $SCAN_FILES 2>/dev/null | grep -E '^\+[^+]' || true)
    if echo "$DIFF" | grep -qE '(A{1}KIA[A-Z0-9]{16}|-----BEGIN [A-Z]+ PRIVATE KEY|password\s*=\s*["\x27][^"\x27]+|secret\s*=\s*["\x27][^"\x27]+|api_key\s*=\s*["\x27][^"\x27]+)'; then
        echo "⚠️  Possible plaintext secrets detected in push."
        echo "   The warden filter may have been bypassed."
        echo "   Run: dracon-warden once $(git rev-parse --show-toplevel)"
        exit 1
    fi
done
"#;

fn run_setup_hooks(mode: HookMode, repo: Option<&Path>) -> Result<()> {
    let dir = hook_dir(mode, repo)?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create hook directory: {}", dir.display()))?;

    let pre_commit_path = dir.join("pre-commit");
    let pre_push_path = dir.join("pre-push");

    fs::write(&pre_commit_path, PRE_COMMIT_HOOK)
        .with_context(|| format!("failed to write {}", pre_commit_path.display()))?;
    fs::write(&pre_push_path, PRE_PUSH_HOOK)
        .with_context(|| format!("failed to write {}", pre_push_path.display()))?;

    // Set executable permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&pre_commit_path, perms.clone())?;
        fs::set_permissions(&pre_push_path, perms)?;
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
            println!("   pre-push hook   = scans for plaintext secrets (defense-in-depth)");
            println!();
            println!("   Next: commit a file with secrets to test the encryption filter");
        }
        HookMode::Local => {
            let repo_path = repo.context("--local requires a repo path")?;
            let output = std::process::Command::new("git")
                .args(["-C"])
                .arg(repo_path)
                .args(["config", "local", "core.hooksPath", &dir.to_string_lossy()])
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

fn install_hooks_for_repo(repo: &Path) -> Result<()> {
    let hooks_dir = repo.join(".git/hooks");
    if !hooks_dir.exists() {
        return Ok(());
    }

    let pre_commit_path = hooks_dir.join("pre-commit");
    let pre_push_path = hooks_dir.join("pre-push");

    // Only install if not already present (don't overwrite user hooks)
    if pre_commit_path.exists() && pre_push_path.exists() {
        return Ok(());
    }

    fs::create_dir_all(&hooks_dir)?;

    if !pre_commit_path.exists() {
        fs::write(&pre_commit_path, PRE_COMMIT_HOOK)?;
    }
    if !pre_push_path.exists() {
        fs::write(&pre_push_path, PRE_PUSH_HOOK)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        if pre_commit_path.exists() {
            fs::set_permissions(&pre_commit_path, perms.clone())?;
        }
        if pre_push_path.exists() {
            fs::set_permissions(&pre_push_path, perms)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
// end-to-end test: 2026-06-21T12:26:19Z — verify daemon still auto-pushes after .gitignore change

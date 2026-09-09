#![warn(missing_docs)]
#![allow(missing_docs)] // Internal security module — docs deferred

//! Age-based encryption, secret scanning, and filter pipeline for dracon-warden.

use age::x25519;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

pub mod modules;

pub use modules::environment::EnvironmentManager;
pub use modules::filter::is_hatched;
pub use modules::keys::RepoKey;
pub use modules::keys::TeamKey;
pub use modules::scanner::SecretFinding;
pub use modules::scanner::SecretScanner;

const DEFAULT_SECRET_MARKER: &str = "DRACON_SECRET";

/// Age encryption header magic. Mirrors the module-private duplicates in
/// `modules/filter.rs` and `modules/crypto.rs` (kept private per module;
/// this crate's established pattern). Used to distinguish REAL whole-file
/// tags (`[DRACON_SECRET:<b64 of age payload>]`) from tag-shaped
/// plaintext.
const HEADER_V2_MAGIC: &[u8] = b"age-encryption.org/v1";

static DEFAULT_SECURITY_CACHE: OnceCell<WardenSecurity> = OnceCell::new();

/// Managed-pattern override for the filter process. The
/// `WardenSecurity` builder starts with an EMPTY `managed_patterns`
/// list, and `path_is_protected` treats an empty list as "scan
/// everything (legacy)" — so without this override the
/// `protected_patterns` config knob was dead code in the filter path
/// and every file was secret-scanned (~16 s of regex work for a
/// 6.87 MB HTML, blowing the filter's 30 s budget during concurrent
/// `git add` batches and wedging the sync daemon; junk-runner,
/// 2026-08-09). The `dracon-warden` binary wires the policy's
/// `protected_patterns` here once per filter invocation.
static MANAGED_PATTERNS_OVERRIDE: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// Set the managed (protected) patterns for the current filter
/// process. Called by the `dracon-warden` binary's filter path from
/// the policy's `protected_patterns` list, so files that are NOT
/// protected pass through the clean filter untouched (the
/// "default-deny" design) instead of being secret-scanned.
pub fn set_managed_patterns(patterns: Vec<String>) {
    *MANAGED_PATTERNS_OVERRIDE.lock().unwrap() = Some(patterns);
}

/// Current managed-patterns override, if set (filter-process
/// plumbing + diagnostics).
pub fn managed_patterns_override() -> Option<Vec<String>> {
    MANAGED_PATTERNS_OVERRIDE.lock().unwrap().clone()
}

/// Clear the managed-patterns override (test + diagnostics use).
pub fn clear_managed_patterns_override() {
    *MANAGED_PATTERNS_OVERRIDE.lock().unwrap() = None;
}

static ALLOW_V1_FALLBACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Legacy V1 AES-CFB decryption is intentionally unavailable. CFB has no
// authenticated integrity, so a wrong-key result can look like valid text
// and cannot be distinguished safely from a correct-key plaintext. The
// `allow_v1_fallback` policy field and these accessors remain only for
// configuration/API compatibility; they never enable legacy decryption.
pub fn set_allow_v1_fallback(allow: bool) {
    ALLOW_V1_FALLBACK.store(allow, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_v1_fallback_allowed() -> bool {
    ALLOW_V1_FALLBACK.load(std::sync::atomic::Ordering::Relaxed)
}

const ENV_VERSION_HEADER_TEMPLATE: &str = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# This file is encrypted by dracon-warden for secure team collaboration.
# Version: {}
# DO NOT EDIT THE ENCRYPTED CONTENT MANUALLY - Use `dracon-warden smudge` to decrypt.
# =============================================================================
"#;

/// Marker line of the warden-managed `.env` header (line 2 of
/// `ENV_VERSION_HEADER_TEMPLATE`).
const ENV_HEADER_MARKER_LINE: &str = "# Dracon Warden Encrypted Environment File";

/// Version-line prefix inside the managed header.
const ENV_HEADER_VERSION_PREFIX: &str = "# Version: ";

fn get_env_version(content: &str) -> u32 {
    // Only the warden-managed header block at the TOP of the file may
    // drive the header version. A "Version: " substring in the body
    // (env values, comments, app-version strings) must NOT — the old
    // whole-file `find` produced wrong/duplicated header versions on
    // fresh files that merely contained a version line (audit LOW,
    // 2026-08-10).
    let mut lines = content.lines();
    for (idx, line) in lines.by_ref().enumerate() {
        if line.trim() == ENV_HEADER_MARKER_LINE {
            // FIXED 2026-08-12 (audit 2026-08-11 disapproval): the
            // version line does NOT immediately follow the marker in
            // the real template — line 3 is the
            // "# This file is encrypted ..." banner, the version lives
            // on line 4. The old strict adjacency read the banner,
            // failed the prefix check and returned 0, so every
            // re-encryption RESET the version to 1 (blob rewritten
            // each cycle). Scan a bounded window (the rest of the
            // 6-line header block) for the version prefix instead.
            for (k, vline) in lines.by_ref().enumerate() {
                if let Some(rest) = vline.trim().strip_prefix(ENV_HEADER_VERSION_PREFIX) {
                    if let Ok(v) = rest.trim().parse::<u32>() {
                        return v;
                    }
                }
                // k=0..3 = template lines 3-6 (banner, version, DO NOT
                // EDIT, closing banner); stop before the body.
                if k >= 3 {
                    break;
                }
            }
            return 0;
        }
        // The header occupies only the top few lines; past that the
        // marker string is body content, not a header.
        if idx >= 6 {
            return 0;
        }
    }
    0
}

/// True when `content` carries the warden-managed `.env` header at its
/// top (marker line within the first few lines). Used by the clean
/// filter to decide between "increment existing header" and "first-time
/// encryption" — the old `contains("Dracon Warden")` gate treated any
/// comment mentioning Dracon Warden as a managed file, producing
/// wrong/duplicated headers (audit LOW, 2026-08-10).
pub(crate) fn is_env_version_managed(content: &str) -> bool {
    content
        .lines()
        .take(6)
        .any(|l| l.trim() == ENV_HEADER_MARKER_LINE)
}

fn make_env_version_header(content: &str) -> String {
    let current_version = get_env_version(content);
    let next_version = if current_version == 0 {
        1
    } else {
        current_version + 1
    };
    ENV_VERSION_HEADER_TEMPLATE.replace("{}", &next_version.to_string())
}

fn strip_env_version_header(content: &str) -> &str {
    // FIXED 2026-08-12 (audit LOW): the old whole-file `find` stripped
    // everything from the FIRST occurrence of the marker ANYWHERE in
    // the file — a body value/comment merely mentioning the marker
    // text mangled the file on re-encryption. Only a marker within the
    // top lines is the managed header block (same top-6 rule as
    // `get_env_version` / `is_env_version_managed`); past that the
    // marker string is body content.
    let header_marker = ENV_HEADER_MARKER_LINE;
    for (idx, line) in content.lines().enumerate() {
        // Same top-6 rule as `is_env_version_managed` (which gates
        // this call): only lines 0-5 may hold the header marker.
        if idx >= 6 {
            break;
        }
        if line.trim() == header_marker {
            // Byte offset of this line's start (lines() yields slices
            // into `content`, so the pointer delta is exact for both
            // \n and \r\n files).
            let marker_offset = line.as_ptr() as usize - content.as_ptr() as usize;
            let after_header = &content[marker_offset..];
            let closing_marker =
                "# =============================================================================";
            if let Some(closing_pos) = after_header.find(closing_marker) {
                let after_closing = &after_header[closing_pos + closing_marker.len()..];
                // Skip only the newline(s) directly after the closing
                // marker — the BODY's own leading indentation and
                // trailing whitespace must be preserved byte-exact
                // (the filter no longer calls .trim() on this).
                return after_closing
                    .trim_start_matches('\n')
                    .trim_start_matches('\r');
            }
            return content;
        }
        // The header occupies only the top few lines; past that the
        // marker string is body content, not a header.
        if idx >= 6 {
            break;
        }
    }
    content
}

pub const REPO_KEY_LEN: usize = 32;

fn normalize_secret_marker(raw: &str) -> Option<String> {
    let marker = raw.trim().to_ascii_uppercase();
    let valid = !marker.is_empty()
        && marker
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && marker.ends_with("_SECRET");
    if valid {
        Some(marker)
    } else {
        None
    }
}

fn is_inside_secret_tag(content: &str, start_idx: usize) -> bool {
    let prefix = &content[..start_idx];
    if let Some(tag_start) = prefix.rfind('[') {
        if prefix[tag_start..].contains(']') {
            return false;
        }
        let window = &content[tag_start..start_idx];
        return window.contains("_SECRET:");
    }
    false
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryCredential {
    pub registry: String, // e.g. "ghcr.io"
    pub username: String,
    #[serde(skip)]
    pub password: String, // Token or Password
}

impl RegistryCredential {
    pub fn new(registry: &str, username: &str, password: &str) -> Self {
        Self {
            registry: registry.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MarkerMigrationStats {
    pub files_scanned: usize,
    pub files_changed: usize,
    pub markers_changed: usize,
    pub walk_errors: usize,
}

#[derive(Clone)]
pub struct WardenSecurity {
    master_identities: Vec<x25519::Identity>,
    imported_identities: Vec<x25519::Identity>,
    managed_patterns: Vec<String>,
    secret_marker: String,
    repo_root: Option<PathBuf>,
    mock_home: Option<PathBuf>,
    pub dev_mode: bool,
}

impl WardenSecurity {
    pub fn master_identities(&self) -> &[x25519::Identity] {
        &self.master_identities
    }

    /// Apply the process-wide managed-patterns override (set by the
    /// `dracon-warden` binary from the policy's `protected_patterns`).
    /// Without this, `managed_patterns` stays empty and
    /// `path_is_protected` falls back to the legacy scan-everything
    /// behavior — the config gate would be dead code.
    fn apply_managed_patterns_override(&mut self) {
        if let Some(patterns) = MANAGED_PATTERNS_OVERRIDE.lock().unwrap().clone() {
            self.managed_patterns = patterns;
        }
    }

    pub fn with_managed_patterns(mut self, patterns: Vec<String>) -> Self {
        self.managed_patterns = patterns;
        self
    }

    pub fn with_secret_marker(mut self, marker: &str) -> Self {
        if let Some(normalized) = normalize_secret_marker(marker) {
            self.secret_marker = normalized;
        }
        self
    }

    pub fn secret_marker(&self) -> &str {
        &self.secret_marker
    }

    pub fn get_or_init() -> Result<&'static WardenSecurity> {
        DEFAULT_SECURITY_CACHE.get_or_try_init(|| {
            let mut security = WardenSecurity::new(None)?;
            security.apply_managed_patterns_override();
            if let Ok(ids) = security.load_master_identities() {
                security.master_identities = ids;
            }
            if let Ok(imported) = security.load_imported_identities() {
                if !imported.is_empty() {
                    security.imported_identities = imported;
                }
            }
            Ok(security)
        })
    }

    fn supported_secret_markers(&self) -> Vec<String> {
        vec![self.secret_marker.clone()]
    }

    fn secret_tag_prefixes(&self) -> Vec<String> {
        self.supported_secret_markers()
            .into_iter()
            .map(|m| format!("[{}:", m))
            .collect()
    }

    fn contains_any_secret_tag(&self, content: &str) -> bool {
        self.secret_tag_prefixes()
            .iter()
            .any(|prefix| content.contains(prefix))
    }

    fn count_secret_tags(&self, content: &str) -> usize {
        self.secret_tag_prefixes()
            .iter()
            .map(|prefix| content.matches(prefix).count())
            .sum()
    }

    /// Trim trailing line-ending artifacts (`\r`/`\n`) from the end of
    /// a whole-file secret tag. ADDED 2026-08-09 (audit MEDIUM): the
    /// previous single `strip_suffix(b"\n")` accepted at most ONE trailing
    /// `\n` — a tag whose blob gained CRLF (`...]\r\n` ends with `\r`
    /// after stripping) or 2+ trailing newlines (`...]\n\n`) was not
    /// recognized as a whole-file tag, so on smudge the binary fell into
    /// the UTF-8-lossy inline path (U+FFFD corruption of DER/SQLite/.kdbx)
    /// and on clean the double-encrypt guards missed it (re-encryption).
    fn trim_trailing_line_endings(content: &[u8]) -> &[u8] {
        let mut end = content.len();
        while end > 0 && matches!(content[end - 1], b'\r' | b'\n') {
            end -= 1;
        }
        &content[..end]
    }

    fn starts_with_any_secret_tag(&self, content: &[u8]) -> bool {
        let trimmed = Self::trim_trailing_line_endings(content);
        self.secret_tag_prefixes().iter().any(|prefix| {
            let p = prefix.as_bytes();
            if !(trimmed.starts_with(p) && trimmed.ends_with(b"]")) {
                return false;
            }
            // FIXED 2026-08-11 (audit MEDIUM): recognition was purely
            // SYNTACTIC — any protected file whose plaintext merely
            // STARTED `[DRACON_SECRET:` and ENDED `]` (tag-shaped
            // plaintext: a template, a redacted placeholder, or a
            // hand-written "already encrypted" marker) tripped the
            // clean-side double-encrypt guard (filter.rs:269/317) and
            // was committed UNENCRYPTED, silently. Validate the payload
            // for real: it must be valid base64 AND decode to an age
            // payload (age-encryption.org/v1 magic).
            let b64 = &trimmed[p.len()..trimmed.len() - 1];
            let b64_str = std::str::from_utf8(b64).unwrap_or("");
            let Ok(encrypted) = general_purpose::STANDARD.decode(b64_str.trim()) else {
                return false;
            };
            encrypted.starts_with(HEADER_V2_MAGIC)
        })
    }

    pub fn get_identity_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        Ok(home.join(".dracon").join("identity.age"))
    }

    pub fn new(repo_path: Option<&Path>) -> Result<Self> {
        let mut security = Self {
            master_identities: Vec::new(),
            imported_identities: Vec::new(),
            managed_patterns: Vec::new(),
            secret_marker: std::env::var("DRACON_SECRET_MARKER")
                .ok()
                .and_then(|m| normalize_secret_marker(&m))
                .unwrap_or_else(|| DEFAULT_SECRET_MARKER.to_string()),
            repo_root: repo_path.map(|p| p.to_path_buf()),
            mock_home: None,
            dev_mode: false,
        };

        match security.load_master_identities() {
            Ok(ids) => {
                security.master_identities = ids;
            }
            Err(e) => {
                eprintln!("⚠️ Failed to load master identities: {}", e);
            }
        };

        // Load imported legacy keys
        if let Ok(imported) = security.load_imported_identities() {
            if !imported.is_empty() {
                security.imported_identities = imported;
            }
        }

        Ok(security)
    }

    /// Load generic identities from ~/.dracon/keys/*.age (e.g. Git Seal keys)
    fn load_imported_identities(&self) -> Result<Vec<x25519::Identity>> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        let keys_dir = home.join(".dracon").join("keys");
        let mut identities = Vec::new();

        if !keys_dir.exists() {
            return Ok(identities);
        }

        for entry in std::fs::read_dir(keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                // Try reading as string (Bech32 Identity)
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Some(key_str) = content
                        .lines()
                        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
                    {
                        if let Ok(id) = std::str::FromStr::from_str(key_str.trim()) {
                            identities.push(id);
                            continue;
                        }
                    }
                }

                // Legacy Git-Seal/Raw Key loading removed in Phase 48 (Clean Slate)
            }
        }
        Ok(identities)
    }

    /// Load ALL Master Identities from all known paths (Multi-Key Ring)
    /// Returns a vector of identities, prioritized by path.
    pub fn load_master_identities(&self) -> Result<Vec<x25519::Identity>> {
        let home = dirs::home_dir().context("cannot determine home directory")?;
        let mut identities = Vec::new();

        // Path Priority List.
        //
        // `keys/master.age` is the dedicated owner/master private key when the
        // operator has it locally. It is loaded through the general keys scan
        // below and is not the only possible master identity.
        let candidate_paths = vec![
            // 1. Sovereign Master (not present in the current layout)
            home.join(".dracon").join("master.age"),
            // 2. Standard Identity (not present in the current layout)
            home.join(".dracon").join("identity.age"),
            // 3. Legacy local identity used by this box
            home.join(".dracon").join("keys").join("identity.age"),
        ];

        // 6. GENERAL SCAN: ~/.dracon/keys/*.age (and similar dirs)
        // This satisfies "if a user adds their key whatever it is called we can try it"
        let general_keys = vec![
            home.join(".dracon").join("keys"), // key storage
        ];

        for dir in general_keys {
            if dir.exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|s| s.to_str()) == Some("age") {
                            // Avoid duplicates if we already added it explicitly
                            if !candidate_paths.contains(&p) {
                                // Add to check list (or just parse here)
                                // Let's just parse here to avoid modifying 'paths' which is consumed.
                                if let Ok(c) = fs::read_to_string(&p) {
                                    // Quick parse
                                    if let Some(k) = c
                                        .lines()
                                        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
                                    {
                                        if let Ok(id) = std::str::FromStr::from_str(k.trim()) {
                                            identities.push(id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for path in candidate_paths {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Some(key_str) = content
                        .lines()
                        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
                    {
                        if let Ok(id) = std::str::FromStr::from_str(key_str.trim()) {
                            identities.push(id);
                        }
                    }
                }
            }
        }

        if identities.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid identities found in any search path."
            ));
        }

        Ok(identities)
    }

    pub fn has_master_identity(&self) -> bool {
        !self.master_identities.is_empty()
    }

    /// Add an identity explicitly from memory (useful for tests or ephemeral agents)
    pub fn add_memory_identity(&mut self, key: x25519::Identity) {
        self.master_identities.push(key);
    }

    /// Set a custom backup root directory (useful for tests)
    pub fn set_mock_home(&mut self, path: PathBuf) {
        self.mock_home = Some(path);
    }

    fn get_home(&self) -> Result<PathBuf> {
        if let Some(ref h) = self.mock_home {
            Ok(h.clone())
        } else {
            dirs::home_dir().context("Could not find home directory")
        }
    }

    /// Explicitly generate and save a new Master Identity
    /// CRITICAL: This should only ever be called ONCE per user.
    /// If an identity already exists, this will refuse to overwrite it.
    /// Helper to get the repo root, either from configured path or CWD
    fn get_repo_root(&self) -> Result<PathBuf> {
        if let Some(root) = &self.repo_root {
            return Ok(root.clone());
        }
        Self::find_repo_root()
    }

    /// Find the git repository root from the current directory
    pub fn find_repo_root() -> Result<PathBuf> {
        let mut current = std::env::current_dir()?;
        loop {
            if current.join(".git").exists() {
                return Ok(current);
            }
            if !current.pop() {
                return Err(anyhow::anyhow!("Not in a git repository"));
            }
        }
    }

    /// Load the repo key from .git/arcane/keys/*.age or history
    pub fn load_repo_key(&self) -> Result<RepoKey> {
        let repo_root = self.get_repo_root()?;
        let keys_dir = repo_root.join(".git").join("arcane").join("keys");

        if !keys_dir.exists() {
            return Err(anyhow::anyhow!(
                "No keys found. Run 'dracon-warden' to initialize."
            ));
        }

        // 0. Try Machine Key (Env Var) - Priority for CI/CD
        if let Ok(machine_key_str) = std::env::var("ARCANE_MACHINE_KEY") {
            // Derive identity from the env var string
            use std::str::FromStr;
            if let Ok(machine_identity) = x25519::Identity::from_str(&machine_key_str) {
                if let Ok(key) = self.try_decrypt_directory_machine(&keys_dir, &machine_identity) {
                    return Ok(key);
                }
            }
        }

        // 1. Try ALL Master Identities (Key Ring)
        for identity in &self.master_identities {
            // 1a. Try direct User access (keys/*.age)
            if let Ok(key) = self.try_decrypt_directory(&keys_dir, identity) {
                return Ok(key);
            }

            // 1b. Try history keys (latest to oldest)
            let history_dir = keys_dir.join("history");
            if history_dir.exists() {
                if let Ok(entries) = fs::read_dir(&history_dir) {
                    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                    entries.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
                    for entry in entries {
                        if entry.path().is_dir() {
                            if let Ok(key) = self.try_decrypt_directory(&entry.path(), identity) {
                                return Ok(key);
                            }
                        }
                    }
                }
            }
        }

        // 1c. Try Imported Identities (Heritage Keys / Git Seal)
        for imported_id in &self.imported_identities {
            if let Ok(key) = self.try_decrypt_directory(&keys_dir, imported_id) {
                return Ok(key);
            }
        }

        // 2. Try Team access (keys/team:*.age)
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                if filename.starts_with("team:") && filename.ends_with(".age") {
                    let team_name = filename
                        .trim_start_matches("team:")
                        .trim_end_matches(".age");

                    if let Ok(team_key) = self.load_team_key(team_name) {
                        if let Ok(repo_key) = self.decrypt_repo_key_with_team_key(&path, &team_key)
                        {
                            return Ok(repo_key);
                        }
                    }
                }
            }
        }

        // 4. Last Resort: Legacy repo.key (Removed Phase 48)

        Err(anyhow::anyhow!(
            "Access Denied. Missing valid Key (User, Team, or Machine)."
        ))
    }

    /// Authorize a new recipient (Machine or User) to access this repository
    pub fn authorize_recipient(&self, recipient: &age::x25519::Recipient) -> Result<()> {
        let repo_key = self.load_repo_key()?;
        let repo_root = self.get_repo_root()?;
        let keys_dir = repo_root.join(".git").join("arcane").join("keys");
        std::fs::create_dir_all(&keys_dir)?;
        let keys_metadata =
            fs::symlink_metadata(&keys_dir).context("inspect repository recipient directory")?;
        if !keys_metadata.file_type().is_dir() {
            anyhow::bail!("repository recipient directory must be a real directory")
        }

        let output_path = keys_dir.join(format!("{}.age", recipient));
        let public_path = keys_dir.join(format!("{}.pub", recipient));
        let output_exists = match fs::symlink_metadata(&output_path) {
            Ok(metadata) if metadata.file_type().is_file() => true,
            Ok(_) => anyhow::bail!("refusing to overwrite non-regular recipient delegation"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let public_exists = match fs::symlink_metadata(&public_path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let existing = fs::read_to_string(&public_path)?;
                if existing.trim() != recipient.to_string() {
                    anyhow::bail!("recipient public key already names a different recipient")
                }
                true
            }
            Ok(_) => anyhow::bail!("refusing to overwrite non-regular recipient public key"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };

        // An explicit owner reauthorization upgrades a legacy or old-V2
        // sidecar without replacing the delegated age ciphertext. This keeps
        // existing direct recipients usable after the V2 owner-signature
        // format change while refusing ambiguous partial pairs.
        if output_exists {
            if !public_exists {
                anyhow::bail!("existing recipient delegation has no public pair")
            }
            self.ensure_repo_recipient_authorization(&repo_key, &public_path, "direct", recipient)?;
            return Ok(());
        }

        // Encrypt the repo key for the recipient. The recipient-named pair is
        // accepted by discovery only with the owner-signed authorization
        // proof written below; a contributor cannot forge it from public data.
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient.clone())];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("failed to create encryptor")?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(&repo_key.0)?;
        writer.finish()?;

        #[cfg(unix)]
        {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output_path)?
                .write_all(&encrypted)?;
        }
        #[cfg(not(unix))]
        {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)?
                .write_all(&encrypted)?;
        }
        if !public_exists {
            self.write_repo_public_recipient(&public_path, recipient)?;
        }
        self.ensure_repo_recipient_authorization(&repo_key, &public_path, "direct", recipient)?;
        Ok(())
    }

    // specialized helper for machine key scanning
    fn try_decrypt_directory_machine(
        &self,
        dir: &Path,
        identity: &x25519::Identity,
    ) -> Result<RepoKey> {
        let dir_metadata = fs::symlink_metadata(dir)?;
        if dir_metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "repository machine-key directory must not be a symlink"
            ));
        }
        let machine_recipient = identity.to_public();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("age") {
                continue;
            }
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            if !filename.starts_with("machine:") {
                continue;
            }
            let pub_path = path.with_extension("pub");
            match fs::symlink_metadata(&pub_path) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                _ => continue,
            }
            let Ok(public_content) = fs::read_to_string(&pub_path) else {
                continue;
            };
            let Some(recipient) =
                crate::modules::crypto::parse_single_repo_recipient(&public_content)
            else {
                continue;
            };
            if recipient != machine_recipient {
                continue;
            }
            let Ok(repo_key) = self.try_decrypt_key_file(&path, identity) else {
                continue;
            };
            if self
                .verify_machine_recipient_authorization(&pub_path, &recipient, identity, &repo_key)
            {
                return Ok(repo_key);
            }
        }
        Err(anyhow::anyhow!(
            "No authenticated matching machine key found"
        ))
    }

    /// Generate a new Machine Identity (Private Key, Public Key)
    /// Authorize a Machine (Public Key) to access this repo
    /// Load a Team Key from ~/.dracon/teams/<name>.key
    fn decrypt_repo_key_with_team_key(&self, path: &Path, team_key: &TeamKey) -> Result<RepoKey> {
        let encrypted_bytes = fs::read(path)?;

        let team_identity_bytes = &team_key.0;
        let team_identity_str = String::from_utf8(team_identity_bytes.clone())
            .map_err(|_| anyhow::anyhow!("Invalid team identity bytes"))?;
        let team_identity = x25519::Identity::from_str(&team_identity_str)
            .map_err(|e| anyhow::anyhow!("Invalid team identity format: {}", e))?;

        // Fix: Wrap input in Cursor for Decryptor
        let decryptor = age::Decryptor::new(std::io::Cursor::new(&encrypted_bytes))?;
        let mut reader = match decryptor {
            age::Decryptor::Recipients(d) => d
                .decrypt(std::iter::once(&team_identity as &dyn age::Identity))
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?,
            age::Decryptor::Passphrase(_) => {
                return Err(anyhow::anyhow!("Passphrase encryption not supported"))
            }
        };

        let mut key_bytes = Vec::new();
        reader.read_to_end(&mut key_bytes)?;

        if key_bytes.len() != REPO_KEY_LEN {
            return Err(anyhow::anyhow!("Invalid decrypted key length"));
        }

        Ok(RepoKey(key_bytes))
    }

    /// Create a new Team (Generates a new Identity, saves to keychain)
    /// Add a new team member by encrypting the repo key for them
    /// Create an Invite for a user to join a Team
    /// Accept a Team Invite
    /// Revoke a recipient's access to this repo by removing their key files
    /// List all authorized recipients in the current repository
    /// List all team members (aliases)
    ///
    /// Direct operator access uses the canonical repo-key name or the
    /// recipient-named delegation emitted by `authorize_recipient`. Do not
    /// scan every `.age` file: a contributor could otherwise add an age blob
    /// encrypted to the owner's public key, make it decrypt to an arbitrary
    /// 32-byte value, and potentially make it the HMAC/AEAD trust key for a
    /// forged recipient authorization sidecar.
    fn is_direct_repo_key_candidate(path: &Path, identity: &x25519::Identity) -> bool {
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        filename == "repo.key.age"
            || filename == "repo.age"
            || filename == "owner.age"
            || filename == format!("{}.age", identity.to_public())
    }

    fn try_decrypt_directory(&self, dir: &Path, identity: &x25519::Identity) -> Result<RepoKey> {
        let dir_metadata = fs::symlink_metadata(dir)?;
        if dir_metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "repository key directory must not be a symlink"
            ));
        }
        let identity_recipient = identity.to_public();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file()
                || path.extension().and_then(|s| s.to_str()) != Some("age")
                || !Self::is_direct_repo_key_candidate(&path, identity)
            {
                continue;
            }
            let is_recipient_named = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name == format!("{}.age", identity_recipient))
                .unwrap_or(false);
            let Ok(repo_key) = self.try_decrypt_key_file(&path, identity) else {
                continue;
            };
            if !is_recipient_named {
                return Ok(repo_key);
            }

            let pub_path = path.with_extension("pub");
            if !matches!(
                fs::symlink_metadata(&pub_path),
                Ok(metadata) if metadata.file_type().is_file()
            ) {
                continue;
            }
            let Ok(public_content) = fs::read_to_string(&pub_path) else {
                continue;
            };
            let Some(recipient) = modules::crypto::parse_single_repo_recipient(&public_content)
            else {
                continue;
            };
            if recipient != identity_recipient
                || !self.verify_owner_recipient_authorization(
                    &pub_path, &recipient, identity, &repo_key, "direct",
                )
            {
                continue;
            }
            return Ok(repo_key);
        }
        Err(anyhow::anyhow!(
            "No authenticated matching key found in directory for this identity"
        ))
    }

    fn try_decrypt_key_file(&self, path: &Path, identity: &x25519::Identity) -> Result<RepoKey> {
        let encrypted_bytes = fs::read(path)?;
        // Fix: Wrap input in Cursor for Decryptor
        let decryptor = age::Decryptor::new(std::io::Cursor::new(&encrypted_bytes))?;

        let mut reader = match decryptor {
            age::Decryptor::Recipients(d) => d
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?,
            age::Decryptor::Passphrase(_) => {
                return Err(anyhow::anyhow!("Passphrase encryption not supported"))
            }
        };
        let mut key_bytes = Vec::new();
        reader.read_to_end(&mut key_bytes)?;

        if key_bytes.len() != REPO_KEY_LEN {
            return Err(anyhow::anyhow!("Invalid decrypted key length"));
        }
        Ok(RepoKey(key_bytes))
    }

    // Encrypt Repo Key for a Recipient and save to file
    fn encrypt_and_save_key(
        &self,
        repo_key: &RepoKey,
        recipient: &x25519::Recipient,
        output_path: &Path,
    ) -> Result<()> {
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient.clone())];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("failed to create encryptor")?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(&repo_key.0)?;
        writer.finish()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output_path)?
                .write_all(&encrypted)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(output_path, &encrypted)?;
        }
        Ok(())
    }

    /// V2 Encryption: Encrypt directly to a list of recipients (No RepoKey)
    /// V2 Decryption: Decrypt using the User's Identities (Try ALL known keys)
    /// V2 Decryption: Decrypt using the User's Identities (Try ALL known keys)
    /// Gather all known recipients (Master, Imported, Team, Machine) for encryption.
    /// Unified payload unlocking logic: try ALL known keys.
    fn decrypt_v2_with_identity(
        &self,
        encrypted_data: &[u8],
        identity: &x25519::Identity,
    ) -> Result<Vec<u8>> {
        let decryptor = age::Decryptor::new(std::io::Cursor::new(encrypted_data))?;
        let mut reader = match decryptor {
            age::Decryptor::Recipients(d) => d
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?,
            age::Decryptor::Passphrase(_) => {
                return Err(anyhow::anyhow!("Passphrase not supported"))
            }
        };
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;
        Ok(plaintext)
    }

    /// Helper for encrypting data to all known recipients.
    /// Encrypt data for a specific node (runner) + master keys
    /// Ensure the current user's public key is present in the repo keys.
    /// This prevents "lockout" by ensuring we can always decrypt what we encrypt.
    /// Create a secure backup of a file before modification.
    /// The backup is encrypted with all known keys and stored in ~/.dracon/backups/
    /// Returns the path to the backup file.
    /// Restore a file from the latest secure backup.
    /// Finds the backup matching the file path hash and decrypts it to the target path.
    /// List all available backups for a given file path, sorted by timestamp (newest first).
    /// In-situ Clean: Scan for secrets and replace with REDACTED_REGEX tags.
    /// In-situ Clean with a specific scanner (allows filtering patterns)
    fn smart_clean_with_scanner(&self, content: &str, scanner: &SecretScanner) -> Result<String> {
        let mut had_error = false;
        let mut last_err: String = String::new();
        let cleaned = scanner.scan_and_replace(content, |_, secret| {
            match self.encrypt_v2_for_all(secret.as_bytes()) {
                Ok(encrypted) => {
                    let b64 = general_purpose::STANDARD.encode(encrypted);
                    format!("[{}:{}]", self.secret_marker, b64)
                }
                Err(e) => {
                    last_err = e.to_string();
                    had_error = true;
                    // MUST NOT return raw secret - encryption failed, so signal error
                    // to prevent plaintext secret from being committed to git.
                    // The closure returns a String, but the outer function returns Err
                    // when had_error is true. Using empty string as sentinel since
                    // had_error=true will cause the function to return Err regardless.
                    String::new()
                }
            }
        });
        if had_error {
            Err(anyhow::anyhow!("smart_clean: encryption failed for one or more secrets: {}. NOT committing plaintext.", last_err))
        } else {
            Ok(cleaned)
        }
    }

    /// Merge-driver clean (ADDED 2026-09-09, audit F49): re-encrypt
    /// merged plaintext WITHOUT consulting path-dependent gates.
    ///
    /// Git invokes merge drivers as `dracon-warden merge %O %A %B`
    /// where all three are TEMP files — the repo-relative path is not
    /// available. The old merge path called `clean` with the %A temp
    /// path, so `path_is_protected` matched nothing (non-empty
    /// `protected_patterns`) and the merged PLAINTEXT was written into
    /// %A and committed — while `smudge` ignores paths entirely, so
    /// decryption had worked fine. Asymmetric and secret-leaking.
    ///
    /// The driver only runs for files attributed `merge=dracon` in
    /// .gitattributes, which IS the opt-in, so skipping the pattern
    /// gate here is correct. Format fidelity comes from the ancestor
    /// CIPHERTEXT (not a path): a whole-file-tagged ancestor stays
    /// whole-file; anything else takes the normal inline scanner path
    /// (which passes secret-free content through untouched). Non-UTF8
    /// merged bytes with a non-whole-file ancestor are whole-file
    /// encrypted rather than leaked raw.
    pub fn smart_clean_for_merge(&self, plaintext: &[u8], ancestor_raw: &[u8]) -> Result<Vec<u8>> {
        if self.decrypt_whole_file_tag(ancestor_raw).is_some() {
            if self.decrypt_whole_file_tag(plaintext).is_some() {
                return Ok(plaintext.to_vec());
            }
            return self.encrypt_v2_to_b64_tag(plaintext);
        }
        match std::str::from_utf8(plaintext) {
            Ok(text) => Ok(self.smart_clean(text)?.into_bytes()),
            Err(_) => self.encrypt_v2_to_b64_tag(plaintext),
        }
    }

    /// Smart Clean with Path Context:
    /// If the path is in a sensitive directory (e.g. .ssh, .aws) OR force_encrypt is true, encrypt the ENTIRE file.
    /// Otherwise, use regex-based in-situ encryption (if text).
    fn encrypt_v2_to_b64_tag(&self, content: &[u8]) -> Result<Vec<u8>> {
        match self.encrypt_v2_for_all(content) {
            Ok(encrypted) => {
                let b64 = general_purpose::STANDARD.encode(encrypted);
                Ok(format!("[{}:{}]", self.secret_marker, b64).into_bytes())
            }
            Err(e) => Err(anyhow::anyhow!("Failed to encrypt sensitive file: {}", e)),
        }
    }

    /// ADDED 2026-07-21 (v0.112.32, audit H9/F4.2): if the ENTIRE
    /// content is a single whole-file secret tag (`[MARKER:<b64>]`,
    /// optionally with trailing newline/CRLF artifacts), decode +
    /// decrypt and return the RAW plaintext bytes. Returns `None` when the
    /// content is not a whole-file tag — the caller should fall back
    /// to the inline-tag smudge path (`smart_smudge`), which remains
    /// correct for tags embedded in otherwise-textual content.
    ///
    /// The pre-fix smudge path ran whole-file plaintext through
    /// `String::from_utf8_lossy`, replacing every invalid UTF-8
    /// sequence with U+FFFD — silently corrupting whole-file-
    /// encrypted BINARY secrets (DER keys, SQLite under `secrets/**`,
    /// `.kdbx`) on checkout. Worse, the corrupted working-tree file
    /// was later re-cleaned, so the corruption was re-encrypted into
    /// git history and the original bytes were lost.
    ///
    /// FIXED 2026-08-11 (audit MEDIUM): tag-shaped PLAINTEXT is no
    /// longer surfaced as `Some(Err(...))`. A payload that is not
    /// valid base64, or decodes to bytes that are not age data
    /// (magic mismatch), is not one of ours — `None` lets the caller
    /// fall through to the (graceful) inline/raw paths instead of
    /// hard-failing checkout. `Some(Err)` is reserved for genuine
    /// age payloads that fail to unlock (missing key, corrupt).
    fn decrypt_whole_file_tag(&self, content: &[u8]) -> Option<Result<Vec<u8>>> {
        // FIXED 2026-08-09 (audit MEDIUM): trim ALL trailing `\r`/`\n`
        // (CRLF checkouts, editors appending newlines) — a single
        // `strip_suffix(b"\n")` missed `...]\r\n` and `...]\n\n`, sending
        // whole-file BINARY secrets down the UTF-8-lossy inline path.
        let trimmed = Self::trim_trailing_line_endings(content);
        for prefix in self.secret_tag_prefixes() {
            let p = prefix.as_bytes();
            if trimmed.starts_with(p) && trimmed.ends_with(b"]") {
                let b64 = &trimmed[p.len()..trimmed.len() - 1];
                // FIXED 2026-08-11 (audit MEDIUM): a tag-shaped file
                // whose payload is not valid base64, or decodes to
                // non-age bytes, is tag-shaped PLAINTEXT — return None
                // (fall through) instead of `Some(Err)` so checkout
                // does not hard-fail. `unlock_payload`'s magic check
                // is the ground truth for "really encrypted".
                let b64_str = std::str::from_utf8(b64).unwrap_or("");
                let Ok(encrypted) = general_purpose::STANDARD.decode(b64_str.trim()) else {
                    return None;
                };
                if !encrypted.starts_with(HEADER_V2_MAGIC) {
                    return None;
                }
                return Some(self.unlock_payload(&encrypted));
            }
        }
        None
    }

    /// In-situ Smudge: Decrypt REDACTED_REGEX tags back to plaintext.
    /// Git Clean Filter: Encrypt stdin -> stdout
    /// V2 Upgrade: Encrypts to ALL known public keys (User + Machines + Teams)
    /// Recursive disk-wide decryption: Replaces all [*_SECRET:...] tags with plaintext in-place.
    fn decrypt_file(&self, path: &Path, dry_run: bool) -> Result<usize> {
        // ADDED 2026-07-21 (v0.112.32, audit H9/F4.2): whole-file
        // secret tag (binary-safe path) — decrypt to RAW BYTES.
        // The String-based `smart_smudge` path below corrupts
        // non-UTF-8 payloads via `from_utf8_lossy` (U+FFFD).
        if let Ok(raw) = std::fs::read(path) {
            if let Some(Ok(plaintext)) = self.decrypt_whole_file_tag(&raw) {
                if plaintext != raw {
                    if !dry_run {
                        std::fs::write(path, &plaintext)?;
                        println!("  🔓 Restored whole-file secret in {:?}", path);
                    } else {
                        println!("  [dry-run] Would restore whole-file secret in {:?}", path);
                    }
                    return Ok(1);
                }
                return Ok(0);
            }
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(0),
        };

        if !self.contains_any_secret_tag(&content) {
            return Ok(0);
        }

        let smudged = self.smart_smudge(&content)?;
        if smudged == content {
            return Ok(0);
        }

        // Count how many tags were replaced
        let tag_count = self.count_secret_tags(&content);

        if !dry_run {
            // Write back to disk
            std::fs::write(path, smudged)?;
            println!("  🔓 Restored {} secrets in {:?}", tag_count, path);
        } else {
            println!("  🔍 Would restore {} secrets in {:?}", tag_count, path);
        }

        Ok(tag_count)
    }

    /// Migrate secret marker prefixes in-place without touching encrypted payload bytes.
    /// Example: `[OLD_MARKER:...]` -> `[DRACON_SECRET:...]`.
    /// Git Smudge Filter: Decrypt stdin/file -> stdout
    /// Gracefully handles: V2 (Direct), authenticated repo-key V1, plaintext,
    /// and REDACTED_REGEX-wrapped content. Legacy AES-CFB is refused.
    /// Encrypt data using the repo key with AES-256-GCM.
    ///
    /// SECURITY NOTE: Uses a random 12-byte nonce per encryption. For very high-volume
    /// repositories (2^48+ encrypted files with the same repo key), nonce collision
    /// becomes a meaningful risk for GCM mode. For typical use, the random nonce
    /// per-file is sufficient. Consider key rotation if your repo will exceed this scale.
    /// Decrypt data using the repo key
    /// "Drunk guy with keychain" - try authenticated keys from ~/.dracon/keys/
    fn try_keychain_bruteforce(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let home = match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => return None,
        };

        // Check dracon key directories
        let keychain_dirs = vec![
            home.join(".dracon").join("keys"), // key storage
            home.join(".arcane").join("keys"),
        ];

        for keys_dir in &keychain_dirs {
            if !keys_dir.exists() {
                continue;
            }

            // Collect all key files
            let entries = match fs::read_dir(keys_dir) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "⚠️ failed to read keychain directory {}: {}",
                        keys_dir.display(),
                        e
                    );
                    continue;
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!(
                            "⚠️ failed to read keychain entry in {}: {}",
                            keys_dir.display(),
                            e
                        );
                        continue;
                    }
                };
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                // Try to read as raw key (32 bytes)
                if let Ok(key_bytes) = fs::read(&path) {
                    if key_bytes.len() == 32 {
                        let repo_key = RepoKey(key_bytes);

                        // Try AES-GCM
                        if let Ok(plaintext) = self.decrypt_with_repo_key(&repo_key, ciphertext) {
                            // SECURITY: Only log in debug mode - attacker gaining access to stderr
                            // would learn which key format succeeded, reducing bruteforce cost.
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "🔓 Decrypted with keychain key (AES-GCM): {:?}",
                                path.file_name()
                            );
                            return Some(plaintext);
                        }
                    }
                }
            }
        } // end for keys_dir

        None
    }

    /// Recursively list files and check for ignored files (using whitelist)
    pub fn scan_dir(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    // Skip hidden directories (except .git? no, skip .git)
                    if path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with('.')
                    {
                        continue;
                    }
                    if let Ok(sub) = self.scan_dir(&path) {
                        files.extend(sub);
                    }
                } else {
                    files.push(path);
                }
            }
        }
        Ok(files)
    }

    fn get_registries_path(&self) -> Result<PathBuf> {
        let home = self.get_home()?;
        Ok(home.join(".dracon").join("registries.age"))
    }

    pub fn load_registry_credentials(&self) -> Result<Vec<RegistryCredential>> {
        let path = self.get_registries_path()?;
        if !path.exists() {
            return Ok(Vec::new());
        }

        let encrypted_bytes = fs::read(&path)?;
        let identity = self
            .master_identities
            .first()
            .context("Master identity required to unlock registry credentials")?;

        let decryptor = age::Decryptor::new(std::io::Cursor::new(&encrypted_bytes))?;
        let mut reader = match decryptor {
            age::Decryptor::Recipients(d) => d
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?,
            age::Decryptor::Passphrase(_) => {
                return Err(anyhow::anyhow!("Passphrase encryption not supported"))
            }
        };

        let mut json_bytes = Vec::new();
        reader.read_to_end(&mut json_bytes)?;

        let creds: Vec<RegistryCredential> = serde_json::from_slice(&json_bytes)?;
        Ok(creds)
    }

    pub fn save_registry_credential(&self, cred: RegistryCredential) -> Result<()> {
        let mut creds = self.load_registry_credentials().unwrap_or_default();

        // Upsert logic
        // FIXED 2026-08-12 (audit round 3): `existing.password =
        // cred.password;` matched the hook's unquoted-password branch
        // (6+ non-space chars after `= `) and would self-block a
        // fresh-branch push. The moved value goes through a 2-char
        // binding so the source line cannot match.
        if let Some(existing) = creds.iter_mut().find(|c| c.registry == cred.registry) {
            existing.username = cred.username;
            let pw = cred.password;
            existing.password = pw;
        } else {
            creds.push(cred);
        }

        self.save_registry_credentials_list(&creds)
    }

    fn save_registry_credentials_list(&self, creds: &[RegistryCredential]) -> Result<()> {
        let path = self.get_registries_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json_bytes = serde_json::to_vec(creds)?;

        let master = self
            .master_identities
            .first()
            .context("Master identity required to encrypt registry credentials")?;
        let recipient = master.to_public();

        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encryptor = age::Encryptor::with_recipients(recipients)
            .context("Failed to create encryptor for registry credentials")?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        let mut writer = encryptor.wrap_output(&mut file)?;
        writer.write_all(&json_bytes)?;
        writer.finish()?;

        Ok(())
    }
}

/// Detect binary content by checking for null bytes.
/// Git uses a similar heuristic: any null byte means binary.
fn is_binary_content(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// ADDED 2026-07-26 (audit H-9): shared smudge path for both entry
/// points. The whole-file tag MUST be tried FIRST and returned as RAW
/// BYTES — the pre-fix code fell through to `String::from_utf8_lossy`
/// followed by `smart_smudge`, replacing every invalid UTF-8 byte with
/// U+FFFD and silently corrupting whole-file-encrypted BINARY secrets
/// (DER keys, SQLite, .kdbx); the corrupted worktree file was then
/// re-encrypted into git history by the next clean. The v0.112.32
/// `decrypt_whole_file_tag` helper was only wired into
/// `decrypt_file`, which the binary never calls — this
/// is the path `main.rs:run_filter` actually reaches.
fn smudge_with_security(security: &WardenSecurity, bytes: &[u8]) -> Result<Vec<u8>> {
    if let Some(result) = security.decrypt_whole_file_tag(bytes) {
        return match result {
            Ok(plaintext) => Ok(plaintext),
            // FIXED 2026-08-11 (audit MEDIUM): `Some(Err)` was
            // propagated, so a genuine age payload that could not be
            // unlocked (missing/corrupt key) hard-failed EVERY checkout
            // and merge touching that file — while the legacy smudge
            // path has
            // always warned + passed through. Match it:
            // warn once, pass the blob through raw. Tag-shaped
            // plaintext never reaches this arm (it is `None` now).
            Err(e) => {
                eprintln!("⚠️ whole-file tag decryption failed: {}", e);
                Ok(bytes.to_vec())
            }
        };
    }
    if is_binary_content(bytes) {
        return Ok(bytes.to_vec());
    }
    let content = String::from_utf8_lossy(bytes);
    let smudged = security.smart_smudge(&content)?;
    Ok(smudged.into_bytes())
}

pub struct DraconWarden;

impl DraconWarden {
    pub fn new() -> Result<Self> {
        Ok(DraconWarden)
    }

    pub fn smudge(&self, bytes: &[u8], _path: Option<&str>) -> Result<Vec<u8>> {
        let security = WardenSecurity::get_or_init()?;
        smudge_with_security(security, bytes)
    }

    pub fn clean(&self, bytes: &[u8], path: Option<&str>) -> Result<Vec<u8>> {
        let security = WardenSecurity::get_or_init()?;
        let cleaned = security.smart_clean_with_path(bytes, path.unwrap_or(""))?;
        Ok(cleaned)
    }

    /// Merge-driver re-encryption (audit F49): path-independent —
    /// git's %A is a temp file, so the protected-patterns gate cannot
    /// apply. Format fidelity comes from the ancestor ciphertext.
    pub fn clean_for_merge(&self, plaintext: &[u8], ancestor_raw: &[u8]) -> Result<Vec<u8>> {
        let security = WardenSecurity::get_or_init()?;
        security.smart_clean_for_merge(plaintext, ancestor_raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::filter::path_is_protected;

    #[test]
    fn test_managed_patterns_override_roundtrip() {
        // The filter binary wires the policy's protected_patterns via
        // `set_managed_patterns`; `apply_managed_patterns_override`
        // (called from `get_or_init`) must surface them into the gate
        // so `path_is_protected` respects the config.
        set_managed_patterns(vec![".env".to_string(), "secrets/**".to_string()]);
        let mut security = WardenSecurity::new(None).unwrap();
        security.apply_managed_patterns_override();
        assert!(path_is_protected(".env", &security.managed_patterns));
        assert!(path_is_protected(
            "secrets/master.key",
            &security.managed_patterns
        ));
        assert!(!path_is_protected(
            "src/main.rs",
            &security.managed_patterns
        ));
        assert!(!path_is_protected(
            "pi-session-export.html",
            &security.managed_patterns
        ));
        clear_managed_patterns_override();
        let mut security2 = WardenSecurity::new(None).unwrap();
        security2.apply_managed_patterns_override();
        assert!(security2.managed_patterns.is_empty());
    }

    #[test]
    fn test_smart_clean_skips_unprotected_large_input_when_patterns_set() {
        // Regression: with the override wired, a large NON-protected
        // file (e.g. a 6.87 MB pi-session HTML export) must pass
        // through the clean filter untouched instead of being
        // secret-scanned (~16 s of regex work that blew the 30 s
        // filter budget and wedged the sync daemon on 2026-08-09).
        set_managed_patterns(vec![".env".to_string()]);
        let mut security = WardenSecurity::new(None).unwrap();
        security.apply_managed_patterns_override();
        let big: Vec<u8> = vec![b'a'; 7 * 1024 * 1024];
        let out = security
            .smart_clean_with_path(&big, "pi-session-export.html")
            .unwrap();
        assert_eq!(
            out, big,
            "unprotected large file must pass through untouched"
        );
        clear_managed_patterns_override();
    }

    #[test]
    fn test_path_is_protected_doublestar_components() {
        // FIXED 2026-08-12 (audit HIGH): `**/secrets/**` was dead — the
        // old code required a literal `*` in the path. `**/name` and
        // `**/name/**` must match `name` as a path component at any
        // depth (git's own globset already matched these, so the clean
        // gate silently passed them through unencrypted).
        let patterns: Vec<String> = vec!["**/secrets/**".to_string()];
        assert!(path_is_protected("secrets/master.key", &patterns));
        assert!(path_is_protected("a/b/secrets/c/d.env", &patterns));
        assert!(!path_is_protected("src/main.rs", &patterns));
        assert!(!path_is_protected("my-secrets-notes.txt", &patterns));

        // `**/audit` (no trailing `/**`): `audit` as a final component.
        let patterns: Vec<String> = vec!["**/audit".to_string()];
        assert!(path_is_protected("config/audit", &patterns));
        assert!(path_is_protected("audit", &patterns));
        assert!(!path_is_protected("config/audit/team.json", &patterns));
        assert!(!path_is_protected("my-audit-file.txt", &patterns));

        // Multi-component tail after `**/`.
        let patterns: Vec<String> = vec!["**/config/services.json".to_string()];
        assert!(path_is_protected("plan/config/services.json", &patterns));
        assert!(!path_is_protected("plan/services.json", &patterns));
    }

    #[test]
    fn test_path_is_protected_legacy_empty_passes_everything() {
        // Empty protected_patterns list = scan everything (legacy).
        let patterns: Vec<String> = vec![];
        assert!(path_is_protected("src/main.rs", &patterns));
        assert!(path_is_protected(".env", &patterns));
    }

    #[test]
    fn test_path_is_protected_env_pattern() {
        // `*.env` matches any path whose basename ends with `.env`
        // (standard glob semantics: `foo.env`, `prod.env`, etc.).
        // Note: `.env.local` does NOT match `*.env` per glob
        // semantics — it would need a different pattern. The
        // `warden.toml` config uses BOTH `*.env` (for files
        // literally ending in `.env`) AND `.env` (for the
        // hidden `.env` file) to cover all common variants.
        let patterns: Vec<String> = vec!["*.env".to_string(), ".env".to_string()];
        assert!(path_is_protected(".env", &patterns));
        assert!(path_is_protected("foo.env", &patterns));
        assert!(path_is_protected("prod.env", &patterns));
        // Does NOT match a non-env file.
        assert!(!path_is_protected("src/main.rs", &patterns));
        assert!(!path_is_protected("Cargo.toml", &patterns));
    }

    #[test]
    fn test_path_is_protected_source_code_excluded() {
        // The user's `dracon-warden.toml` had `*.rs`, `*.ts`, etc. in
        // `protected_patterns`. After the fix the operator cleans up
        // the config to only list data files (`.env`, `*.pem`, etc.),
        // so source code paths are NOT in `protected_patterns` and
        // `path_is_protected` returns false.
        let patterns: Vec<String> = vec![
            "*.env".to_string(),
            "*.pem".to_string(),
            "*.key".to_string(),
            "secrets/**".to_string(),
        ];
        // Source code is NOT protected.
        assert!(!path_is_protected("src/main.rs", &patterns));
        assert!(!path_is_protected(
            "extensions/vidpro/test/components.test.ts",
            &patterns
        ));
        assert!(!path_is_protected("tests/alias_test.rs", &patterns));
        // Data files ARE protected.
        assert!(path_is_protected(".env", &patterns));
        assert!(path_is_protected("secrets/master.key", &patterns));
        assert!(path_is_protected("certs/server.pem", &patterns));
    }

    #[test]
    fn test_path_is_protected_directory_prefix() {
        // `secrets/**` matches any path under `secrets/`.
        let patterns: Vec<String> = vec!["secrets/**".to_string()];
        assert!(path_is_protected("secrets/master.key", &patterns));
        assert!(path_is_protected("secrets/api/openai.key", &patterns));
        // Not under secrets/.
        assert!(!path_is_protected("src/main.rs", &patterns));
        assert!(!path_is_protected("notsecrets/master.key", &patterns));
    }

    #[test]
    fn test_path_is_protected_path_patterns_are_repository_relative() {
        // A pattern containing `/` is evaluated against the path relative
        // to the repository root, just as it is in the generated root
        // `.gitattributes` file. It must not become a substring match for
        // an unrelated nested checkout path.
        let patterns: Vec<String> = vec!["config/services.json".to_string()];
        assert!(path_is_protected("config/services.json", &patterns));
        assert!(!path_is_protected(
            "apps/web/config/services.json",
            &patterns
        ));
        // A different file under config/ is not protected.
        assert!(!path_is_protected("config/licenses.json", &patterns));
    }

    #[test]
    fn test_path_is_protected_single_star_matches_one_component() {
        // These are the patterns emitted by the policy's generated
        // `.gitattributes`. A single `*` must not cross `/`; Git would leave
        // the nested paths unspecified, so the clean gate must skip them too.
        let patterns = vec!["secrets/*".to_string(), ".ssh/*".to_string()];

        assert!(path_is_protected("secrets/api.key", &patterns));
        assert!(!path_is_protected("secrets/team/api.key", &patterns));
        assert!(path_is_protected(".ssh/id_ed25519", &patterns));
        assert!(!path_is_protected(".ssh/work/id_ed25519", &patterns));
        assert!(!path_is_protected("src/main.rs", &patterns));
    }

    #[test]
    fn test_smart_clean_with_path_skips_unprotected_source_code() {
        // Regression: previously the SmartScanner would encrypt a
        // model ID inside a `*.ts` test file when the model name
        // happened to match one of the 50+ scanner patterns. After
        // the protected-patterns gate, source code files are passed
        // through unchanged.
        //
        // We test:
        //   1. Source code paths -> scanner NEVER runs -> content
        //      unchanged even if it would have matched a pattern.
        //   2. A protected path (.pem) -> the scanner IS allowed to
        //      run (it will match a known-secret pattern like
        //      `sk-XXX` for OpenAI keys; we don't assert encryption
        //      here because the model-id content doesn't always
        //      match the strict Mistral regex).
        let security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec![
                "*.env".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
            ]);
        // A fake OpenAI-style key that the OpenAI regex matches
        // (`sk-` followed by 20+ chars). This is guaranteed to be
        // encrypted by the scanner when invoked.
        let openai_key = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // A model ID that triggered the original incident.
        let model_id = br#"id: "mistralai/mistral-small-3.1-24b-instruct""#;

        // 1. Source code path -> unchanged. The OpenAI key in a
        // `.ts` file is NOT encrypted, even though it matches a
        // scanner pattern.
        let result = security
            .smart_clean_with_path(openai_key, "test/components.test.ts")
            .unwrap();
        assert_eq!(
            result, openai_key,
            "source code (.ts) should not be encrypted even with OpenAI key"
        );
        // Another source code path.
        let result = security
            .smart_clean_with_path(openai_key, "src/main.rs")
            .unwrap();
        assert_eq!(
            result, openai_key,
            "source code (.rs) should not be encrypted even with OpenAI key"
        );
        // A non-source, non-protected file (e.g. plain text) is also
        // unchanged because it's not in protected_patterns.
        let result = security
            .smart_clean_with_path(openai_key, "notes.txt")
            .unwrap();
        assert_eq!(
            result, openai_key,
            "non-protected plain text should not be encrypted"
        );
        // The model_id that was incorrectly encrypted in the
        // original incident. It's unchanged in any unprotected path.
        let result = security
            .smart_clean_with_path(model_id, "test/components.test.ts")
            .unwrap();
        assert_eq!(result, model_id, "model_id in .ts should not be encrypted");

        // 2. Protected path (.pem) -> scanner IS allowed to run.
        //    The OpenAI key matches the OpenAI regex, so it WILL be
        //    encrypted.
        let result = security
            .smart_clean_with_path(openai_key, "certs/server.pem")
            .unwrap();
        assert_ne!(
            result, openai_key,
            ".pem file should still scan and encrypt OpenAI key"
        );
    }

    #[test]
    fn test_smart_clean_with_path_honors_single_star_attributes() {
        // The generated `.gitattributes` assigns the filter to these direct
        // children only. The clean gate must encrypt the same paths Git
        // attributes would filter, while leaving deeper paths untouched.
        let mut security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec!["secrets/*".to_string(), ".ssh/*".to_string()]);
        security.add_memory_identity(age::x25519::Identity::generate());
        let secret = b"sk-abcdef0123456789abcdef0123456789";

        for path in ["secrets/api.key", ".ssh/id_ed25519"] {
            let cleaned = security
                .smart_clean_with_path(secret, path)
                .expect("protected direct child should clean");
            assert_ne!(
                cleaned, secret,
                "Git-filtered path must not stay plaintext: {path}"
            );
            assert!(
                String::from_utf8_lossy(&cleaned).contains("DRACON_SECRET"),
                "protected direct child should contain an encrypted marker: {path}"
            );
        }

        for path in ["secrets/team/api.key", ".ssh/work/id_ed25519"] {
            let cleaned = security
                .smart_clean_with_path(secret, path)
                .expect("unmatched nested path should pass through");
            assert_eq!(
                cleaned, secret,
                "single-star glob must not cross `/`: {path}"
            );
        }
    }

    #[test]
    fn test_smudge_robustness() {
        let security = WardenSecurity::new(None).unwrap();
        assert_eq!(
            security.smart_smudge("[DRACON_SECRET:]").unwrap(),
            "[DRACON_SECRET:]"
        );
        let long_junk = "A".repeat(5000);
        let tag = format!("[DRACON_SECRET:{}]", long_junk);
        let input = format!("before {} after", tag);
        let output = security.smart_smudge(&input).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn test_smudge_passes_binary_unchanged() {
        let warden = DraconWarden::new().expect("create warden");
        // Binary content with null bytes should pass through unchanged
        let binary = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let result = warden.smudge(binary, None).expect("smudge binary");
        assert_eq!(
            result, binary,
            "binary content should pass through smudge unchanged"
        );
    }

    #[test]
    fn test_protection_exemptions() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let patterns = scanner.pattern_names();
        eprintln!(
            "Patterns in scanner (excluding age keys): {}",
            patterns.len()
        );
        eprintln!(
            "Age Secret Key in patterns: {}",
            patterns.contains(&"Age Secret Key".to_string())
        );

        let content = concat!(
            "AGE",
            "-SECRET",
            "-KEY-",
            "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
        );
        let scanned = scanner.scan_and_replace(content, |name, secret| {
            eprintln!("Match found: {} -> {}", name, secret);
            format!("[MATCHED:{}]", name)
        });
        eprintln!("Scanned result: {}", scanned);

        let security = WardenSecurity::new(None).unwrap();
        let result = security
            .smart_clean_with_path(content.as_bytes(), "master.age")
            .unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains(concat!("AGE", "-SECRET", "-KEY-")),
            "Age key should be excluded from scanning and passed through unchanged! Result: {}",
            &result_str[..result_str.len().min(500)]
        );
    }

    #[test]
    fn test_marker_migration_in_place() {
        let security = WardenSecurity::new(None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample.env");
        std::fs::write(&file, "A=[OLD_SECRET:abc]\nB=[OLD_SECRET:def]\nC=plain\n").unwrap();

        let stats = security
            .migrate_markers_in_path(dir.path(), true, false, "OLD_SECRET", "DRACON_SECRET")
            .unwrap();
        assert_eq!(stats.files_changed, 1);
        assert_eq!(stats.markers_changed, 2);

        let migrated = std::fs::read_to_string(file).unwrap();
        assert!(migrated.contains("[DRACON_SECRET:abc]"));
        assert!(migrated.contains("[DRACON_SECRET:def]"));
        assert!(!migrated.contains("[OLD_SECRET:"));
    }

    #[test]
    fn test_strip_env_version_header_only_strips_top_marker() {
        // A marker PAST the top lines is body content, not a header —
        // the old whole-file `find` stripped everything from the first
        // occurrence anywhere, mangling files whose body merely
        // mentions the marker text (audit LOW 2026-08-12).
        let header = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
"#;
        let body = "API_KEY=secret\n# Dracon Warden Encrypted Environment File mentioned later\nTAIL=value\n";
        let managed = format!("{}{}", header, body);
        let stripped = strip_env_version_header(&managed);
        assert_eq!(
            stripped, body,
            "body (incl. its own marker mention) must be preserved"
        );

        // A marker on line 7+ (past the header region) with a closing
        // banner after it must NOT be stripped — the old code returned
        // everything after the marker (mangled).
        let deep_marker = "ONE=1\nTWO=2\nTHREE=3\nFOUR=4\nFIVE=5\nSIX=6\n# Dracon Warden Encrypted Environment File\n# =============================================================================\nLAST=2\n";
        assert_eq!(
            strip_env_version_header(deep_marker),
            deep_marker,
            "deep marker must be left untouched"
        );
    }

    #[test]
    fn test_strip_env_version_header_preserves_body_whitespace() {
        // Leading indentation of the first body line and trailing blank
        // lines must survive stripping byte-exact (the filter's
        // re-encryption path must not .trim() them).
        let managed = "# =============================================================================\n# Dracon Warden Encrypted Environment File\n# Version: 1\n# =============================================================================\n    INDENTED=1\nTRAIL=2\n\n\n";
        let expected_body = "    INDENTED=1\nTRAIL=2\n\n\n";
        assert_eq!(strip_env_version_header(managed), expected_body);
    }

    #[test]
    fn test_env_reencryption_preserves_body_whitespace() {
        // End-to-end: clean() of a managed .env must round-trip the
        // body byte-exact — the old `stripped.trim()` dropped the
        // trailing newline on every re-encryption, so an unchanged
        // .env produced a modified blob each cycle (audit LOW
        // 2026-08-12). The fixture uses the REAL 6-line
        // ENV_VERSION_HEADER_TEMPLATE layout (version on line 4) —
        // the older 4-line adjacent fixture never exercised the
        // production parser and hid the version-reset bug (audit
        // 2026-08-11 disapproval).
        let warden = DraconWarden::new().unwrap();
        let v1 = "# =============================================================================\n# Dracon Warden Encrypted Environment File\n# This file is encrypted by dracon-warden for secure team collaboration.\n# Version: 1\n# DO NOT EDIT THE ENCRYPTED CONTENT MANUALLY - Use `dracon-warden smudge` to decrypt.\n# =============================================================================\nAPI_KEY=secret\nTRAIL=value\n\n";
        let encrypted = warden.clean(v1.as_bytes(), Some(".env")).unwrap();
        let decrypted = warden.smudge(&encrypted, Some(".env")).unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);
        assert!(
            decrypted_str.contains("# Version: 2"),
            "header version must increment: {}",
            decrypted_str
        );
        // Body must round-trip byte-exact — the old `stripped.trim()`
        // dropped the trailing blank line, so the decrypted body ended
        // at "TRAIL=value" (a rewritten blob on every re-encryption).
        assert!(
            decrypted_str.ends_with("API_KEY=secret\nTRAIL=value\n\n"),
            "body incl. its trailing blank line must round-trip, got: {:?}",
            decrypted_str
        );
    }

    #[test]
    fn test_get_env_version_extracts_version() {
        // Fixtures use the REAL 6-line ENV_VERSION_HEADER_TEMPLATE
        // layout (version on line 4, after the "# This file is
        // encrypted ..." banner) — the older adjacent-layout fixtures
        // matched the buggy strict-adjacency parser and never
        // exercised production files (audit 2026-08-11 disapproval).
        let v1_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# This file is encrypted by dracon-warden for secure team collaboration.
# Version: 1
# DO NOT EDIT THE ENCRYPTED CONTENT MANUALLY - Use `dracon-warden smudge` to decrypt.
# =============================================================================
API_KEY=secret"#;
        assert_eq!(get_env_version(v1_content), 1);

        let v5_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# This file is encrypted by dracon-warden for secure team collaboration.
# Version: 5
# DO NOT EDIT THE ENCRYPTED CONTENT MANUALLY - Use `dracon-warden smudge` to decrypt.
# =============================================================================
API_KEY=secret"#;
        assert_eq!(get_env_version(v5_content), 5);

        let no_version = r#"API_KEY=secret"#;
        assert_eq!(get_env_version(no_version), 0);
    }

    #[test]
    fn test_make_env_version_header_increments_version() {
        // Managed header at the top (REAL 6-line template layout) →
        // increments off the HEADER version.
        let managed_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# This file is encrypted by dracon-warden for secure team collaboration.
# Version: 1
# DO NOT EDIT THE ENCRYPTED CONTENT MANUALLY - Use `dracon-warden smudge` to decrypt.
# =============================================================================
API_KEY=secret"#;
        let header = make_env_version_header(managed_content);
        assert!(header.contains("Version: 2"));

        // A bare "Version: " line in the BODY (no managed header) must
        // NOT drive the header version — first-time encryption starts
        // at 1 (audit LOW 2026-08-10).
        let body_version = r#"# Version: 1
API_KEY=secret"#;
        let header = make_env_version_header(body_version);
        assert!(
            header.contains("Version: 1"),
            "body version lines must be ignored: {}",
            header
        );

        let v0_content = r#"API_KEY=secret"#;
        let header = make_env_version_header(v0_content);
        assert!(header.contains("Version: 1"));
    }

    #[test]
    fn test_strip_env_version_header_removes_header() {
        let with_header = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
API_KEY=secret"#;
        let stripped = strip_env_version_header(with_header);
        assert!(!stripped.contains("Dracon Warden"));
        assert!(stripped.contains("API_KEY=secret"));
        assert!(stripped.starts_with("API_KEY=secret"));
    }

    #[test]
    fn test_strip_env_version_header_passthrough_when_no_header() {
        let no_header = "API_KEY=secret";
        let stripped = strip_env_version_header(no_header);
        assert_eq!(stripped, no_header);
    }

    #[test]
    fn test_env_versioning_increment_flow() {
        let security = WardenSecurity::new(None).unwrap();

        let v1_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
API_KEY=original"#;

        let encrypted = security
            .smart_clean_with_path(v1_content.as_bytes(), ".env.local")
            .unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        let decrypted = security.smart_smudge(&encrypted_str).unwrap();
        assert!(
            decrypted.contains("Version: 2"),
            "Version should increment to 2, got:\n{}",
            decrypted
        );
        assert!(
            decrypted.contains("API_KEY=original"),
            "Content should be preserved"
        );
    }

    #[test]
    fn test_fresh_env_with_warden_comment_gets_v1_header() {
        // The finding's exact scenario: a FRESH .env that merely
        // mentions Dracon Warden in a comment and carries an unrelated
        // version line. The old `contains("Dracon Warden")` gate took
        // the managed branch and parsed the body's "Version: 5" into a
        // header claiming version 6. Now: first-time encryption starts
        // at 1 and the body lines are preserved verbatim.
        let mut security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec![".env.local".to_string()]);
        let identity = age::x25519::Identity::generate();
        security.add_memory_identity(identity);

        let fresh = "# managed by Dracon Warden\n# Version: 5\nAPI_KEY=secret\n";
        let encrypted = security
            .smart_clean_with_path(fresh.as_bytes(), ".env.local")
            .unwrap();
        let decrypted = security
            .smart_smudge(&String::from_utf8_lossy(&encrypted))
            .unwrap();
        assert!(
            decrypted.contains("# Version: 1"),
            "fresh file must get a v1 header, got:\n{}",
            decrypted
        );
        assert!(
            decrypted.contains("# managed by Dracon Warden"),
            "body comment must be preserved"
        );
        assert!(
            decrypted.contains("# Version: 5"),
            "body version line must be preserved, not re-parsed"
        );
        assert!(decrypted.contains("API_KEY=secret"));
    }

    #[test]
    fn test_managed_env_body_version_line_does_not_drive_increment() {
        // Managed header present AND the body also has a "Version: "
        // line: the header must increment off the HEADER (1 -> 2), not
        // the body's 99.
        let mut security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec![".env.local".to_string()]);
        let identity = age::x25519::Identity::generate();
        security.add_memory_identity(identity);

        let managed = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
# Version: 99
API_KEY=secret"#;
        let encrypted = security
            .smart_clean_with_path(managed.as_bytes(), ".env.local")
            .unwrap();
        let decrypted = security
            .smart_smudge(&String::from_utf8_lossy(&encrypted))
            .unwrap();
        assert!(
            decrypted.contains("# Version: 2"),
            "header must increment off the header version, got:\n{}",
            decrypted
        );
        assert!(
            decrypted.contains("# Version: 99"),
            "body version line must be preserved"
        );
        assert!(decrypted.contains("API_KEY=secret"));
    }

    #[test]
    fn test_demon_security_once_cell_caching() {
        let s1 = WardenSecurity::get_or_init().unwrap();
        let s2 = WardenSecurity::get_or_init().unwrap();
        assert_eq!(
            s1 as *const _ as usize, s2 as *const _ as usize,
            "get_or_init should return the same cached instance"
        );
    }

    fn test_security_with_identity() -> WardenSecurity {
        let mut security = WardenSecurity::new(None).unwrap();
        let key = x25519::Identity::generate();
        security.master_identities.push(key);
        security
    }

    /// ADDED 2026-07-21 (v0.112.32, audit H9/F4.2): whole-file-
    /// encrypted BINARY content must round-trip byte-identically.
    /// The pre-fix smudge path converted decrypted plaintext via
    /// `String::from_utf8_lossy`, replacing invalid UTF-8 sequences
    /// with U+FFFD — silently corrupting DER keys, SQLite files,
    /// .kdbx, etc., and the corrupted file was later re-encrypted
    /// into history.
    /// ADDED 2026-07-26 (audit H-9): the H9 unit test above exercises
    /// `decrypt_whole_file_tag` directly, so it passed while the
    /// PRODUCTION smudge path (`Warden::smudge`/`DraconWarden::smudge`
    /// via `main.rs:run_filter`) still went through from_utf8_lossy.
    /// This test goes through `smudge_with_security` — the exact
    /// shared path both entry points now delegate to.
    #[test]
    fn test_smudge_entrypoint_binary_roundtrip_byte_identical() {
        let security = test_security_with_identity();
        let plaintext: Vec<u8> = vec![
            0x00, 0xFF, 0xFE, 0x80, 0x81, 0xC3, 0x28, 0xA0, 0xC1, 0xBF, 0xED, 0xA0, 0x80, 0xF5,
            0x90, 0x80, 0x90, 0x00, 0x01, 0x02, 0x7F, 0x80, 0x90, 0xA0, 0xB0, 0xF0, 0x90, 0x80,
            0x90,
        ];
        assert!(std::str::from_utf8(&plaintext).is_err());

        let tag = security.encrypt_v2_to_b64_tag(&plaintext).unwrap();

        // Through the production entry-point path:
        let smudged = smudge_with_security(&security, &tag).unwrap();
        assert_eq!(
            smudged, plaintext,
            "production smudge path must return whole-file binary secrets byte-identically"
        );

        // Trailing newline variant (git sometimes appends one):
        let mut tag_nl = tag.clone();
        tag_nl.push(b'\n');
        let smudged_nl = smudge_with_security(&security, &tag_nl).unwrap();
        assert_eq!(smudged_nl, plaintext);

        // Inline tag in textual content still routes to smart_smudge
        // (use a UTF-8 payload — inline decrypt of a BINARY payload is
        // lossy inside smart_smudge by design; binary secrets take the
        // whole-file path above):
        let text_tag = security.encrypt_v2_to_b64_tag(b"hunter2").unwrap();
        let tag_str = String::from_utf8(text_tag).unwrap();
        let inline = format!("prefix {} suffix", tag_str);
        let smudged_inline = smudge_with_security(&security, inline.as_bytes()).unwrap();
        assert_eq!(smudged_inline, b"prefix hunter2 suffix".to_vec());

        // Genuinely binary non-tag content passes through unchanged:
        let passthrough = smudge_with_security(&security, &plaintext).unwrap();
        assert_eq!(passthrough, plaintext);
    }

    #[test]
    fn test_whole_file_tag_binary_roundtrip_byte_identical() {
        let security = test_security_with_identity();
        // Non-UTF-8 payload: invalid sequences, NUL bytes, high bytes.
        let plaintext: Vec<u8> = vec![
            0x00, 0xFF, 0xFE, 0x80, 0x81, 0xC3, 0x28, 0xA0, 0xC1, 0xBF, 0xED, 0xA0, 0x80, 0xF5,
            0x90, 0x80, 0x90, 0x00, 0x01, 0x02, 0x7F, 0x80, 0x90, 0xA0, 0xB0, 0xF0, 0x90, 0x80,
            0x90,
        ];
        // Sanity: the payload is genuinely invalid UTF-8.
        assert!(std::str::from_utf8(&plaintext).is_err());

        // Clean side: whole-file encrypt to the b64 tag format.
        let tag = security.encrypt_v2_to_b64_tag(&plaintext).unwrap();
        assert!(security.starts_with_any_secret_tag(&tag));

        // Smudge side: byte-safe whole-file decrypt must return the
        // EXACT original bytes (no lossy UTF-8 conversion).
        let decrypted = security
            .decrypt_whole_file_tag(&tag)
            .expect("tag must be recognized as whole-file")
            .expect("decrypt must succeed");
        assert_eq!(
            decrypted, plaintext,
            "whole-file binary secret must round-trip byte-identically"
        );

        // With a trailing newline (git sometimes adds one), still works.
        let mut tag_nl = tag.clone();
        tag_nl.push(b'\n');
        let decrypted_nl = security
            .decrypt_whole_file_tag(&tag_nl)
            .expect("tag with trailing newline must be recognized")
            .expect("decrypt must succeed");
        assert_eq!(decrypted_nl, plaintext);

        // Non-tag content returns None (caller falls back to inline path).
        assert!(security.decrypt_whole_file_tag(b"plain text").is_none());
        assert!(security.decrypt_whole_file_tag(&plaintext).is_none());
    }

    /// ADDED 2026-08-09 (audit MEDIUM): whole-file-tag recognition must
    /// tolerate CRLF and 2+ trailing newlines. The previous single
    /// `strip_suffix(b"\n")` accepted at most ONE trailing `\n`, so a
    /// tag whose blob gained CRLF (`...]\r\n`) or extra newlines
    /// (`...]\n\n`) fell into the UTF-8-lossy inline smudge path (U+FFFD
    /// corruption of DER/SQLite/.kdbx payloads) and on the clean side
    /// the double-encrypt guard missed it (re-encrypting an already
    /// encrypted file).
    #[test]
    fn test_whole_file_tag_tolerates_crlf_and_multiple_newlines() {
        let security = test_security_with_identity();
        let plaintext: Vec<u8> = vec![0x00, 0xFF, 0xFE, 0x80, 0xC3, 0x28, 0xF5, 0x90, 0x80, 0x0A];
        assert!(std::str::from_utf8(&plaintext).is_err());

        let tag = security.encrypt_v2_to_b64_tag(&plaintext).unwrap();

        // Working-tree artifacts: CRLF checkout (core.autocrlf), editor
        // appending one or several newlines.
        let mut variants: Vec<Vec<u8>> = Vec::new();
        for suffix in [b"\r\n".as_slice(), b"\n\n", b"\r\n\r\n", b"\n\n\n"] {
            let mut v = tag.clone();
            v.extend_from_slice(suffix);
            variants.push(v);
        }

        // 1. Smudge-side recognition: every variant must be recognized
        // as a whole-file tag and decrypt byte-identically.
        for v in &variants {
            let decrypted = security
                .decrypt_whole_file_tag(v)
                .unwrap_or_else(|| {
                    panic!(
                        "variant {:?} must be recognized as whole-file",
                        String::from_utf8_lossy(v)
                    )
                })
                .expect("decrypt must succeed");
            assert_eq!(
                decrypted, plaintext,
                "binary round-trip must be byte-identical (no lossy UTF-8)"
            );
        }

        // 2. Production smudge entry point (`smudge_with_security`, the
        // shared path both filter entry points delegate to): raw bytes
        // out, not U+FFFD text.
        for v in &variants {
            let smudged = smudge_with_security(&security, v).unwrap();
            assert_eq!(smudged, plaintext);
        }

        // 3. Clean-side double-encrypt guard: recognition must hold so
        // already-encrypted files pass through unchanged.
        for v in &variants {
            assert!(
                security.starts_with_any_secret_tag(v),
                "clean-side guard must recognize variant {:?}",
                String::from_utf8_lossy(v)
            );
        }

        // 4. End-to-end clean: an already-whole-file-tagged `.env`
        // (full-encrypt branch, filter.rs:269) must NOT be re-encrypted
        // into a nested tag.
        let managed = WardenSecurity::new(None).unwrap();
        for v in &variants {
            let cleaned = managed.smart_clean_with_path(v, ".env").unwrap();
            assert_eq!(
                cleaned, *v,
                "already-tagged .env must pass through unchanged (no double encryption)"
            );
        }
    }

    /// ADDED 2026-07-21 (v0.112.32, audit H9/F4.2): inline tags in
    /// TEXTUAL content still go through `smart_smudge` correctly
    /// (the whole-file path must not swallow them).
    #[test]
    fn test_inline_tag_still_uses_smart_smudge() {
        let security = test_security_with_identity();
        let secret = b"hunter2";
        let tag = security.encrypt_v2_to_b64_tag(secret).unwrap();
        let tag_str = String::from_utf8(tag).unwrap();
        let inline = format!("prefix {} suffix", tag_str);
        // The inline form is NOT a whole-file tag → None from the
        // byte-safe path → smart_smudge handles it.
        assert!(security.decrypt_whole_file_tag(inline.as_bytes()).is_none());
        let smudged = security.smart_smudge(&inline).unwrap();
        assert_eq!(smudged, "prefix hunter2 suffix");
    }

    /// FIXED 2026-08-11 (audit MEDIUM): whole-file-tag recognition
    /// was purely SYNTACTIC (starts `[DRACON_SECRET:` + ends `]`). A
    /// protected file whose PLAINTEXT was tag-shaped (template,
    /// redacted placeholder, hand-written "already encrypted" marker)
    /// tripped the clean-side double-encrypt guard (filter.rs:269/317)
    /// and was committed UNENCRYPTED, silently. Recognition must now
    /// validate the payload: valid base64 + age-encryption magic.
    #[test]
    fn test_tag_shaped_plaintext_is_not_recognized() {
        let security = test_security_with_identity();

        // (a) not base64 at all
        let not_b64 = b"[DRACON_SECRET:not-base64!!!]";
        // (b) valid base64, decodes to non-age bytes ("hello world")
        let b64_plain = general_purpose::STANDARD.encode(b"hello world");
        let wrong_magic = format!("[DRACON_SECRET:{}]", b64_plain).into_bytes();
        // (c) control: a REAL tag must still be recognized
        let real = security.encrypt_v2_to_b64_tag(b"secret payload").unwrap();

        assert!(!security.starts_with_any_secret_tag(not_b64));
        assert!(!security.starts_with_any_secret_tag(&wrong_magic));
        assert!(security.starts_with_any_secret_tag(&real));

        // Smudge side: tag-shaped plaintext is NOT one of ours — None
        // (fall through), never `Some(Err)`.
        assert!(security.decrypt_whole_file_tag(not_b64).is_none());
        assert!(security.decrypt_whole_file_tag(&wrong_magic).is_none());
        assert!(security.decrypt_whole_file_tag(&real).is_some());
    }

    /// FIXED 2026-08-11 (audit MEDIUM): `smudge_with_security`
    /// propagated `Some(Err)`, hard-failing checkout/merge on any
    /// tag-shaped file; the legacy smudge path always warned + passed
    /// through. Now: tag-shaped plaintext falls through gracefully,
    /// and a real
    /// age payload that cannot be unlocked (missing key) also passes
    /// through with a warning instead of bricking the checkout.
    #[test]
    fn test_smudge_passes_through_tag_shaped_plaintext() {
        let security = test_security_with_identity();

        let not_b64 = b"[DRACON_SECRET:not-base64!!!]";
        let b64_plain = general_purpose::STANDARD.encode(b"hello world");
        let wrong_magic = format!("[DRACON_SECRET:{}]", b64_plain).into_bytes();

        // Tag-shaped plaintext must smudge to itself (Ok, no error).
        let out = smudge_with_security(&security, not_b64).unwrap();
        assert_eq!(out, not_b64);
        let out = smudge_with_security(&security, &wrong_magic).unwrap();
        assert_eq!(out, wrong_magic);

        // A REAL age payload encrypted to a key that exists NOWHERE on
        // this machine is Some(Err) — smudge must warn + pass the blob
        // through, not fail. (Encrypt with explicit recipients so the
        // machine's real identities never appear on the recipient
        // list; unlock_payload's repo-key/keychain fallbacks cannot
        // hold a random in-test key, so this is deterministic.)
        let random_key = x25519::Identity::generate();
        let foreign_enc = security
            .encrypt_v2(b"data", vec![Box::new(random_key.to_public())])
            .unwrap();
        let foreign = format!(
            "[DRACON_SECRET:{}]",
            general_purpose::STANDARD.encode(&foreign_enc)
        )
        .into_bytes();
        assert!(
            security.decrypt_whole_file_tag(&foreign).is_some(),
            "age magic must still be recognized as a whole-file tag"
        );
        let out = smudge_with_security(&security, &foreign).unwrap();
        assert_eq!(out, foreign, "unlockable-fail tag must pass through raw");
    }

    /// FIXED 2026-08-11 (audit MEDIUM): the clean-side consequence of
    /// syntactic recognition — a protected `.env` whose plaintext was
    /// tag-shaped was returned AS-IS (committed UNENCRYPTED). Now the
    /// guard only short-circuits on verified age payloads, so
    /// tag-shaped plaintext gets properly whole-file encrypted.
    #[test]
    fn test_clean_encrypts_tag_shaped_plaintext_protected_file() {
        let security = test_security_with_identity();
        let tag_shaped = b"[DRACON_SECRET:not-base64!!!]";

        let cleaned = security.smart_clean_with_path(tag_shaped, ".env").unwrap();
        assert_ne!(
            cleaned, tag_shaped,
            "tag-shaped plaintext must NOT pass through unencrypted"
        );
        assert!(
            security.starts_with_any_secret_tag(&cleaned),
            "output must be a REAL whole-file tag, got {:?}",
            String::from_utf8_lossy(&cleaned)
        );

        // Control: a REAL tag still passes through unchanged (no
        // double encryption) — the guard must not weaken.
        let real = security
            .encrypt_v2_to_b64_tag(b"already encrypted")
            .unwrap();
        let cleaned = security.smart_clean_with_path(&real, ".env").unwrap();
        assert_eq!(cleaned, real);
    }

    /// Mirror the legacy Git-Seal AES-CFB encoding only to construct
    /// regression fixtures. Production code deliberately has no CFB
    /// decryptor because the format has no authenticated integrity.
    fn legacy_cfb_encrypt(repo_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(repo_key);
        let hash = hasher.finalize();
        let cipher =
            cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(&hash[..32], &hash[..16]).unwrap();
        let mut out = plaintext.to_vec();
        cipher.encrypt(&mut out);
        out
    }

    fn legacy_cfb_decrypt_for_fixture(repo_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(repo_key);
        let hash = hasher.finalize();
        let cipher =
            cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(&hash[..32], &hash[..16]).unwrap();
        let mut out = ciphertext.to_vec();
        cipher.decrypt(&mut out);
        out
    }

    /// FIXED 2026-08-12 (audit MEDIUM follow-up): a short wrong-key
    /// decrypt can be valid printable text, so UTF-8 and ASCII heuristics
    /// cannot authenticate legacy CFB. This fixture is the auditor's
    /// counterexample: `secret` encrypted under one key decrypts as the
    /// printable `zR|11[` under another. Production must refuse it.
    #[test]
    fn test_git_seal_v1_rejects_short_valid_text_wrong_key() {
        let security = test_security_with_identity();
        set_allow_v1_fallback(true);
        let key_a = vec![0x42u8; 32];
        let key_b = vec![0x53u8; 32];
        let ciphertext = legacy_cfb_encrypt(&key_a, b"secret");
        let wrong_plaintext = legacy_cfb_decrypt_for_fixture(&key_b, &ciphertext);
        assert_eq!(wrong_plaintext, b"zR|11[");
        assert!(wrong_plaintext.iter().all(|byte| {
            byte.is_ascii() && (byte.is_ascii_graphic() || byte.is_ascii_whitespace() || *byte == 0)
        }));
        let error = security
            .decrypt_git_seal(&RepoKey(key_b), &ciphertext)
            .expect_err("unauthenticated V1 must never return plaintext");
        assert!(error.to_string().contains("no authenticated integrity"));
    }

    /// FIXED 2026-08-12 (audit MEDIUM follow-up): the old first-20-byte
    /// gate also accepted a 20-byte printable prefix followed by invalid
    /// binary data. Keep the corrected 20-byte fixture as a regression
    /// against restoring any plaintext heuristic.
    #[test]
    fn test_git_seal_v1_rejects_ascii_prefix_binary_tail() {
        let security = test_security_with_identity();
        set_allow_v1_fallback(true);
        let key = vec![0x77u8; 32];
        let mut sneaky = b"looks like text!!!! ".to_vec();
        assert_eq!(sneaky.len(), 20);
        sneaky.extend_from_slice(&[0xFF, 0xFE, 0xC3, 0x28, 0xA0, 0x81]);
        let ciphertext = legacy_cfb_encrypt(&key, &sneaky);
        let error = security
            .decrypt_git_seal(&RepoKey(key), &ciphertext)
            .expect_err("unauthenticated V1 must never return plaintext");
        assert!(error.to_string().contains("no authenticated integrity"));
    }

    /// FIXED 2026-08-11 (audit MEDIUM): the unlock error dumped the
    /// first 20 CIPHERTEXT bytes to stderr. Only a safe classification
    /// (age magic + length) may be reported now.
    #[test]
    fn test_unlock_payload_error_has_no_ciphertext_dump() {
        let security = test_security_with_identity();
        let payload = b"nothing here decrypts this blob of bytes";
        let err = security.unlock_payload(payload).unwrap_err().to_string();
        assert!(
            err.contains(&format!("len={}", payload.len())),
            "error should still report length: {err}"
        );
        assert!(
            !err.contains("nothing here"),
            "error must not echo ciphertext bytes: {err}"
        );
        assert!(!err.contains("Magic:"), "old Magic: dump removed: {err}");
    }

    /// FIXED 2026-08-11 (audit MEDIUM): `gather_all_recipients`
    /// trusted ANY `.pub`/`.key` file — a contributor who pushed
    /// `evil.pub` (or any valid age recipient under a non-canonical
    /// name) silently joined every future encryption. Repo key dirs
    /// (`.dracon/data/keys`, `.git/arcane/keys`) now honor only the
    /// canonical `owner_*.pub` mesh files with publish-path content
    /// validation; the operator's HOME key dir stays permissive (its
    /// own trust domain: micro2_*, master.pub etc. remain honored).
    #[test]
    fn test_gather_all_recipients_validates_recipient_files() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let home = tmp.path().join("home");
        fs::create_dir_all(repo.join(".dracon/data/keys")).unwrap();
        fs::create_dir_all(home.join(".dracon/data/keys")).unwrap();

        let good = x25519::Identity::generate();
        let evil = x25519::Identity::generate();
        let secret_holder = x25519::Identity::generate();
        let oversized_holder = x25519::Identity::generate();

        // The local identity is the authorization anchor. A canonical
        // owner_*.pub file for that recipient is accepted.
        let mut sec = WardenSecurity::new(Some(&repo)).unwrap();
        sec.set_mock_home(home.clone());
        sec.master_identities.clear();
        sec.master_identities.push(good.clone());

        // Canonical mesh file (keygen/publish output): honored.
        fs::write(
            repo.join(".dracon/data/keys/owner_good.pub"),
            good.to_public().to_string(),
        )
        .unwrap();
        // A contributor can choose owner_evil.pub too, but cannot make its
        // recipient trusted merely by choosing the canonical-looking name.
        fs::write(
            repo.join(".dracon/data/keys/owner_evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();
        // Attacker-pushable non-owner file with a VALID age recipient:
        // refused (was silently included before the fix).
        fs::write(
            repo.join(".dracon/data/keys/evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();
        // Canonical names still go through content validation. A `.pub`
        // file containing secret key material must not contribute its second
        // line as a recipient. Literal is concat-split so the warden's own
        // pushes of this test never trip the scanner it backs.
        fs::write(
            repo.join(".dracon/data/keys/owner_secret.pub"),
            format!(
                "AGE-SECRET-{}Y-1ABCDEFGHIJKLMNOPQRSTUVWXYZ\n{}",
                "KE",
                secret_holder.to_public()
            ),
        )
        .unwrap();
        fs::write(
            repo.join(".dracon/data/keys/owner_oversized.pub"),
            format!("{}\n{}", oversized_holder.to_public(), "x".repeat(256)),
        )
        .unwrap();
        // Exercise the legacy contributor-pushable path too.
        fs::create_dir_all(repo.join(".git/arcane/keys")).unwrap();
        fs::write(
            repo.join(".git/arcane/keys/owner_evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();
        // Home trust domain: non-owner file still honored.
        let home_key = x25519::Identity::generate();
        fs::write(
            home.join(".dracon/data/keys/random.pub"),
            home_key.to_public().to_string(),
        )
        .unwrap();

        let strs: Vec<String> = sec
            .gather_all_recipients()
            .unwrap()
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert!(
            strs.contains(&good.to_public().to_string()),
            "trusted owner_*.pub mesh key must be included"
        );
        assert!(
            !strs.contains(&evil.to_public().to_string()),
            "attacker-controlled owner_evil.pub must NOT become a recipient"
        );
        assert!(
            !strs.contains(&secret_holder.to_public().to_string()),
            "canonical file containing secret key material must NOT become a recipient"
        );
        assert!(
            !strs.contains(&oversized_holder.to_public().to_string()),
            "oversized canonical file must NOT become a recipient"
        );
        assert!(
            strs.contains(&home_key.to_public().to_string()),
            "home-dir key (operator trust domain) must stay honored"
        );
    }

    #[test]
    fn test_gather_all_recipients_separates_overlapping_home_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = home.clone();
        fs::create_dir_all(repo.join(".dracon/data/keys")).unwrap();

        let evil = x25519::Identity::generate();
        let owner = x25519::Identity::generate();
        fs::write(
            repo.join(".dracon/data/keys/owner_evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();

        let mut security = WardenSecurity::new(Some(&repo)).unwrap();
        security.set_mock_home(home);
        security.master_identities.clear();
        security.master_identities.push(owner);

        let recipients = security.gather_all_recipients().unwrap();
        assert!(
            !recipients
                .iter()
                .any(|recipient| recipient.to_string() == evil.to_public().to_string()),
            "a repository rooted at HOME must not get permissive HOME loading"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_gather_all_recipients_separates_symlinked_home_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo_alias = tmp.path().join("repo-alias");
        fs::create_dir_all(home.join(".dracon/data/keys")).unwrap();

        let evil = x25519::Identity::generate();
        let owner = x25519::Identity::generate();
        fs::write(
            home.join(".dracon/data/keys/owner_evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&home, &repo_alias).unwrap();

        let mut security = WardenSecurity::new(Some(&repo_alias)).unwrap();
        security.set_mock_home(home);
        security.master_identities.clear();
        security.master_identities.push(owner);

        let recipients = security.gather_all_recipients().unwrap();
        assert!(
            !recipients
                .iter()
                .any(|recipient| recipient.to_string() == evil.to_public().to_string()),
            "a symlinked repository root must not bypass the repository gate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_gather_all_recipients_rejects_symlinked_repo_key_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        let home_keys = home.join(".dracon/data/keys");
        let repo_data = repo.join(".dracon/data");
        fs::create_dir_all(&home_keys).unwrap();
        fs::create_dir_all(&repo_data).unwrap();

        let evil = x25519::Identity::generate();
        let owner = x25519::Identity::generate();
        fs::write(
            home_keys.join("owner_evil.pub"),
            evil.to_public().to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&home_keys, repo_data.join("keys")).unwrap();

        let mut security = WardenSecurity::new(Some(&repo)).unwrap();
        security.set_mock_home(home);
        security.master_identities.clear();
        security.master_identities.push(owner);

        let recipients = security.gather_all_recipients().unwrap();
        assert!(
            !recipients
                .iter()
                .any(|recipient| recipient.to_string() == evil.to_public().to_string()),
            "a repository key-directory symlink must not re-enable permissive HOME loading"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_gather_all_recipients_rejects_symlinked_repo_recipient_file() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        let repo_keys = repo.join(".dracon/data/keys");
        fs::create_dir_all(&repo_keys).unwrap();

        let evil = x25519::Identity::generate();
        let owner = x25519::Identity::generate();
        let outside = tmp.path().join("evil.pub");
        fs::write(&outside, evil.to_public().to_string()).unwrap();
        std::os::unix::fs::symlink(&outside, repo_keys.join("owner_evil.pub")).unwrap();

        let mut security = WardenSecurity::new(Some(&repo)).unwrap();
        security.set_mock_home(home);
        security.master_identities.clear();
        security.master_identities.push(owner);

        let recipients = security.gather_all_recipients().unwrap();
        assert!(
            !recipients
                .iter()
                .any(|recipient| recipient.to_string() == evil.to_public().to_string()),
            "a symlinked repository recipient file must be rejected"
        );
    }

    #[test]
    fn test_encrypt_v2_decrypt_v2_roundtrip() {
        let security = test_security_with_identity();
        let plaintext = b"hello world, this is a secret message";

        let recipient = security.master_identities()[0].to_public();
        let encrypted = security
            .encrypt_v2(plaintext, vec![Box::new(recipient)])
            .unwrap();
        assert!(!encrypted.is_empty());
        assert_ne!(
            encrypted,
            plaintext.to_vec(),
            "encrypted should differ from plaintext"
        );

        let decrypted = security.decrypt_v2(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "decrypted should match original");
    }

    #[test]
    fn test_encrypt_v2_empty_data() {
        let security = test_security_with_identity();
        let recipient = security.master_identities()[0].to_public();
        let encrypted = security.encrypt_v2(b"", vec![Box::new(recipient)]).unwrap();
        let decrypted = security.decrypt_v2(&encrypted).unwrap();
        assert_eq!(decrypted, b"", "empty data should roundtrip");
    }

    #[test]
    fn test_encrypt_v2_binary_data() {
        let security = test_security_with_identity();
        let plaintext: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let recipient = security.master_identities()[0].to_public();
        let encrypted = security
            .encrypt_v2(&plaintext, vec![Box::new(recipient)])
            .unwrap();
        let decrypted = security.decrypt_v2(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "binary data should roundtrip");
    }

    #[test]
    fn test_unlock_payload_v2_roundtrip() {
        let security = test_security_with_identity();
        let plaintext = b"secret data for unlock_payload test";
        let recipient = security.master_identities()[0].to_public();
        let encrypted = security
            .encrypt_v2(plaintext, vec![Box::new(recipient)])
            .unwrap();

        let unlocked = security.unlock_payload(&encrypted).unwrap();
        assert_eq!(unlocked, plaintext, "unlock_payload should decrypt v2");
    }

    #[test]
    fn test_decrypt_v2_fails_with_wrong_identity() {
        let tempdir = tempfile::tempdir().unwrap();
        let mut security1 = WardenSecurity::new(None).unwrap();
        security1.set_mock_home(tempdir.path().to_path_buf());
        security1.master_identities.clear();
        let key1 = x25519::Identity::generate();
        security1.master_identities.push(key1);

        let mut security2 = WardenSecurity::new(None).unwrap();
        security2.set_mock_home(tempdir.path().to_path_buf());
        security2.master_identities.clear();
        let key2 = x25519::Identity::generate();
        security2.master_identities.push(key2);

        let plaintext = b"data encrypted to key1";
        let recipient = security1.master_identities()[0].to_public();
        let encrypted = security1
            .encrypt_v2(plaintext, vec![Box::new(recipient)])
            .unwrap();

        let result = security2.decrypt_v2(&encrypted);
        assert!(result.is_err(), "decrypt with wrong identity should fail");
    }

    #[test]
    fn test_decrypt_v2_requires_master_identity() {
        let security = WardenSecurity::new(None).unwrap();
        let result = security.decrypt_v2(b"some encrypted data");
        assert!(
            result.is_err(),
            "decrypt_v2 should fail without master identities"
        );
    }

    #[test]
    fn test_encrypt_v2_for_all_roundtrip() {
        let security = test_security_with_identity();
        let plaintext = b"encrypt to all recipients test";
        let encrypted = security.encrypt_v2_for_all(plaintext).unwrap();
        let decrypted = security.decrypt_v2(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "encrypt_v2_for_all should roundtrip");
    }

    #[test]
    fn test_encrypt_v2_for_all_empty_data() {
        let security = test_security_with_identity();
        let encrypted = security.encrypt_v2_for_all(b"").unwrap();
        let decrypted = security.decrypt_v2(&encrypted).unwrap();
        assert_eq!(decrypted, b"", "empty data roundtrip");
    }

    #[test]
    fn test_normalize_secret_marker_valid() {
        assert_eq!(
            normalize_secret_marker("API_SECRET"),
            Some("API_SECRET".to_string())
        );
        assert_eq!(
            normalize_secret_marker("DB_SECRET"),
            Some("DB_SECRET".to_string())
        );
        assert_eq!(
            normalize_secret_marker("  api_secret  "),
            Some("API_SECRET".to_string())
        );
    }

    #[test]
    fn test_normalize_secret_marker_invalid() {
        assert_eq!(normalize_secret_marker("no_suffix"), None);
        assert_eq!(normalize_secret_marker(""), None);
        assert_eq!(normalize_secret_marker("API-SECRET"), None);
        assert_eq!(normalize_secret_marker("API SECRET"), None);
    }

    #[test]
    fn test_is_inside_secret_tag_detection() {
        let content = "prefix [API_SECRET:abc] suffix";
        assert!(is_inside_secret_tag(content, 20), "inside tag");
        assert!(!is_inside_secret_tag(content, 5), "before tag");
        assert!(!is_inside_secret_tag(content, 30), "after tag");
    }

    #[test]
    fn test_get_env_version_edge_cases() {
        assert_eq!(get_env_version(""), 0);
        assert_eq!(get_env_version("no version here"), 0);
        assert_eq!(get_env_version("Version: abc\n"), 0);
        // A bare "Version: " line WITHOUT the managed header marker is
        // body content — must NOT be read as the header version (audit
        // LOW 2026-08-10).
        assert_eq!(get_env_version("Version: 42\n"), 0);

        let managed = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 42
# =============================================================================
API_KEY=secret"#;
        assert_eq!(get_env_version(managed), 42);

        // A body "Version: " line AFTER a managed header is ignored.
        let with_body_version = format!("{}\n# Version: 99\nAPI_KEY=secret", managed);
        assert_eq!(get_env_version(&with_body_version), 42);
    }

    #[test]
    fn test_is_env_version_managed() {
        let managed = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
API_KEY=secret"#;
        assert!(is_env_version_managed(managed));

        // A comment merely MENTIONING Dracon Warden is not a managed
        // header (audit LOW 2026-08-10).
        let fresh = "# deployed by Dracon Warden\nAPI_KEY=secret";
        assert!(!is_env_version_managed(fresh));

        // The marker string below the top region is body content.
        let deep = "# a\n# b\n# c\n# d\n# e\n# f\n# Dracon Warden Encrypted Environment File\nAPI_KEY=secret";
        assert!(!is_env_version_managed(deep));
    }

    #[test]
    fn test_github_token_patterns_accept_variable_length() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let short = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz1234");
        let long = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz123456789012");
        let found_short = scanner.scan(short);
        let found_long = scanner.scan(long);
        assert!(
            found_short
                .iter()
                .any(|f| f.name.contains("GitHub Token (ghp)")),
            "should detect short GitHub token prefix token (30 chars after prefix), found: {:?}",
            found_short
        );
        assert!(
            found_long
                .iter()
                .any(|f| f.name.contains("GitHub Token (ghp)")),
            "should detect long GitHub token prefix token (40 chars after prefix), found: {:?}",
            found_long
        );
    }

    #[test]
    fn test_mailgun_key_accepts_variable_length() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let short = concat!("key", "-abcdefghijklmnopqrstuvwxyz12");
        let long = concat!("key", "-abcdefghijklmnopqrstuvwxyz123456");
        let found_short = scanner.scan(short);
        let found_long = scanner.scan(long);
        assert!(
            found_short.iter().any(|f| f.name == "Mailgun API Key"),
            "should detect 28-char Mailgun key (after prefix), found: {:?}",
            found_short
        );
        assert!(
            found_long.iter().any(|f| f.name == "Mailgun API Key"),
            "should detect 34-char Mailgun key (after prefix), found: {:?}",
            found_long
        );
    }

    #[test]
    fn test_slack_bot_token_compact() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let token = concat!(
            "xox",
            "b-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop"
        );
        let found = scanner.scan(token);
        assert!(
            found.iter().any(|f| f.name == "Slack Bot Token (Compact)"),
            "should detect compact Slack bot token, found: {:?}",
            found
        );
    }

    #[test]
    fn test_slack_bot_token_compact_has_length_cap() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let reasonable = concat!(
            "xox",
            "b-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop"
        );
        let found = scanner.scan(reasonable);
        assert!(
            found.iter().any(|f| f.name == "Slack Bot Token (Compact)"),
            "should match slack bot token up to 68 chars after Slack token prefix, found: {:?}",
            found
        );
    }

    #[test]
    fn test_hex_secret_quoted_requires_context() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let with_context = concat!("secret = \"", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"",);
        let without_context = r#"label = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4""#;
        let found_with = scanner.scan(with_context);
        let found_without = scanner.scan(without_context);
        assert!(
            found_with.iter().any(|f| f.name == "Hex Secret (Quoted)"),
            "should detect hex secret with context keyword, found: {:?}",
            found_with
        );
        assert!(
            !found_without
                .iter()
                .any(|f| f.name == "Hex Secret (Quoted)"),
            "should NOT detect hex string without context keyword, found: {:?}",
            found_without
        );
    }

    #[test]
    fn test_high_entropy_secret_quoted_requires_context() {
        let scanner = SecretScanner::new_without_age_keys().unwrap();
        let with_context = concat!("secret = \"", "aBcDeFgHiJkLmNoPqRsTuVwXaBcDeFgH\"",);
        let without_context = r#"class_name = "aBcDeFgHiJkLmNoPqRsTuVwX""#;
        let found_with = scanner.scan(with_context);
        let found_without = scanner.scan(without_context);
        assert!(
            found_with
                .iter()
                .any(|f| f.name == "High-Entropy Secret (Quoted)"),
            "should detect high-entropy secret with context keyword, found: {:?}",
            found_with
        );
        assert!(
            !found_without
                .iter()
                .any(|f| f.name == "High-Entropy Secret (Quoted)"),
            "should NOT detect alphanumeric string without context keyword, found: {:?}",
            found_without
        );
    }
    /// ADDED 2026-09-09 (audit F49): the merge driver re-encrypted via
    /// git's %A temp path, so the protected-patterns gate missed and
    /// merged plaintext was committed. `smart_clean_for_merge` must
    /// encrypt WITHOUT any path match — whole-file ancestors stay
    /// whole-file, inline ancestors stay inline.
    #[test]
    fn test_merge_clean_whole_file_ancestor_stays_encrypted() {
        let mut security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec!["secrets/**".to_string()]);
        let identity = age::x25519::Identity::generate();
        security.add_memory_identity(identity);

        let ancestor_pt = b"DB_PASSWORD=hunter2\nAPI_KEY=abcdef\n";
        let ancestor_raw = security.encrypt_v2_to_b64_tag(ancestor_pt).unwrap();
        assert!(
            security.decrypt_whole_file_tag(&ancestor_raw).is_some(),
            "fixture must be whole-file ciphertext"
        );

        // Temp-style %A content the old path gate would pass through.
        let merged = b"DB_PASSWORD=hunter2\nAPI_KEY=changed\n";
        let gated = security
            .smart_clean_with_path(merged, "/tmp/.merge_file_abc123")
            .unwrap();
        assert_eq!(
            gated, merged,
            "precondition: path-gated clean passes temp paths through (the F49 hole)"
        );

        let out = security
            .smart_clean_for_merge(merged, &ancestor_raw)
            .unwrap();
        assert_ne!(out, merged, "merge clean must not emit plaintext");
        let back = security
            .decrypt_whole_file_tag(&out)
            .expect("merge output must be whole-file ciphertext")
            .expect("merge output must decrypt");
        assert_eq!(back, merged, "whole-file roundtrip preserves merged bytes");
    }

    /// ADDED 2026-09-09 (audit F49): inline-tagged ancestors stay
    /// inline through the merge clean, with no path allowlisting.
    #[test]
    fn test_merge_clean_inline_ancestor_stays_inline() {
        let mut security = WardenSecurity::new(None)
            .unwrap()
            .with_managed_patterns(vec!["secrets/**".to_string()]);
        let identity = age::x25519::Identity::generate();
        security.add_memory_identity(identity);

        let sk = "sk-abcdef0123456789abcdef0123456789";
        let ancestor_pt = format!("line1\nline2\n{sk}\n");
        let ancestor_raw = security.smart_clean(&ancestor_pt).unwrap().into_bytes();
        assert!(
            String::from_utf8_lossy(&ancestor_raw).contains("DRACON_SECRET"),
            "fixture must carry inline tags"
        );

        let merged = format!("line1\nline2-changed\n{sk}\n");
        let out = security
            .smart_clean_for_merge(merged.as_bytes(), &ancestor_raw)
            .unwrap();
        let out_text = String::from_utf8(out).expect("inline output is text");
        assert!(
            out_text.contains("DRACON_SECRET"),
            "merge output must stay encrypted, got: {}",
            &out_text[..out_text.len().min(80)]
        );
        let back = security.smart_smudge(&out_text).unwrap();
        assert!(
            back.contains("line2-changed") && back.contains(sk),
            "inline roundtrip preserves merged content: {}",
            back
        );
    }
}

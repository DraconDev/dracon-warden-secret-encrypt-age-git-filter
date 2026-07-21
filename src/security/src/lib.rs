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

pub mod modules;

pub use modules::environment::EnvironmentManager;
pub use modules::filter::is_hatched;
pub use modules::keys::RepoKey;
pub use modules::keys::TeamKey;
pub use modules::scanner::SecretFinding;
pub use modules::scanner::SecretScanner;

const DEFAULT_SECRET_MARKER: &str = "DRACON_SECRET";

static DEFAULT_SECURITY_CACHE: OnceCell<WardenSecurity> = OnceCell::new();

static ALLOW_V1_FALLBACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// DEPRECATED 2026-07-18 (FDRACONWARDEN-001): V1 decryption uses
// AES-256-CFB with a deterministic IV derived as SHA256(repo_key)[..16].
// This is a textbook CFB nonce-misuse vulnerability: identical plaintexts
// under the same key produce identical ciphertexts. We retain the
// runtime gate ONLY for one migration cycle so operators can recover
// V1-format ciphertexts. The escape hatch will be removed in v0.113.0.
// To migrate: set `allow_v1_fallback = true` in the policy, decrypt once
// to re-encrypt under V2 (AES-256-GCM with a random nonce), then unset
// the gate.
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

fn get_env_version(content: &str) -> u32 {
    if let Some(pos) = content.find("Version: ") {
        let after = &content[pos + 9..];
        if let Some(end) = after.find('\n').or_else(|| after.find('\r')) {
            if let Ok(v) = after[..end].trim().parse::<u32>() {
                return v;
            }
        }
    }
    0
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
    let header_marker = "Dracon Warden Encrypted Environment File";
    if let Some(start_pos) = content.find(header_marker) {
        let after_header = &content[start_pos..];
        let closing_marker =
            "# =============================================================================";
        if let Some(closing_pos) = after_header.find(closing_marker) {
            let after_closing = &after_header[closing_pos + closing_marker.len()..];
            return after_closing
                .trim_start_matches('\n')
                .trim_start_matches('\r');
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

    fn starts_with_any_secret_tag(&self, content: &[u8]) -> bool {
        let trimmed = content.strip_suffix(b"\n").unwrap_or(content);
        self.secret_tag_prefixes()
            .iter()
            .any(|prefix| trimmed.starts_with(prefix.as_bytes()) && trimmed.ends_with(b"]"))
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

        let output_path = keys_dir.join(format!("{}.age", recipient));

        // Encrypt the repo key for the recipient
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient.clone())];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("failed to create encryptor")?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(&repo_key.0)?;
        writer.finish()?;

        std::fs::write(&output_path, &encrypted)?;
        Ok(())
    }

    // specialized helper for machine key scanning
    fn try_decrypt_directory_machine(
        &self,
        dir: &Path,
        identity: &x25519::Identity,
    ) -> Result<RepoKey> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                let filename = path.file_name().unwrap_or_default().to_string_lossy();
                if filename.starts_with("machine:") {
                    if let Ok(repo_key) = self.try_decrypt_key_file(&path, identity) {
                        return Ok(repo_key);
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No matching machine key found"))
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
    fn try_decrypt_directory(&self, dir: &Path, identity: &x25519::Identity) -> Result<RepoKey> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                if let Ok(repo_key) = self.try_decrypt_key_file(&path, identity) {
                    return Ok(repo_key);
                }
            }
        }
        Err(anyhow::anyhow!(
            "No matching key found in directory for this identity"
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

    fn backup_secret(&self, original_path: &str, content: &[u8]) -> Result<()> {
        if original_path.contains("dracon/backups") || original_path.contains("arcane/backups") {
            return Ok(()); // Silent skip for internal Git/Arcane backups
        }
        let repo_root = self.get_repo_root()?;
        let backup_dir = repo_root.join(".git").join("arcane").join("backups");
        fs::create_dir_all(&backup_dir)?;

        let safe_name = original_path.replace("/", "_").replace("\\", "_");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let backup_path = backup_dir.join(format!("{}.{}.bak.age", safe_name, timestamp));

        let identity = self
            .master_identities
            .first()
            .context("Master identity required for secure backup")?;
        let recipient = identity.to_public();

        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encryptor = age::Encryptor::with_recipients(recipients)
            .context("Failed to create encryptor for backup")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&backup_path)?;
            let mut writer = encryptor.wrap_output(&mut file)?;
            writer.write_all(content)?;
            writer.finish()?;
        }
        #[cfg(not(unix))]
        {
            let mut file = fs::File::create(&backup_path)?;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(&backup_path, perms)?;
            let mut writer = encryptor.wrap_output(&mut file)?;
            writer.write_all(content)?;
            writer.finish()?;
        }

        Ok(())
    }

    // ============================================================
    // V2: DIRECT RECIPIENT ENCRYPTION (Standard Age)
    // ============================================================

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
    /// optionally with one trailing newline), decode + decrypt and
    /// return the RAW plaintext bytes. Returns `None` when the
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
    fn decrypt_whole_file_tag(&self, content: &[u8]) -> Option<Result<Vec<u8>>> {
        let trimmed = content.strip_suffix(b"\n").unwrap_or(content);
        for prefix in self.secret_tag_prefixes() {
            let p = prefix.as_bytes();
            if trimmed.starts_with(p) && trimmed.ends_with(b"]") {
                let b64 = &trimmed[p.len()..trimmed.len() - 1];
                let encrypted = match general_purpose::STANDARD.decode(b64.trim()) {
                    Ok(e) => e,
                    Err(e) => {
                        return Some(Err(anyhow::anyhow!(
                            "whole-file tag base64 decode failed: {}",
                            e
                        )))
                    }
                };
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
    /// Gracefully handles: V2 (Direct), V1 (RepoKey), Plaintext, REDACTED_REGEX wrapped
    /// Encrypt data using the repo key with AES-256-GCM.
    ///
    /// SECURITY NOTE: Uses a random 12-byte nonce per encryption. For very high-volume
    /// repositories (2^48+ encrypted files with the same repo key), nonce collision
    /// becomes a meaningful risk for GCM mode. For typical use, the random nonce
    /// per-file is sufficient. Consider key rotation if your repo will exceed this scale.
    /// Decrypt data using the repo key
    /// Decrypt data using the legacy Git Seal V1 format (AES-256-CFB with derived IV).
    /// WARNING: This format uses a deterministic IV derived from the key (SHA-256 hash → first 16 bytes), which violates AES-CFB security requirements. Using the same IV for multiple encryptions leaks information about plaintext relationships. This format exists for backward compatibility with legacy git-seal ciphertexts. DO NOT use this for new encryptions. If you have ciphertexts created with this format, consider migrating to AES-256-GCM (encrypt_with_repo_key) with random nonces.
    /// "Drunk guy with keychain" - try all keys from ~/.dracon/keys/
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

                        // Try AES-CFB (git-seal style)
                        if let Ok(plaintext) = self.decrypt_git_seal(&repo_key, ciphertext) {
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "🔓 Decrypted with keychain key (AES-CFB): {:?}",
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
        if let Some(existing) = creds.iter_mut().find(|c| c.registry == cred.registry) {
            existing.username = cred.username;
            existing.password = cred.password;
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

pub struct Warden;

/// Detect binary content by checking for null bytes.
/// Git uses a similar heuristic: any null byte means binary.
fn is_binary_content(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

impl Warden {
    pub fn new() -> Result<Self> {
        Ok(Warden)
    }

    pub fn smudge(&self, bytes: &[u8], _path: Option<&str>) -> Result<Vec<u8>> {
        if is_binary_content(bytes) {
            return Ok(bytes.to_vec());
        }
        let content = String::from_utf8_lossy(bytes);
        let smudged = WardenSecurity::new(None)?.smart_smudge(&content)?;
        Ok(smudged.into_bytes())
    }
}

pub struct DraconWarden;

impl DraconWarden {
    pub fn new() -> Result<Self> {
        Ok(DraconWarden)
    }

    pub fn smudge(&self, bytes: &[u8], _path: Option<&str>) -> Result<Vec<u8>> {
        if is_binary_content(bytes) {
            return Ok(bytes.to_vec());
        }
        let content = String::from_utf8_lossy(bytes);
        let security = WardenSecurity::get_or_init()?;
        let smudged = security.smart_smudge(&content)?;
        Ok(smudged.into_bytes())
    }

    pub fn clean(&self, bytes: &[u8], path: Option<&str>) -> Result<Vec<u8>> {
        let security = WardenSecurity::get_or_init()?;
        let cleaned = security.smart_clean_with_path(bytes, path.unwrap_or(""))?;
        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::filter::path_is_protected;

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
    fn test_path_is_protected_substring_fallback() {
        // `config/services.json` matches by substring as a last-resort
        // fallback (rules 1-4 don't match a literal path component).
        let patterns: Vec<String> = vec!["config/services.json".to_string()];
        assert!(path_is_protected("config/services.json", &patterns));
        assert!(path_is_protected(
            "apps/web/config/services.json",
            &patterns
        ));
        // A different file under config/ is not protected.
        assert!(!path_is_protected("config/licenses.json", &patterns));
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
        let security = WardenSecurity::new(None).unwrap()
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

        let content =
            concat!("AGE", "-SECRET", "-KEY-", "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L");
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
    fn test_get_env_version_extracts_version() {
        let v1_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 1
# =============================================================================
API_KEY=secret"#;
        assert_eq!(get_env_version(v1_content), 1);

        let v5_content = r#"# =============================================================================
# Dracon Warden Encrypted Environment File
# Version: 5
# =============================================================================
API_KEY=secret"#;
        assert_eq!(get_env_version(v5_content), 5);

        let no_version = r#"API_KEY=secret"#;
        assert_eq!(get_env_version(no_version), 0);
    }

    #[test]
    fn test_make_env_version_header_increments_version() {
        let v1_content = r#"# Version: 1
API_KEY=secret"#;
        let header = make_env_version_header(v1_content);
        assert!(header.contains("Version: 2"));

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
        assert!(security
            .decrypt_whole_file_tag(&plaintext)
            .is_none());
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
        assert_eq!(get_env_version("Version: 42\n"), 42);
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
        let token = concat!("xox", "b-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop");
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
        let reasonable = concat!("xox", "b-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop");
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
        let with_context = r#"secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4""#;
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
        let with_context = r#"secret = "aBcDeFgHiJkLmNoPqRsTuVwXaBcDeFgH""#;
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
}

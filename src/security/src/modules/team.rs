//! Team key management and collaboration.

use age::x25519;
use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::TeamKey;
use crate::WardenSecurity;

/// Create a new private key file without following a check-then-create race.
/// On Unix the mode is applied at creation so the encrypted key is never
/// exposed with the process umask's default permissions.
fn write_new_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)
    }
}

impl WardenSecurity {
    pub fn load_team_key(&self, team_name: &str) -> Result<TeamKey> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        let team_key_path = home
            .join(".dracon")
            .join("teams")
            .join(format!("{}.key", team_name));

        if !team_key_path.exists() {
            return Err(anyhow::anyhow!(
                "Team key '{}' not found in keychain",
                team_name
            ));
        }

        // Team keys are encrypted with Master Identity
        // Team keys are encrypted with Master Identity. Use PRIMARY (first in ring).
        let identity = self
            .master_identities
            .first()
            .context("Master identity required to unlock team keys")?;

        // Decrypt the file
        let encrypted_bytes = fs::read(&team_key_path)?;
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
        use std::io::Read;
        reader.read_to_end(&mut key_bytes)?;

        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid team key length"));
        }

        Ok(TeamKey(key_bytes))
    }

    pub fn create_team(&self, team_name: &str) -> Result<()> {
        // Validate name
        if team_name.contains('/') || team_name.contains('\\') || team_name.contains(':') {
            return Err(anyhow::anyhow!("Invalid team name"));
        }

        let home = dirs::home_dir().context("Could not find home directory")?;
        let team_dir = home.join(".dracon").join("teams");
        fs::create_dir_all(&team_dir)?;

        let team_key_path = team_dir.join(format!("{}.key", team_name));

        // Generate new Identity for the team
        let team_identity = x25519::Identity::generate();
        let team_identity_string = team_identity.to_string(); // Extend lifetime
        let team_secret = team_identity_string.expose_secret();

        // Encrypt this secret with Master Identity for storage
        let master = self
            .master_identities
            .first()
            .context("Master identity required")?;
        let recipient = master.to_public();

        // Encryption logic
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient.clone())];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("failed to create encryptor")?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(team_secret.as_bytes())?;
        writer.finish()?;

        match write_new_private_file(&team_key_path, &encrypted) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(
                anyhow::anyhow!("Team '{}' already exists in your keychain", team_name),
            ),
            Err(error) => Err(error.into()),
        }
    }

    pub fn add_team_member(&self, alias: &str, public_key_str: &str) -> Result<()> {
        let recipient: x25519::Recipient = public_key_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        let repo_key = self
            .load_repo_key()
            .context("Must have access to repo to add members")?;

        // Sanitize alias
        let alias = alias.trim();
        if alias.is_empty() || alias.contains('/') || alias.contains('\\') {
            return Err(anyhow::anyhow!("Invalid alias"));
        }

        let repo_root = self.get_repo_root()?;
        let keys_dir = repo_root.join(".git").join("arcane").join("keys");
        let keys_metadata =
            fs::symlink_metadata(&keys_dir).context("inspect repository recipient directory")?;
        if !keys_metadata.file_type().is_dir() {
            anyhow::bail!("repository recipient directory must be a real directory")
        }
        let key_path = keys_dir.join(format!("{}.age", alias));
        let pub_key_path = keys_dir.join(format!("{}.pub", alias));

        if key_path.exists() {
            if !matches!(
                fs::symlink_metadata(&key_path),
                Ok(metadata) if metadata.file_type().is_file()
            ) {
                anyhow::bail!("existing team delegation must be a regular file")
            }
            // Legacy team entries predate the authenticated sidecar. An
            // operator who explicitly re-authorizes the same recipient can
            // add the proof in place; arbitrary existing files are never
            // trusted automatically.
            if !matches!(
                fs::symlink_metadata(&pub_key_path),
                Ok(metadata) if metadata.file_type().is_file()
            ) {
                anyhow::bail!("existing team public key must be a regular file")
            }
            let existing = fs::read_to_string(&pub_key_path).unwrap_or_default();
            if existing.trim() == recipient.to_string() {
                self.ensure_repo_recipient_authorization(
                    &repo_key,
                    &pub_key_path,
                    "team",
                    &recipient,
                )?;
                return Ok(());
            }
            return Err(anyhow::anyhow!("Member '{}' already exists", alias));
        }

        // Save Age key (encrypted for member)
        self.encrypt_and_save_key(&repo_key, &recipient, &key_path)?;

        // The public file is contributor-visible, so its basename is not an
        // authorization signal. Store an owner-signed sidecar that binds this
        // exact team recipient to the authorization operation.
        self.write_repo_public_recipient(&pub_key_path, &recipient)?;
        self.write_repo_recipient_authorization(&repo_key, &pub_key_path, "team", &recipient)?;

        Ok(())
    }

    pub fn create_team_invite(&self, team_name: &str, user_public_key: &str) -> Result<PathBuf> {
        let team_key = self.load_team_key(team_name)?;

        let recipient: x25519::Recipient = user_public_key
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid user public key: {}", e))?;

        let repo_root = self.get_repo_root()?;

        // Generate a random invite ID
        let invite_id = uuid::Uuid::new_v4().to_string();

        let invites_dir = repo_root.join(".dracon").join("invites").join(team_name);
        fs::create_dir_all(&invites_dir)?;

        let invite_path = invites_dir.join(format!("{}.age", invite_id));

        // Encrypt the TEAM KEY for the USER
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("Failed to create encryptor")?;

        let mut file = fs::File::create(&invite_path)?;
        let mut writer = encryptor.wrap_output(&mut file)?;
        writer.write_all(&team_key.0)?;
        writer.finish()?;

        Ok(invite_path)
    }

    pub fn accept_team_invite(&self, invite_path: &Path) -> Result<String> {
        let identity = self
            .master_identities
            .first()
            .context("Master identity required to accept invite")?;

        let encrypted_bytes = fs::read(invite_path)?;
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

        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid invite content"));
        }

        // Determine team name from path: dracon/invites/<team_name>/...
        let team_name = invite_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Could not determine team name from path"))?;

        // Save to key chain
        let home = dirs::home_dir().context("Could not find home directory")?;
        let team_dir = home.join(".dracon").join("teams");
        fs::create_dir_all(&team_dir)?;

        let team_key_path = team_dir.join(format!("{}.key", team_name));

        // Encrypt for local storage (Master Identity)
        let master = self
            .master_identities
            .first()
            .context("Master identity required to accept invite")?;
        let recipient = master.to_public();

        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encryptor =
            age::Encryptor::with_recipients(recipients).context("Failed to create encryptor")?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(&key_bytes)?;
        writer.finish()?;

        write_new_private_file(&team_key_path, &encrypted)?;

        Ok(team_name.to_string())
    }

    pub fn list_authorized_recipients(&self) -> Result<Vec<(String, String)>> {
        // Reuse the same trust classifier as encryption. A listing must not
        // present contributor-added files as authorized when gather would
        // correctly reject them.
        let authorized = self
            .gather_all_recipients()?
            .into_iter()
            .map(|recipient| recipient.to_string())
            .collect::<std::collections::HashSet<_>>();
        let repo_root = self.get_repo_root()?;
        let repo_key = self.load_repo_key().ok();
        let mut recipients = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let search_paths = vec![
            repo_root.join(".dracon").join("data").join("keys"),
            repo_root.join(".git").join("arcane").join("keys"),
        ];

        for dir in search_paths {
            if !matches!(
                fs::symlink_metadata(&dir),
                Ok(metadata) if metadata.file_type().is_dir()
            ) {
                continue;
            }
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !matches!(
                    fs::symlink_metadata(&path),
                    Ok(metadata) if metadata.file_type().is_file()
                ) {
                    continue;
                }
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext != "pub" && ext != "key" {
                    continue;
                }
                let Some(recipient) = crate::modules::crypto::parse_single_repo_recipient(
                    &fs::read_to_string(&path).unwrap_or_default(),
                ) else {
                    continue;
                };
                let recipient_string = recipient.to_string();
                if !authorized.contains(&recipient_string) {
                    continue;
                }
                let canonical = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| {
                        (name.starts_with("owner_") && name.ends_with(".pub"))
                            || name == "master.pub"
                    })
                    .unwrap_or(false);
                let delegated = repo_key.as_ref().is_some_and(|key| {
                    path.with_extension("age")
                        .symlink_metadata()
                        .map(|metadata| metadata.file_type().is_file())
                        .unwrap_or(false)
                        && self.verify_repo_recipient_authorization(&path, &recipient, key)
                });
                if (canonical || delegated) && seen.insert(recipient_string.clone()) {
                    let name = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    recipients.push((name, recipient_string));
                }
            }
        }
        Ok(recipients)
    }

    pub fn list_team_members(&self) -> Result<Vec<String>> {
        // Only report delegated files that the same gather path accepts. This
        // prevents a contributor-added `.age` filename from appearing as an
        // authorized team member when it cannot receive future encryption.
        let authorized_names = self
            .list_authorized_recipients()?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<std::collections::HashSet<_>>();
        let repo_root = self.get_repo_root()?;
        let keys_dir = repo_root.join(".git").join("arcane").join("keys");

        if !matches!(
            fs::symlink_metadata(&keys_dir),
            Ok(metadata) if metadata.file_type().is_dir()
        ) {
            return Ok(Vec::new());
        }

        let mut members = Vec::new();
        for entry in fs::read_dir(keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !matches!(
                fs::symlink_metadata(&path),
                Ok(metadata) if metadata.file_type().is_file()
            ) {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    if authorized_names.contains(name)
                        && !name.starts_with("machine:")
                        && !name.starts_with("team:")
                        && name != "repo"
                        && name != "owner"
                    {
                        members.push(name.to_string());
                    }
                }
            }
        }
        Ok(members)
    }
}

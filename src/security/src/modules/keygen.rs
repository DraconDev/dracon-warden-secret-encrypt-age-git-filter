//! Key generation and management.

use age::x25519;
use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::WardenSecurity;

fn refuse_dedicated_master_overwrite(home: &std::path::Path) -> anyhow::Result<()> {
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
                "refusing to generate a legacy master identity while the dedicated master key exists at {}; \
                 use the explicit master-key rotation procedure instead",
                protected.display()
            );
        }
    }

    Ok(())
}

impl WardenSecurity {
    pub fn generate_master_identity(&mut self) -> Result<()> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        refuse_dedicated_master_overwrite(&home)?;
        let dracon_dir = home.join(".dracon");
        let identity_path = dracon_dir.join("identity.age");
        // Protection: Check legacy path too
        let legacy_path = dracon_dir.join("identity.txt");

        // PROTECTION: Scan for ANY existing identity files (backups, corrupted, legacy)
        // We refuse to init if there is ANY trace of an identity to prevent data loss.
        if let Some(parent) = identity_path.parent() {
            if parent.exists() {
                for entry in fs::read_dir(parent)? {
                    let entry = entry?;
                    let path = entry.path();
                    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

                    if file_name.starts_with("identity") {
                        return Err(anyhow::anyhow!(
                            "🛡️ SAFETY TRIGGERED: Found existing identity artifact '{:?}'.\n\n\
                             CRITICAL: warden refuses to overwrite, modify, or delete Master Identity files.\n\
                             This ensures you can NEVER be locked out of your secrets by an automated process.\n\n\
                             To generate a NEW identity, you must MANUALLY move or delete all 'identity*' files in {:?}.",
                            file_name,
                            parent
                        ));
                    }
                }
            }
        }

        if legacy_path.exists() {
            return Err(anyhow::anyhow!(
                "🛡️ SAFETY TRIGGERED: Legacy identity found at {:?}. Please remove explicitly.",
                legacy_path
            ));
        }

        // Generate new identity
        let key = x25519::Identity::generate();
        if let Some(parent) = identity_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Save Private Identity
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&identity_path)?;
        let mut writer = file;
        #[cfg(not(unix))]
        {
            let mut perms = writer.metadata()?.permissions();
            perms.set_mode(0o400);
            if let Err(e) = fs::set_permissions(&identity_path, perms) {
                eprintln!(
                    "⚠️ failed to set permissions on {}: {}",
                    identity_path.display(),
                    e
                );
            }
        }
        writeln!(writer, "{}", key.to_string().expose_secret())?;

        // Save Public Key for sharing
        let pub_path = dracon_dir.join("identity.pub");
        fs::write(&pub_path, key.to_public().to_string())?;

        // Auto-Backup Master Identity
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backup_dir = dracon_dir.join("backups");
        if let Err(e) = fs::create_dir_all(&backup_dir) {
            eprintln!(
                "⚠️ failed to create backup dir {}: {}",
                backup_dir.display(),
                e
            );
        }
        let backup_path = backup_dir.join(format!("master_{}.age", timestamp));
        if let Ok(mut b_file) = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&backup_path)
        {
            if let Err(e) = writeln!(b_file, "{}", key.to_string().expose_secret()) {
                eprintln!("⚠️ failed to write backup {}: {}", backup_path.display(), e);
            }
        }

        self.master_identities = vec![key];
        Ok(())
    }

    pub fn generate_machine_identity() -> (String, String) {
        let identity = x25519::Identity::generate();
        let pub_key = identity.to_public().to_string();
        let identity_str = identity.to_string();
        let priv_key = identity_str.expose_secret();
        (priv_key.to_string(), pub_key)
    }

    pub fn whitelist_machine(&self, public_key_str: &str) -> Result<()> {
        let recipient: x25519::Recipient = public_key_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid machine public key: {}", e))?;

        let repo_key = self
            .load_repo_key()
            .context("Must have access to repo to whitelist machines")?;

        let repo_root = self.get_repo_root()?;
        let keys_dir = repo_root.join(".git").join("arcane").join("keys");

        // Use hash or similar ID for filename
        let safe_name = public_key_str
            .replace(":", "_")
            .chars()
            .take(12)
            .collect::<String>();
        let machine_file = keys_dir.join(format!("machine:{}.age", safe_name));
        let pub_file = keys_dir.join(format!("machine:{}.pub", safe_name));

        // Save public key (for V2 filtering)
        fs::write(&pub_file, public_key_str)?;

        self.encrypt_and_save_key(&repo_key, &recipient, &machine_file)?;

        Ok(())
    }

    pub fn ensure_current_user_key(&self) -> Result<()> {
        let repo_root = match self.get_repo_root() {
            Ok(r) => r,
            Err(_) => return Ok(()), // Not in a repo, skip
        };

        let identity = self
            .master_identities
            .first()
            .context("No master identity found")?;
        let pub_key = identity.to_public();
        let pub_key_str = pub_key.to_string();

        // Use a short hash of the key for the filename to allow multiple owners
        // without conflict or overwriting.
        let safe_id = pub_key_str.chars().take(8).collect::<String>();
        let filename = format!("owner_{}.pub", safe_id);

        let keys_dir = repo_root.join(".dracon").join("data").join("keys");
        fs::create_dir_all(&keys_dir)?;

        let key_path = keys_dir.join(&filename);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&key_path)?;
            file.write_all(pub_key_str.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&key_path, &pub_key_str)?;
        }
        Ok(())
    }
}

//! Backup and restore operations for encrypted files.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{
    refuse_unfenced_git_metadata_write, write_single_link_file, WardenSecurity,
};

fn write_backup(
    backup_dir: &Path,
    hash_hex: &str,
    encrypted: &[u8],
    mut timestamp: u128,
) -> Result<PathBuf> {
    // Filename: <hash>_<timestamp>.age. Retry with the next timestamp if
    // another backup was created at the same instant.
    loop {
        let filename = format!("{}_{}.age", hash_hex, timestamp);
        let backup_path = backup_dir.join(filename);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup_path)
        {
            Ok(mut file) => {
                if let Err(error) = file.write_all(encrypted) {
                    let _ = fs::remove_file(&backup_path);
                    return Err(error.into());
                }
                return Ok(backup_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                timestamp = timestamp
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("backup timestamp exhausted"))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

impl WardenSecurity {
    pub fn backup_file(&self, file_path: &Path, content: &[u8]) -> Result<PathBuf> {
        let path_str = file_path.to_string_lossy();
        if path_str.contains("dracon/backups") || path_str.contains("arcane/backups") {
            return Err(anyhow::anyhow!(
                "Recursion guard: Skipping backup of backup file"
            ));
        }

        // Auto-ensure our key is in the repo before we do anything that might rely on it later

        let home = self.get_home()?;
        let backup_dir = home.join(".dracon").join("backups");
        fs::create_dir_all(&backup_dir)?;

        // Hash the path to create a deterministic but safe filename
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        // Use nanoseconds in the filename so rapid backups do not collide.
        // The exclusive create below is still required: clock resolution can
        // be coarser than nanoseconds, and concurrent callers may observe the
        // same timestamp.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        // Encrypt logic (using encrypt_v2_for_all)
        let encrypted = self.encrypt_v2_for_all(content)?;

        write_backup(&backup_dir, &hash_hex, &encrypted, timestamp)
    }

    pub fn restore_file(&self, file_path: &Path) -> Result<PathBuf> {
        refuse_unfenced_git_metadata_write(file_path, "Warden backup restore")?;
        let home = self.get_home()?;
        let backup_dir = home.join(".dracon").join("backups");

        if !backup_dir.exists() {
            return Err(anyhow::anyhow!(
                "No backups found for file: {:?}",
                file_path
            ));
        }

        // Hash the path to find matching backups
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        // Find matching backup files
        let mut backups = Vec::new();
        if backup_dir.exists() {
            for entry in fs::read_dir(&backup_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Check if file starts with the hash
                    if name.starts_with(&hash_hex) && name.ends_with(".age") {
                        backups.push(path);
                    }
                }
            }
        }

        if backups.is_empty() {
            return Err(anyhow::anyhow!(
                "No backups found for file: {:?}",
                file_path
            ));
        }

        // Sort to get the latest
        backups.sort();
        let latest_backup = backups
            .last()
            .ok_or_else(|| anyhow::anyhow!("No backups found for file: {:?}", file_path))?;

        // Decrypt
        let encrypted_content = fs::read(latest_backup)?;
        let decrypted_content = self.unlock_payload(&encrypted_content)?;

        // Write back only after validating that the final target is a regular,
        // single-link inode; never truncate a metadata hard-link alias.
        write_single_link_file(file_path, &decrypted_content)?;

        Ok(latest_backup.clone())
    }

    pub fn list_backups(&self, file_path: &Path) -> Result<Vec<PathBuf>> {
        let home = self.get_home()?;
        let backup_dir = home.join(".dracon").join("backups");

        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        // Hash the path to find matching backups
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        // Find matching backup files
        let mut backups = Vec::new();
        for entry in fs::read_dir(&backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Check if file starts with the hash
                if name.starts_with(&hash_hex) && name.ends_with(".age") {
                    backups.push(path);
                }
            }
        }

        // Sort reverse (newest first)
        backups.sort_by(|a, b| b.cmp(a));

        Ok(backups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_backup_retries_when_timestamp_already_exists() {
        let temp_dir = tempfile::tempdir().expect("create temporary backup directory");

        let first = write_backup(temp_dir.path(), "path-hash", b"first", 123);
        let first = first.expect("first backup should be created");
        let second = write_backup(temp_dir.path(), "path-hash", b"second", 123);
        let second = second.expect("colliding backup should be retried");

        assert_eq!(
            first.file_name().and_then(|name| name.to_str()),
            Some("path-hash_123.age")
        );
        assert_eq!(
            second.file_name().and_then(|name| name.to_str()),
            Some("path-hash_124.age")
        );
        assert_eq!(fs::read(first).expect("read first backup"), b"first");
        assert_eq!(fs::read(second).expect("read second backup"), b"second");
    }
}

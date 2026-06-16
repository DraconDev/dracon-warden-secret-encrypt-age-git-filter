//! Backup and restore operations for encrypted files.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::WardenSecurity;

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

        // Timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Filename: <hash>_<timestamp>.age
        let filename = format!("{}_{}.age", hash_hex, timestamp);
        let backup_path = backup_dir.join(filename);

        // Encrypt logic (using encrypt_v2_for_all)
        let encrypted = self.encrypt_v2_for_all(content)?;

        fs::write(&backup_path, encrypted)?;
        Ok(backup_path)
    }

    pub fn restore_file(&self, file_path: &Path) -> Result<PathBuf> {
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

        // Write back
        fs::write(file_path, decrypted_content)?;

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

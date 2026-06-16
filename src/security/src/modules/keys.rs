//! Key types for encryption.

use age::x25519;
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

const REPO_KEY_LEN: usize = 32;

pub struct RepoKey(pub Vec<u8>);

impl RepoKey {
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() != REPO_KEY_LEN {
            return Err(anyhow::anyhow!("Invalid key length"));
        }
        Ok(RepoKey(bytes))
    }

    pub fn get_key(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub fn from_vec(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() == 32 {
            Some(RepoKey(bytes))
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        RepoKey(bytes.to_vec())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TeamKey(pub Vec<u8>);

impl TeamKey {
    pub fn to_public(&self) -> Result<age::x25519::Recipient> {
        let key_str = String::from_utf8(self.0.clone())
            .map_err(|_| anyhow::anyhow!("TeamKey contains invalid UTF-8"))?;
        let identity = x25519::Identity::from_str(&key_str)
            .map_err(|_| anyhow::anyhow!("TeamKey is not a valid x25519 identity"))?;
        Ok(identity.to_public())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub fn from_identity_string(s: String) -> Self {
        TeamKey(s.into_bytes())
    }
}

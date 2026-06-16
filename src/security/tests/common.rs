use std::sync::Mutex;
use tempfile::TempDir;

pub struct HomeGuard {
    _temp_home: TempDir,
    original_home: Option<String>,
}

static ENV_MUTEX: Mutex<()> = Mutex::new(());

impl HomeGuard {
    pub fn new() -> Self {
        let _lock = ENV_MUTEX.lock().expect("env lock poisoned");
        let original_home = std::env::var("HOME").ok();
        let temp_home = TempDir::new().expect("create temp dir");
        std::env::set_var("HOME", temp_home.path());
        Self {
            _temp_home: temp_home,
            original_home,
        }
    }
}

impl Default for HomeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        std::env::remove_var("HOME");
        if let Some(h) = &self.original_home {
            std::env::set_var("HOME", h);
        }
    }
}

/// Restores an environment variable to its original value on drop.
#[allow(dead_code)]
pub struct EnvRestorer {
    key: String,
    old_value: Option<String>,
}

#[allow(dead_code)]
impl EnvRestorer {
    /// Saves current value of `key`, sets it to `new_value`.
    /// On Drop: restores the original value (or removes if unset).
    pub fn new(key: &str, new_value: &str) -> Self {
        let _lock = ENV_MUTEX.lock().expect("env lock poisoned");
        let old_value = std::env::var(key).ok();
        std::env::set_var(key, new_value);
        EnvRestorer {
            key: key.to_string(),
            old_value,
        }
    }
}

#[allow(dead_code)]
impl Drop for EnvRestorer {
    fn drop(&mut self) {
        std::env::remove_var(&self.key);
        if let Some(ref v) = self.old_value {
            std::env::set_var(&self.key, v);
        }
    }
}

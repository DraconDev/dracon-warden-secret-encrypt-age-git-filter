use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

pub struct HomeGuard {
    _temp_home: TempDir,
    original_home: Option<String>,
    // FIXED 2026-07-21 (v0.112.33, audit F4.9): the guard now HOLDS
    // the env mutex for its whole lifetime — the pre-fix code locked
    // it in a LOCAL binding (`let _lock = ...`) that was dropped
    // when `new()` returned, so the mutex was held only during the
    // `set_var` call and every HOME-mutating test ran in parallel
    // (cross-test contamination via the OnceCell-cached identities
    // keyed by whatever HOME was at first init).
    _lock: MutexGuard<'static, ()>,
}

static ENV_MUTEX: Mutex<()> = Mutex::new(());

impl HomeGuard {
    pub fn new() -> Self {
        let lock = ENV_MUTEX.lock().expect("env lock poisoned");
        let original_home = std::env::var("HOME").ok();
        let temp_home = TempDir::new().expect("create temp dir");
        std::env::set_var("HOME", temp_home.path());
        Self {
            _temp_home: temp_home,
            original_home,
            _lock: lock,
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
        // FIXED 2026-07-21 (v0.112.33, audit F4.9): restore the old
        // value DIRECTLY (overwrite) instead of remove-then-set,
        // which left HOME briefly unset for racing readers.
        if let Some(h) = &self.original_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

/// Restores an environment variable to its original value on drop.
#[allow(dead_code)]
pub struct EnvRestorer {
    key: String,
    old_value: Option<String>,
    // FIXED 2026-07-21 (v0.112.33, audit F4.9): hold the mutex for
    // the guard's lifetime (see HomeGuard above).
    _lock: MutexGuard<'static, ()>,
}

#[allow(dead_code)]
impl EnvRestorer {
    /// Saves current value of `key`, sets it to `new_value`.
    /// On Drop: restores the original value (or removes if unset).
    pub fn new(key: &str, new_value: &str) -> Self {
        let lock = ENV_MUTEX.lock().expect("env lock poisoned");
        let old_value = std::env::var(key).ok();
        std::env::set_var(key, new_value);
        EnvRestorer {
            key: key.to_string(),
            old_value,
            _lock: lock,
        }
    }
}

#[allow(dead_code)]
impl Drop for EnvRestorer {
    fn drop(&mut self) {
        // FIXED 2026-07-21 (v0.112.33, audit F4.9): overwrite
        // directly instead of remove-then-set.
        if let Some(ref v) = self.old_value {
            std::env::set_var(&self.key, v);
        } else {
            std::env::remove_var(&self.key);
        }
    }
}

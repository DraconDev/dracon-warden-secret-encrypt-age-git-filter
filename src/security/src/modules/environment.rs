//! Environment file management.

use anyhow::Result;

#[derive(Default)]
pub struct EnvironmentManager {
    pub variables: std::collections::HashMap<String, String>,
    pub secrets: std::collections::HashMap<String, std::collections::HashMap<String, String>>, // Grouped secrets
}

impl EnvironmentManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_variable(&mut self, key: String, value: String) {
        self.variables.insert(key, value);
    }

    pub fn add_secret(&mut self, group: String, key: String, value: String) {
        self.secrets.entry(group).or_default().insert(key, value);
    }

    pub fn to_env_file(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.variables {
            out.push_str(&format!("{}=\"{}\"\n", k, v.replace('"', "\\\"")));
        }
        for (group, vars) in &self.secrets {
            out.push_str(&format!("# Group: {}\n", group));
            for (k, v) in vars {
                out.push_str(&format!("{}=\"{}\"\n", k, v.replace('"', "\\\"")));
            }
        }
        out
    }

    /// Load variables from a .env file path
    pub fn load_from_env_file(&mut self, path: &std::path::Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                let mut value = v.trim().to_string();
                // Strip quotes if present
                if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value = value[1..value.len() - 1].to_string();
                }
                self.add_variable(key, value);
            }
        }
        Ok(())
    }
}

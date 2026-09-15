//! warden-showcase probe (2026-09-15): a `config/creds.json` whose secrets sit
//! under every inline-scanner floor (14-char password < 16-char minimum,
//! non-keyword key names like `stripe`/`url`, JSON colon form) passed through
//! `smart_clean_with_path` untouched. A file literally named `creds.json`
//! declares credentials content, so it gets whole-file age encryption like
//! `credentials` — structure and values both hidden, regardless of shape.

use anyhow::Result;
use dracon_security::WardenSecurity;

// Mirrors the showcase probe file: short password, provider key under a
// non-keyword name, password-bearing URL under a non-keyword name.
const CREDS_JSON: &str = r#"{
  "app": "warden-showcase",
  "database": {
    "password": "D3m0DbP@ssw0rd!",
    "url": "mongodb+srv://warden:D3m0DbP@ssw0rd%21@cluster.example.net/warden?ssl=true"
  },
  "api_keys": {
    "stripe": "sk_live_4eC39HqLyjWDarwQaBcDeFgHiJkLmN"
  }
}"#;

fn test_security() -> Result<WardenSecurity> {
    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);
    Ok(security.with_managed_patterns(vec![
        "config/creds.json".to_string(),
        "**/creds.json".to_string(),
    ]))
}

#[test]
fn creds_json_gets_whole_file_encryption() -> Result<()> {
    let security = test_security()?;
    let cleaned =
        security.smart_clean_with_path(CREDS_JSON.as_bytes(), "config/creds.json")?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "creds.json was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    for leaked in [
        "D3m0DbP@ssw0rd!",
        "sk_live_4eC39HqLyjWDarwQaBcDeFgHiJkLmN",
        "cluster.example.net",
    ] {
        assert!(
            !cleaned.contains(leaked),
            "plaintext leaked through clean filter: {}",
            leaked
        );
    }
    Ok(())
}

#[test]
fn creds_json_round_trips_through_smudge() -> Result<()> {
    let security = test_security()?;
    let cleaned =
        security.smart_clean_with_path(CREDS_JSON.as_bytes(), "config/creds.json")?;
    let cleaned_str = String::from_utf8(cleaned).expect("clean output is UTF-8");
    let restored = security.smart_smudge(&cleaned_str)?;
    assert_eq!(
        restored, CREDS_JSON,
        "smudge did not restore creds.json byte-exact"
    );
    Ok(())
}

#[test]
fn creds_json_at_any_depth_gets_whole_file_encryption() -> Result<()> {
    let security = test_security()?;
    let cleaned = security.smart_clean_with_path(
        CREDS_JSON.as_bytes(),
        "some/nested/dir/creds.json",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "nested creds.json was not whole-file encrypted"
    );
    Ok(())
}

//! warden-showcase probe round 2 (2026-09-15): the recreated showcase used
//! `keys.json` (AKIA/sk_live/AIzaSy shapes under keyword key names) — the
//! same novel-filename gap as `creds.json`. Files literally named `keys.json`
//! get whole-file age encryption.
//!
//! NOTE: fixture values are deliberately synthetic and kept under GitHub
//! push-protection floors (documented example keys, short runs) — the gate
//! under test is filename-based, so any content exercises it. Do NOT
//! "realism-fix" these into flaggable shapes.

use anyhow::Result;
use dracon_security::WardenSecurity;

const KEYS_JSON: &str = r#"{
  "serviceAccounts": {
    "stripe": {
      "secretKey": "sk_live_1111222233334444",
      "webhookSecret": "whsec_1234"
    },
    "aws": {
      "accessKeyId": "EXAMPLE_ACCESS_ID",
      "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "gcp": {
      "apiKey": "AIzaSyD-EXAMPLE-1234"
    }
  }
}"#;

fn test_security() -> Result<WardenSecurity> {
    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);
    Ok(security.with_managed_patterns(vec![
        "config/keys.json".to_string(),
        "**/keys.json".to_string(),
    ]))
}

#[test]
fn keys_json_gets_whole_file_encryption() -> Result<()> {
    let security = test_security()?;
    let cleaned = security.smart_clean_with_path(KEYS_JSON.as_bytes(), "keys.json")?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "keys.json was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    for leaked in [
        "EXAMPLE_ACCESS_ID",
        "sk_live_1111222233334444",
        "AIzaSyD-EXAMPLE-1234",
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
fn keys_json_round_trips_through_smudge() -> Result<()> {
    let security = test_security()?;
    let cleaned = security.smart_clean_with_path(KEYS_JSON.as_bytes(), "keys.json")?;
    let cleaned_str = String::from_utf8(cleaned).expect("clean output is UTF-8");
    let restored = security.smart_smudge(&cleaned_str)?;
    assert_eq!(
        restored, KEYS_JSON,
        "smudge did not restore keys.json byte-exact"
    );
    Ok(())
}

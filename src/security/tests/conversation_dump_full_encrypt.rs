//! 2026-09-30: LLM conversation/session exports (`conversation-*.txt`,
//! `pi-session-*.html`, ...) get whole-file age encryption like
//! `creds.json` — dumps carry pasted secrets, credentials, internal paths,
//! and PII in free prose, so inline scanning is the wrong tool (and a
//! multi-MB HTML dump costs ~16 s of regex). Same-prefix non-dump source
//! (`pi-session-retention-purge.service`, `conversation-service.rs`) must
//! stay inline-scanned, never whole-file encrypted.

use anyhow::Result;
use dracon_security::{is_llm_conversation_dump, WardenSecurity};

// Fake Muse export: prose plus pasted credential-shaped values that sit
// under every inline-scanner floor. No live-format tokens anywhere.
const CONVERSATION_TXT: &str = concat!(
    "Muse Code Conversation Export\n",
    "=============================\n",
    "\n",
    "Exported At: 2026-09-27 12:41:38 UTC\n",
    "Session: 01a0de24-99a7-7fc1-a85a-0ad09e144ee2\n",
    "Workspace: /home/operator/Dev/example-app\n",
    "\n",
    "## Conversation\n",
    "\n",
    "user: the staging db password is db-Stag1ng-fake-pw42, connection\n",
    "string is postgres://app:db-Stag1ng-fake-pw42@db.internal.example/staging\n",
    "\n",
    "assistant: noted, I will use /home/operator/.config/example/token-store\n",
    "for the deploy. Contact janedoe@example.com for the rotation.\n",
);

// Fake Pi session export: same sensitivity class, HTML shape.
const PI_SESSION_HTML: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html lang=\"en\">\n",
    "<head><title>Session Export</title></head>\n",
    "<body>\n",
    "<p>Session: 01a0e2e2-d060-718e-b988-38dcb0ff6fe7</p>\n",
    "<p>user: prod api key for the widget service is ",
    "widget-prod-fake-key-007 (rotate after the demo)</p>\n",
    "<p>workspace: /home/operator/Dev/widget-service</p>\n",
    "</body>\n",
    "</html>\n",
);

const SYSTEMD_UNIT: &str = concat!(
    "[Unit]\n",
    "Description=Pi session retention purge\n",
    "After=network.target\n",
    "\n",
    "[Service]\n",
    "Type=oneshot\n",
    "ExecStart=/usr/bin/pi-session-retention-purge\n",
    "\n",
    "[Install]\n",
    "WantedBy=multi-user.target\n",
);

const CONVERSATION_SOURCE: &str =
    "pub fn conversation_service() -> &'static str {\n    \"not a dump\"\n}\n";

fn test_security(patterns: Vec<String>) -> Result<WardenSecurity> {
    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);
    Ok(security.with_managed_patterns(patterns))
}

/// Mirrors the warden binary's effective list shape: operator entries plus
/// the shipped conversation defaults.
fn effective_like_patterns() -> Vec<String> {
    vec![
        "config/services.json".to_string(),
        "conversation-*.txt".to_string(),
        "pi-session-*.html".to_string(),
    ]
}

#[test]
fn conversation_txt_gets_whole_file_encryption() -> Result<()> {
    let security = test_security(effective_like_patterns())?;
    let cleaned = security.smart_clean_with_path(
        CONVERSATION_TXT.as_bytes(),
        "conversation-2026-09-27-124138.txt",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "conversation export was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    for leaked in [
        "db-Stag1ng-fake-pw42",
        "db.internal.example",
        "janedoe@example.com",
        "/home/operator/Dev/example-app",
    ] {
        assert!(
            !cleaned.contains(leaked),
            "dump plaintext leaked through clean filter: {}",
            leaked
        );
    }
    Ok(())
}

#[test]
fn conversation_txt_round_trips_through_smudge() -> Result<()> {
    let security = test_security(effective_like_patterns())?;
    let cleaned = security.smart_clean_with_path(
        CONVERSATION_TXT.as_bytes(),
        "conversation-2026-09-27-124138.txt",
    )?;
    let cleaned_str = String::from_utf8(cleaned).expect("clean output is UTF-8");
    let restored = security.smart_smudge(&cleaned_str)?;
    assert_eq!(
        restored, CONVERSATION_TXT,
        "smudge did not restore conversation export byte-exact"
    );
    Ok(())
}

#[test]
fn pi_session_html_at_depth_gets_whole_file_encryption() -> Result<()> {
    let security = test_security(effective_like_patterns())?;
    let path =
        "exports/pi-session-2026-09-27T12-41-50-432Z_01a0e2e2-d060-718e-b988-38dcb0ff6fe7.html";
    let cleaned = security.smart_clean_with_path(PI_SESSION_HTML.as_bytes(), path)?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "pi-session export was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    for leaked in [
        "widget-prod-fake-key-007",
        "/home/operator/Dev/widget-service",
    ] {
        assert!(
            !cleaned.contains(leaked),
            "dump plaintext leaked through clean filter: {}",
            leaked
        );
    }
    Ok(())
}

#[test]
fn pi_session_systemd_unit_is_not_whole_file_encrypted() -> Result<()> {
    // Even under a hypothetical broad `pi-session-*` protected entry, the
    // filename rule's extension gate must keep the systemd unit on the
    // inline-scan path (content has no secrets, so it passes through).
    let security = test_security(vec!["pi-session-*".to_string()])?;
    let cleaned = security.smart_clean_with_path(
        SYSTEMD_UNIT.as_bytes(),
        "systemd/pi-session-retention-purge.service",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        !cleaned.starts_with("[DRACON_SECRET:"),
        "systemd unit was wrongly whole-file encrypted"
    );
    assert!(
        cleaned.contains("Description=Pi session retention purge"),
        "systemd unit content was mangled:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    Ok(())
}

#[test]
fn conversation_source_file_is_not_whole_file_encrypted() -> Result<()> {
    // Same gate for a same-prefix source file under a broad entry.
    let security = test_security(vec!["conversation-*".to_string()])?;
    let cleaned = security.smart_clean_with_path(
        CONVERSATION_SOURCE.as_bytes(),
        "src/conversation-service.rs",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        !cleaned.starts_with("[DRACON_SECRET:"),
        "source file was wrongly whole-file encrypted"
    );
    assert!(
        cleaned.contains("pub fn conversation_service()"),
        "source content was mangled:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    Ok(())
}

#[test]
fn trajectory_json_gets_whole_file_encryption() -> Result<()> {
    // 2026-09-30 audit: `muse export` default output (RAW transcript).
    let security = test_security(vec!["trajectory-*.json".to_string()])?;
    let export = r#"{"export_schema_version":1,"session":"01a0f3aa","messages":[{"role":"user","content":"deploy token widget-prod-fake-key-007"}]}"#;
    let cleaned = security.smart_clean_with_path(
        export.as_bytes(),
        "trajectory-2026-09-30-120000.json",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "trajectory export was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    assert!(
        !cleaned.contains("widget-prod-fake-key-007"),
        "transcript plaintext leaked through clean filter"
    );
    Ok(())
}

#[test]
fn rollout_jsonl_gets_whole_file_encryption() -> Result<()> {
    // 2026-09-30 audit: Codex session transcript copied into a repo.
    let security = test_security(vec!["rollout-*.jsonl".to_string()])?;
    let rollout = r#"{"ts":"2026-09-04T20:31:57","type":"message","content":"db password db-Stag1ng-fake-pw42"}"#;
    let cleaned = security.smart_clean_with_path(
        rollout.as_bytes(),
        "audit/rollout-2026-09-04T20-31-57-01a06de8-0650-7900-a97d-dfbc8e179a76.jsonl",
    )?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        cleaned.starts_with("[DRACON_SECRET:"),
        "rollout transcript was not whole-file encrypted:\n{}",
        &cleaned[..cleaned.len().min(200)]
    );
    assert!(
        !cleaned.contains("db-Stag1ng-fake-pw42"),
        "transcript plaintext leaked through clean filter"
    );
    Ok(())
}

#[test]
fn rollout_prose_doc_is_not_whole_file_encrypted() -> Result<()> {
    // `rollout-` is transcript-only: deploy rollout docs stay inline-scanned.
    let security = test_security(vec!["rollout-*.jsonl".to_string(), "rollout-*.md".to_string()])?;
    let cleaned =
        security.smart_clean_with_path(b"# Rollout plan\n\nWave 1: canary.\n", "rollout-plan.md")?;
    let cleaned = String::from_utf8(cleaned).expect("clean output is UTF-8");
    assert!(
        !cleaned.starts_with("[DRACON_SECRET:"),
        "deploy doc was wrongly whole-file encrypted"
    );
    assert!(cleaned.contains("Wave 1: canary."), "doc content mangled");
    Ok(())
}

#[test]
fn dump_predicate_matches_only_dump_extensions() {
    // Observed real-world names plus every shipped extension.
    for name in [
        "conversation-2026-09-27-124138.txt",
        "conversation-2026-09-27-124138.md",
        "conversation-2026-09-27-124138.json",
        "conversation-2026-09-27-124138.html",
        "pi-session-2026-09-27T12-41-50-432Z_01a0e2e2-d060-718e-b988-38dcb0ff6fe7.html",
        "pi-session-2026-09-27T12-41-50-432Z_01a0e2e2-d060-718e-b988-38dcb0ff6fe7.txt",
        "pi-session-2026-09-27T12-41-50-432Z_01a0e2e2-d060-718e-b988-38dcb0ff6fe7.md",
        "pi-session-2026-09-27T12-41-50-432Z_01a0e2e2-d060-718e-b988-38dcb0ff6fe7.json",
        "trajectory-2026-09-30-120000.json",
        "trajectory-2026-09-30-120000.txt",
        "trajectory-2026-09-30-120000.md",
        "trajectory-2026-09-30-120000.html",
        "rollout-2026-09-04T20-31-57-01a06de8-0650-7900-a97d-dfbc8e179a76.jsonl",
        "rollout-2026-09-04T20-31-57-01a06de8-0650-7900-a97d-dfbc8e179a76.json",
    ] {
        assert!(is_llm_conversation_dump(name), "dump not matched: {name}");
    }
    // Same-prefix source and unrelated files must not match.
    for name in [
        "pi-session-retention-purge.service",
        "pi-session-retention-purge.timer",
        "conversation-service.rs",
        "conversation-handler.ts",
        "rollout-plan.md",
        "rollout-notes.txt",
        "my-conversation-notes.txt",
        "trajectories.md",
        "conversation.txt",
        "pi-session.html",
        ".env",
        "creds.json",
    ] {
        assert!(!is_llm_conversation_dump(name), "non-dump matched: {name}");
    }
}

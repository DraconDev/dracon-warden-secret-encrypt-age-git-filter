//! Integration tests for dracon-warden.
//!
//! These tests verify end-to-end behavior using real git repos.

use std::path::PathBuf;

/// Helper to run a git command.
fn git_cmd(repo: &PathBuf, args: &[&str]) -> std::process::Output {
    let git_bin = std::env::var("DRACON_SYNC_GIT_BIN")
        .unwrap_or_else(|_| "/run/current-system/sw/bin/git".to_string());
    std::process::Command::new(&git_bin)
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap()
}

/// Helper to create a test repo.
fn create_test_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_cmd(&repo, &["init", "-q", "-b", "master"]);
    git_cmd(&repo, &["config", "user.email", "test@test.com"]);
    git_cmd(&repo, &["config", "user.name", "Test"]);
    tmp
}

#[test]
fn test_warden_status() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("status")
        .output()
        .unwrap();
    // Status might fail if no policy exists, but shouldn't crash
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("policy"),
        "warden status should not crash: {}",
        stderr
    );
}

#[test]
fn test_warden_keygen() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    // Set HOME to temp dir
    unsafe { std::env::set_var("HOME", &home) };

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("keygen")
        .output()
        .unwrap();

    // Should succeed or fail gracefully (key might already exist)
    assert!(
        output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("already exists"),
        "keygen should succeed or report existing key: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_warden_once_single_repo() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("once")
        .arg(&repo)
        .output()
        .unwrap();

    // Might fail if no policy exists, but shouldn't crash
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("policy"),
        "warden once should not crash: {}",
        stderr
    );
}

#[test]
fn test_warden_filter_clean() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    // First, set up warden
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("once")
        .arg(&repo)
        .output();

    // Now test filter clean
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("filter-clean")
        .current_dir(&repo)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "filter-clean should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_warden_filter_smudge() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    // First, set up warden
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("once")
        .arg(&repo)
        .output();

    // Test filter smudge with empty content (should pass through)
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("filter-smudge")
        .current_dir(&repo)
        .output()
        .unwrap();

    // Should succeed (empty input passes through)
    assert!(
        output.status.success(),
        "filter-smudge should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_warden_scrub_markers() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    // Create a file with a marker
    std::fs::write(repo.join("test.json"), r#"{"key": "DRACON_SECRET_marker"}"#).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("scrub-markers")
        .arg(&repo)
        .output()
        .unwrap();

    // Should succeed (dry run by default) or fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("policy"),
        "scrub-markers should not crash: {}",
        stderr
    );
}

#[test]
fn test_warden_repair_dry_run() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("repair")
        .arg("--dry-run")
        .arg(&repo)
        .output()
        .unwrap();

    // Should succeed (dry run) or fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("policy"),
        "repair --dry-run should not crash: {}",
        stderr
    );
}

#[test]
fn test_warden_setup_hooks_local() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("setup-hooks")
        .arg("--local")
        .arg(&repo)
        .output()
        .unwrap();

    // Should succeed or fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("hooksPath"),
        "setup-hooks --local should not crash: {}",
        stderr
    );
}

#[test]
fn test_warden_cli_help() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "help should succeed");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("dracon-warden"),
        "help should mention binary name"
    );
    assert!(
        help.contains("setup-hooks"),
        "help should list setup-hooks command"
    );
}

#[test]
fn test_warden_resmudge_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_cmd(&repo, &["init", "-q", "-b", "master"]);
    git_cmd(&repo, &["config", "user.email", "test@test.com"]);
    git_cmd(&repo, &["config", "user.name", "Test"]);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("resmudge")
        .arg("--apply")
        .arg(&repo)
        .output()
        .unwrap();

    // May fail if no policy exists, but shouldn't crash
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("policy"),
        "resmudge should not crash: {}",
        stderr
    );
}

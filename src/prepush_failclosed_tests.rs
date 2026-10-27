//! Incident regression: scan failure must not become an empty/safe diff.
use super::*;

#[test]
fn prepush_scan_io_failure_refuses_while_harmless_change_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let hook = tmp.path().join("pre-push");
    std::fs::write(&hook, render_hook(PRE_PUSH_HOOK, None)).unwrap();
    let output = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/reproduce-prepush-io-failopen.py"))
        .arg("--hook")
        .arg(&hook)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["normal_scan"]["refused"], true, "synthetic secret control must fail");
    assert_eq!(report["harmless_scan"]["refused"], false, "a normal harmless change must pass");
    assert_eq!(report["failed_scan"]["refused"], true, "I/O failure must refuse, never mean no secrets");
    assert_eq!(report["fail_open_reproduced"], false);
}

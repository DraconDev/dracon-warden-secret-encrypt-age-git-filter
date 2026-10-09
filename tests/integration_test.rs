//! Integration tests for dracon-warden.
//!
//! These tests verify end-to-end behavior using real git repos.

use std::path::PathBuf;

/// Helper to run a git command.
fn git_cmd(repo: &PathBuf, args: &[&str]) -> std::process::Output {
    let git_bin = std::env::var("DRACON_SYNC_GIT_BIN").unwrap_or_else(|_| "git".to_string());
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

#[cfg(unix)]
#[test]
fn test_warden_repair_rejects_tracked_symlinks_end_to_end() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_cmd(&repo, &["init", "-q", "-b", "master"]);

    let external_json = tmp.path().join("external.json");
    let external_json_contents = br#"{"secret":"[DRACON_SECRET:external]"}"#;
    std::fs::write(&external_json, external_json_contents).unwrap();
    symlink(&external_json, repo.join("public.json")).unwrap();

    let external_ciphertext = tmp.path().join("external-ciphertext");
    let external_ciphertext_contents = b"[DRACON_SECRET:external]\n";
    std::fs::write(&external_ciphertext, external_ciphertext_contents).unwrap();
    symlink(&external_ciphertext, repo.join("secret.txt")).unwrap();

    let external_env = tmp.path().join("external.env");
    let external_env_contents = b"API_KEY=plaintext\n";
    std::fs::write(&external_env, external_env_contents).unwrap();
    symlink(&external_env, repo.join(".env")).unwrap();

    git_cmd(
        &repo,
        &["add", "-f", "--", "public.json", "secret.txt", ".env"],
    );

    let policy = tmp.path().join("warden.toml");
    std::fs::write(
        &policy,
        r#"
protected_patterns = ["secret.txt"]
repo_roots = []
"#,
    )
    .unwrap();
    let empty_global_gitconfig = tmp.path().join("gitconfig");
    std::fs::write(&empty_global_gitconfig, "").unwrap();

    // `repair` applies changes by default; there is no `repair --apply` CLI
    // flag. Exercise that real apply pipeline rather than calling helpers.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("repair")
        .arg(&repo)
        .env("DRACON_WARDEN_POLICY", &policy)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &empty_global_gitconfig)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "repair apply should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skipping marker scrub") && stderr.contains("public.json"),
        "repair must reject the scrub loop's symlink: {stderr}"
    );
    assert!(
        stderr.contains("skipping resmudge") && stderr.contains("secret.txt"),
        "repair must reject the resmudge loop's symlink: {stderr}"
    );
    assert!(
        stderr.contains("skipping header backfill") && stderr.contains(".env"),
        "repair must reject the header loop's symlink: {stderr}"
    );

    assert!(std::fs::symlink_metadata(repo.join("public.json"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(std::fs::symlink_metadata(repo.join("secret.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(std::fs::symlink_metadata(repo.join(".env"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read(&external_json).unwrap(),
        external_json_contents
    );
    assert_eq!(
        std::fs::read(&external_ciphertext).unwrap(),
        external_ciphertext_contents
    );
    assert_eq!(std::fs::read(&external_env).unwrap(), external_env_contents);
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

/// Live git through the long-running process driver (v0.113.13):
/// `git diff` and `git add` on a repo with MANY files must flow
/// through ONE `filter-process` invocation with content intact.
/// Regression for the 2026-09-19 firehose stall (4092-file diff at
/// 78s via per-file `filter-clean` spawns, starving ai-auto-writer
/// for 2h+ behind a 30s classification budget).
#[test]
fn test_filter_process_live_git_diff_and_add() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");
    let warden_bin = env!("CARGO_BIN_EXE_dracon-warden");
    // Long-running driver instead of the per-file clean/smudge pair.
    git_cmd(
        &repo,
        &[
            "config",
            "filter.dracon.process",
            &format!("{} filter-process", warden_bin),
        ],
    );
    git_cmd(&repo, &["config", "filter.dracon.required", "true"]);
    std::fs::write(repo.join(".gitattributes"), "* filter=dracon\n").unwrap();
    // 300 files: enough that per-file process startup would dominate
    // (and enough to prove the single driver serves every file).
    for i in 0..300 {
        std::fs::write(
            repo.join(format!("file{:03}.txt", i)),
            format!("prose body {}\n", i),
        )
        .unwrap();
    }
    let add = git_cmd(&repo, &["add", "-A"]);
    assert!(
        add.status.success(),
        "add through filter-process must succeed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    // --no-verify: this test exercises the filter-PROCESS driver, not
    // hooks — the operator's ambient global pre-commit hook must not
    // gate the fixture commit (2026-10-03: the R4-W-03 key-completeness
    // gate blocked it for a missing diff.dracon.textconv). Filters
    // still run; only the hook is skipped.
    let commit = git_cmd(&repo, &["commit", "-qm", "seed", "--no-verify"]);
    assert!(commit.status.success());
    // Modify every file, then diff through the driver.
    for i in 0..300 {
        std::fs::write(
            repo.join(format!("file{:03}.txt", i)),
            format!("prose body {} revised\n", i),
        )
        .unwrap();
    }
    let diff = git_cmd(&repo, &["diff", "--name-status", "HEAD"]);
    assert!(
        diff.status.success(),
        "diff through filter-process must succeed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let out = String::from_utf8_lossy(&diff.stdout);
    assert_eq!(out.lines().count(), 300, "all 300 files must diff");
    // Content integrity: the stored blob of an unprotected file
    // must equal the worktree bytes (passthrough, no corruption).
    let show = git_cmd(&repo, &["show", "HEAD:file007.txt"]);
    assert!(show.status.success());
    assert_eq!(show.stdout, b"prose body 7\n");
}

/// pkt-line framing, written out rather than imported: an integration
/// test must exercise the same wire format the driver parses, and
/// `pkt_encode` is not reachable from this crate's integration target.
fn pkt(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

fn pkt_line(text: &str) -> Vec<u8> {
    pkt(format!("{text}\n").as_bytes())
}

/// D2 (audit round 2, HIGH): an oversize size-exempt binary must be
/// addable again through the REAL driver, with real pipes, driven the way
/// git drives it.
///
/// The first cut of the fix streamed the passthrough back as the request
/// arrived. Git's long-running filter protocol has no flow control — it
/// writes the entire request before reading any of the response — so the
/// two sides deadlocked as soon as the response outgrew the 64 KiB pipe
/// buffer while the request still had bytes to write, and `git add` hung
/// forever. Measured on real git 2.51.2 with a 10 MiB limit: a blob 1 KiB
/// over the limit completed, 640 KiB over the limit hung. An in-process
/// test over a `Cursor` cannot see that (no pipe, no blocking), which is
/// why this test drives the real binary over real pipes and only starts
/// reading after the whole request is written, exactly like git.
#[test]
fn test_filter_process_oversize_binary_passthrough_survives_real_pipes() {
    let tmp = tempfile::tempdir().unwrap();
    // `filter_max_bytes` is validated to a 10 MiB floor, so the smallest
    // honest reproduction is a ~11 MiB blob: a 1 MiB over-limit margin is
    // 16x the pipe buffer that used to deadlock the pair.
    let policy = tmp.path().join("warden.toml");
    std::fs::write(
        &policy,
        r#"
protected_patterns = []
repo_roots = []
filter_max_bytes = 10485760
"#,
    )
    .unwrap();
    let empty_global_gitconfig = tmp.path().join("gitconfig");
    std::fs::write(&empty_global_gitconfig, "").unwrap();

    let blob: Vec<u8> = (0..11 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    /// One pkt-line session: handshake, one request, decode the response.
    /// `response` is `(status, content)`; `None` means the driver never
    /// answered within the deadline (the deadlock signature).
    fn drive(
        warden_bin: &str,
        policy: &std::path::Path,
        gitconfig: &std::path::Path,
        command: &str,
        pathname: &str,
        body: &[u8],
    ) -> (String, Vec<u8>) {
        use std::io::{Read, Write};
        use std::sync::mpsc;
        use std::time::Duration;

        let mut child = std::process::Command::new(warden_bin)
            .arg("filter-process")
            .env("DRACON_WARDEN_POLICY", policy)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", gitconfig)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();

        // Git's exact request shape: key lines, a flush, the body in
        // frames, then the terminating flush. Frames stay under the
        // 4-hex-digit pkt-line maximum (0xfff0 total).
        let mut request = Vec::new();
        request.extend(pkt_line("git-filter-client"));
        request.extend(pkt_line("version=2"));
        request.extend(pkt_line("capability=clean"));
        request.extend(pkt_line("capability=smudge"));
        request.extend(b"0000");
        request.extend(pkt_line(&format!("command={command}")));
        request.extend(pkt_line(&format!("pathname={pathname}")));
        request.extend(b"0000");
        for frame in body.chunks(32 * 1024) {
            request.extend(pkt(frame));
        }
        request.extend(b"0000");

        // The whole point: the request goes out in full BEFORE any
        // response byte is read. If the driver answers early on a large
        // blob, this write never completes and the pipes deadlock.
        let (tx, rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let res = stdin.write_all(&request).and_then(|_| stdin.flush());
            let _ = tx.send(res.is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(60)).unwrap_or(false),
            "the driver never drained the request: it answered before the \
             request was written, which deadlocks against real git \
             (pkt-line has no flow control)"
        );
        writer.join().unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let mut raw = Vec::new();
        // Safe to read on this thread: the request is already fully
        // written, so the driver is producing its response and closes
        // stdout at clean EOF.
        stdout
            .read_to_end(&mut raw)
            .expect("read the driver response");
        assert!(
            child.wait().map(|s| s.success()).unwrap_or(false),
            "the driver must exit 0 at clean EOF"
        );

        // Decode: key lines up to the first flush, then the content.
        let (mut status, mut content) = (String::new(), Vec::new());
        let total = raw.len();
        let mut cur = std::io::Cursor::new(raw);
        let mut seen_status = false;
        while cur.position() < total as u64 {
            let mut hdr = [0u8; 4];
            if std::io::Read::read_exact(&mut cur, &mut hdr).is_err() {
                break;
            }
            if &hdr == b"0000" {
                if seen_status {
                    // Content terminator, then the trailing empty list.
                    continue;
                }
                continue;
            }
            if &hdr == b"0001" {
                continue;
            }
            let len = usize::from_str_radix(std::str::from_utf8(&hdr).unwrap(), 16).unwrap();
            let mut payload = vec![0u8; len - 4];
            std::io::Read::read_exact(&mut cur, &mut payload).unwrap();
            if !seen_status {
                let line = String::from_utf8_lossy(&payload);
                if let Some(rest) = line.trim().strip_prefix("status=") {
                    status = rest.to_string();
                    seen_status = true;
                }
                continue;
            }
            content.extend_from_slice(&payload);
        }
        (status, content)
    }

    let bin = env!("CARGO_BIN_EXE_dracon-warden");

    // 1. The D2 goal: an oversize, size-exempt binary is relayed whole.
    let (status, content) = drive(
        bin,
        &policy,
        &empty_global_gitconfig,
        "clean",
        "assets/screenshot.png",
        &blob,
    );
    assert_eq!(status, "success", "a >limit binary must not be refused");
    assert_eq!(
        content.len(),
        blob.len(),
        "the whole blob must come back: no truncation, no dropped tail"
    );
    assert!(content == blob, "relayed content must be byte-identical");

    // 2. The guard the carve-out must not weaken: a >limit TEXT path
    //    still fails closed, with no content.
    let (status, content) = drive(
        bin,
        &policy,
        &empty_global_gitconfig,
        "clean",
        "notes/dump.txt",
        &blob,
    );
    assert_eq!(status, "error", "a >limit text path must still fail closed");
    assert!(content.is_empty(), "a refusal must emit no content");
}

/// Create a test repo WITHOUT the operator's `init.templateDir` hooks:
/// the template ships live warden hooks into every fresh `git init`,
/// which `setup-hooks --local` would preserve as `.dracon-foreign`
/// and chain to — testing the template's hook instead of the one
/// built from this source.
fn create_untemplated_test_repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    let empty_template = tmp.path().join("empty-template");
    std::fs::create_dir_all(&empty_template).unwrap();
    git_cmd(
        &repo,
        &[
            "init",
            "-q",
            "-b",
            "master",
            "--template",
            empty_template.to_str().unwrap(),
        ],
    );
    git_cmd(&repo, &["config", "user.email", "test@test.com"]);
    git_cmd(&repo, &["config", "user.name", "Test"]);
    (tmp, repo)
}

/// Install the warden pre-commit hook into `repo` and return the hooks
/// dir for a hermetic `-c core.hooksPath=` commit (bypasses the
/// operator's global hooksPath so the LOCAL hook under test runs).
fn install_local_precommit(repo: &std::path::Path) -> PathBuf {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("setup-hooks")
        .arg("--local")
        .arg(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "setup-hooks --local must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks = repo.join(".git/hooks");
    assert!(
        hooks.join("pre-commit").exists(),
        "setup-hooks must install a local pre-commit hook"
    );
    hooks
}

/// Commit with the repo's LOCAL hooks dir only.
fn commit_local_hooks(repo: &PathBuf, hooks: &std::path::Path, msg: &str) -> std::process::Output {
    git_cmd(
        repo,
        &[
            "-c",
            &format!("core.hooksPath={}", hooks.display()),
            "commit",
            "-m",
            msg,
        ],
    )
}

/// 2026-10-03 (audit R4-W-05): a bare `.dracon/` dir holding ONLY
/// sync markers must NOT mark the repo warden-MANAGED — commits must
/// succeed. Pre-fix the hook demanded warden filter config and
/// blocked every commit until warden was set up (H-10 class).
#[test]
fn test_precommit_sync_only_dracon_dir_is_not_managed() {
    let (_tmp, repo) = create_untemplated_test_repo();
    let hooks = install_local_precommit(&repo);
    std::fs::create_dir_all(repo.join(".dracon")).unwrap();
    std::fs::write(repo.join(".dracon/dracon-sync.toml"), "# sync-only\n").unwrap();
    std::fs::write(repo.join("hello.txt"), "hello\n").unwrap();
    git_cmd(&repo, &["add", "-A"]);
    let out = commit_local_hooks(&repo, &hooks, "sync-only commit");
    assert!(
        out.status.success(),
        "a sync-only repo (bare .dracon/, no warden markers) must commit freely: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 2026-10-03 (audit R4-W-06): a merge internal error (here: the
/// %O side is missing, so the read fails) exits 2 — NOT 1 — with an
/// INTERNAL ERROR message, and %A is left untouched (no markers).
/// Exit 1 is reserved for routine conflicts (plaintext markers in %A).
#[test]
fn test_merge_internal_error_exits_two_with_current_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ancestor = dir.join("ancestor-missing");
    let current = dir.join("current");
    let other = dir.join("other");
    let current_before = b"line1\nline2-A\nline3\n";
    std::fs::write(&current, current_before).unwrap();
    std::fs::write(&other, b"line1\nline2-B\nline3\n").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("merge")
        .arg(&ancestor)
        .arg(&current)
        .arg(&other)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "internal errors must exit 2 (conflicts exit 1): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("INTERNAL ERROR") && stderr.contains("left untouched"),
        "the operator message must distinguish internal errors: {stderr}"
    );
    assert_eq!(
        std::fs::read(&current).unwrap(),
        current_before,
        "%A must be untouched on internal error"
    );
}

/// 2026-10-03 (audit R4-W-05, positive control): the warden-exclusive
/// `.dracon/data/keys/` marker WITHOUT filter config IS drift and
/// must still block — the fix narrows the probe, it doesn't remove it.
#[test]
fn test_precommit_warden_keys_dir_without_config_blocks_as_drift() {
    let (_tmp, repo) = create_untemplated_test_repo();
    let hooks = install_local_precommit(&repo);
    std::fs::create_dir_all(repo.join(".dracon/data/keys")).unwrap();
    std::fs::write(repo.join("hello.txt"), "hello\n").unwrap();
    git_cmd(&repo, &["add", "-A"]);
    let out = commit_local_hooks(&repo, &hooks, "drift commit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("Warden filter missing"),
        "keys-without-config drift must block with the filter demand, got: {stderr}"
    );
}

/// 2026-10-09 (audit D15, formerly finding F129): a path containing a
/// NEWLINE must REFUSE the push instead of being silently skipped.
///
/// Pre-fix behaviour: every scan reads a `git diff-tree -z` list that
/// was flattened with `tr '\0' '\n'` and iterated with `IFS= read -r`,
/// so `evil\nfile.txt` split into two non-existent fragments. The real
/// file was never a pathspec for the diff-line scan, never entered the
/// added-blob scan, never reached the hatch check and never reached the
/// binary-modified check — it pushed with ZERO output even when it
/// contained a live secret.
///
/// This test drives the real installed hook against a real repo with a
/// real newline-named file (created with `printf '%b'`) and asserts the
/// push is refused, names the reason, and — the security property — that
/// it is refused even when the file holds an unmistakable secret shape.
#[test]
fn test_prepush_newline_named_file_refuses_instead_of_skipping() {
    let (_tmp, repo) = create_untemplated_test_repo();
    let hooks = install_local_hooks(&repo);

    // A file whose NAME contains a newline, holding a live secret shape.
    // `printf '%b'` is the only portable way to create such a name.
    let name = "evil\nsecrets.env";
    let full = repo.join(name.replace('\n', "\\n"));
    // Write via a shell so the newline is literal in the filename.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && printf '%s' 'AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n' > \"$(printf 'evil\\nsecrets.env')\"",
            repo.display()
        ))
        .status()
        .unwrap();
    assert!(status.success(), "could not create the newline-named file");
    assert!(full.join("..").exists());
    assert!(
        std::fs::read_dir(&repo)
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().contains('\n')),
        "the fixture must hold a path with an embedded newline"
    );

    git_cmd(&repo, &["add", "-A"]);
    let commit = git_cmd(&repo, &["commit", "-q", "-m", "newline-named secret"]);
    assert!(
        commit.status.success(),
        "the fixture commit must succeed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // A separate repo acts as the push target so the push is real.
    let remote_dir = _tmp.path().join("remote.git");
    std::fs::create_dir_all(&remote_dir).unwrap();
    git_cmd(&remote_dir, &["init", "-q", "--bare", "-b", "master"]);
    git_cmd(&repo, &["remote", "add", "origin", remote_dir.to_str().unwrap()]);

    let push = push_local_hooks(&repo, &hooks, "origin", "master");
    let stderr = String::from_utf8_lossy(&push.stderr).to_string();
    assert!(
        !push.status.success(),
        "a newline-named path must REFUSE the push — the pre-fix hook pushed it with zero output: {stderr}"
    );
    assert!(
        stderr.contains("NEWLINE") || stderr.contains("newline"),
        "the refusal must name the cause, got: {stderr}"
    );
    assert!(
        stderr.contains("cannot be checked") || stderr.contains("silently"),
        "the refusal must say the file could not be verified, got: {stderr}"
    );
}

/// 2026-10-09 (audit D15, positive control): the SAME scan still passes a
/// normal push whose paths contain spaces — the F4.6 guarantee the
/// NUL handling was introduced for must not regress.
#[test]
fn test_prepush_space_named_file_still_pushes() {
    let (_tmp, repo) = create_untemplated_test_repo();
    let hooks = install_local_hooks(&repo);

    std::fs::create_dir_all(repo.join("sub dir")).unwrap();
    std::fs::write(repo.join("sub dir/prod secrets.env"), "HOST=example.com\n").unwrap();
    std::fs::write(repo.join("plain.txt"), "nothing secret-shaped here\n").unwrap();
    git_cmd(&repo, &["add", "-A"]);
    let commit = git_cmd(&repo, &["commit", "-q", "-m", "space-named files"]);
    assert!(
        commit.status.success(),
        "the fixture commit must succeed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let remote_dir = _tmp.path().join("remote.git");
    std::fs::create_dir_all(&remote_dir).unwrap();
    git_cmd(&remote_dir, &["init", "-q", "--bare", "-b", "master"]);
    git_cmd(&repo, &["remote", "add", "origin", remote_dir.to_str().unwrap()]);

    let push = push_local_hooks(&repo, &hooks, "origin", "master");
    let stderr = String::from_utf8_lossy(&push.stderr).to_string();
    assert!(
        push.status.success(),
        "paths containing SPACES must still push clean: {stderr}"
    );
}

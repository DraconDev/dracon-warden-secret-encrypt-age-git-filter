//! Integration tests for dracon-warden.
//!
//! These tests verify end-to-end behavior using real git repos.

use std::path::{Path, PathBuf};

/// A private HOME for one test process, returned together with the tempdir that
/// owns it.
///
/// INCIDENT 2026-10-27: these tests previously ran `dracon-warden once` and
/// `repair` against the OPERATOR's real HOME. Both commands call
/// `refresh_global_hooks_if_stale()`, so running `cargo test` rewrote the live
/// `~/.config/git/hooks/pre-push` from whichever binary was under test. While a
/// stale installed binary ran the daemon, that meant test runs and the daemon's
/// auto-harden flipped the live hook between the fail-closed and fail-open
/// variants. Any test that can touch global state MUST own a private HOME.
fn private_home(tmp: &tempfile::TempDir) -> PathBuf {
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    home
}

/// Run the built warden binary with a private HOME, so hook refreshes land in
/// the fixture instead of the operator's live hooks directory.
fn warden_in_home(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .args(args)
        .env("HOME", home)
        .output()
        .unwrap()
}

fn warden_with_policy(
    home: &Path,
    policy: &Path,
    global_gitconfig: &Path,
) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"));
    command
        .env("HOME", home)
        .env("DRACON_WARDEN_POLICY", policy)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", global_gitconfig);
    command
}

fn git_cmd_with_private_config(
    repo: &Path,
    global_gitconfig: &Path,
    args: &[&str],
) -> std::process::Output {
    let git_bin = std::env::var("DRACON_SYNC_GIT_BIN").unwrap_or_else(|_| "git".to_string());
    std::process::Command::new(&git_bin)
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", global_gitconfig)
        .output()
        .unwrap()
}

#[cfg(target_os = "linux")]
struct KillChildOnDrop(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for KillChildOnDrop {
    fn drop(&mut self) {
        if self
            .0
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(true)
        {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
fn wait_for_fence_fd(child: &mut std::process::Child, fence_path: &Path) {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("poll resmudge child") {
            panic!("resmudge exited before reaching its metadata fence: {status}");
        }
        let fd_dir = PathBuf::from(format!("/proc/{}/fd", child.id()));
        let opened = std::fs::read_dir(fd_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .any(|path| path == fence_path);
        if opened {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "resmudge never opened its fence descriptor"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

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

/// Read the operator's real global pre-push hook, or None when absent.
///
/// Deliberately reads the LIVE path, not a fixture: the point is to observe
/// whether a test run leaked into the operator's fleet-wide hooks directory.
fn live_pre_push_hook() -> Option<Vec<u8>> {
    std::fs::read(dirs_home()?.join(".config/git/hooks/pre-push")).ok()
}

/// The operator's real HOME, resolved independently of any test-local override.
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// INCIDENT 2026-10-27 regression: hook-refreshing CLI commands must not reach
/// the operator's live hooks from inside the test suite.
///
/// The commands below all call `refresh_global_hooks_if_stale()`. Before the
/// fix they ran with the inherited HOME, so `cargo test` rewrote the live
/// `~/.config/git/hooks/pre-push` — and because that file carried the same
/// warden marker before and after, the daemon and the test suite silently
/// flipped the fleet between the fail-closed and fail-open hook variants.
///
/// This test asserts the live hook's bytes are byte-identical across a real
/// `once` and `repair` invocation, and that the invocation actually landed in
/// the private fixture HOME instead (so it cannot pass by doing nothing).
#[test]
fn hook_refreshing_commands_never_touch_the_operator_home() {
    let Some(before) = live_pre_push_hook() else {
        // No live hook on this machine (CI, fresh container): nothing to leak
        // into, so there is no regression to observe here.
        return;
    };

    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");
    let home = private_home(&tmp);
    let hooks = home.join(".config/git/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    // Refresh is deliberately a DRIFT REPAIR, never a fresh install, so the
    // fixture needs an existing warden-owned hook with stale content. Seeding it
    // makes "the refresh happened" observable; without this the command would
    // legitimately no-op and the unchanged-live-hook assertion would be vacuous.
    let fixture_hook = hooks.join("pre-push");
    std::fs::write(
        &fixture_hook,
        "#!/bin/sh\n# dracon-warden-managed-hook-v1\nstale-fixture-body\n",
    )
    .unwrap();

    let policy = tmp.path().join("warden.toml");
    std::fs::write(
        &policy,
        "watch_roots = []\nrepo_roots = []\nprotected_patterns = [\"secret.txt\"]\n",
    )
    .unwrap();

    for args in [
        vec!["once", repo.to_str().unwrap()],
        vec!["repair", repo.to_str().unwrap()],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
            .args(&args)
            .env("HOME", &home)
            .env("DRACON_WARDEN_POLICY", &policy)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", tmp.path().join("gitconfig"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?} should succeed in a private HOME: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // The refresh really ran — otherwise "live hook unchanged" proves nothing.
    let refreshed = std::fs::read_to_string(&fixture_hook).expect("fixture hook");
    assert!(
        !refreshed.contains("stale-fixture-body"),
        "the private fixture HOME must be where the refresh landed, not the operator's"
    );
    assert!(
        refreshed.contains("dracon-warden-managed-hook-v"),
        "the fixture hook must still be a warden hook after refresh"
    );

    let after = live_pre_push_hook().expect("live hook must still exist");
    assert_eq!(
        before, after,
        "a warden CLI test rewrote the operator's live pre-push hook; hook-refreshing \
         commands must run with a private HOME"
    );
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
    let home = private_home(&tmp);

    // Per-command HOME, not `set_var`: mutating the process environment leaks
    // into parallel tests in this binary (and is unsafe in newer editions).
    let output = warden_in_home(&home, &["keygen"]);

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
    let home = private_home(&tmp);

    let output = warden_in_home(&home, &["once", repo.to_str().unwrap()]);

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

    // First, set up warden (private HOME: `once` refreshes global hooks)
    let home = private_home(&tmp);
    let _ = warden_in_home(&home, &["once", repo.to_str().unwrap()]);

    // Now test filter clean
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("filter-clean")
        .env("HOME", &home)
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

    // First, set up warden (private HOME: `once` refreshes global hooks)
    let home = private_home(&tmp);
    let _ = warden_in_home(&home, &["once", repo.to_str().unwrap()]);

    // Test filter smudge with empty content (should pass through)
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("filter-smudge")
        .env("HOME", &home)
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

#[cfg(target_os = "linux")]
#[test]
fn resmudge_apply_waits_safely_and_releases_the_fence_after_publication() {
    use secrecy::ExposeSecret;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::Duration;

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    let global_gitconfig = tmp.path().join("gitconfig");
    std::fs::write(&global_gitconfig, "").unwrap();
    for (args, label) in [
        (&["init", "-q", "-b", "main"][..], "git init"),
        (
            &["config", "user.email", "test@example.invalid"][..],
            "git email",
        ),
        (&["config", "user.name", "Warden test"][..], "git name"),
    ] {
        let output = git_cmd_with_private_config(&repo, &global_gitconfig, args);
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let home = private_home(&tmp);
    let identity_dir = home.join(".dracon/keys");
    std::fs::create_dir_all(&identity_dir).unwrap();
    let identity = age::x25519::Identity::generate();
    let identity_text = identity.to_string();
    let identity_path = identity_dir.join("identity.age");
    std::fs::write(
        &identity_path,
        format!("{}\n", identity_text.expose_secret()),
    )
    .unwrap();
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let policy = tmp.path().join("warden.toml");
    std::fs::write(
        &policy,
        "protected_patterns = [\".gitignore\"]\nrepo_roots = []\n",
    )
    .unwrap();
    let plaintext =
        b"# synthetic encrypted fixture\nTOKEN=[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGeFFkMzh3SkR3UkEySXdrL3JhcWhRUS81UDdFOE1GUTJPQkw0MDh2UlJrCnYwOGdydUhHNEY0Vnd6N3hlZk55UjZzcS90R3VYdm50ZzB6M1ZlZ1h3VEEKLT4gWDI1NTE5IExmTE1iTzRWTmhiWUtiNWRUY0F2dFNTZWJMaTdxRkNFM1dKYUYrZkJpMVUKd20zZ0RwK0VmQkpyRWNRWGprQkFQUW1oUDc0TUY3TEh2aHQ0MENBODRRVQotPiBYMjU1MTkgVXByZUpHSDYyOWRwZVZBelNMczljK1FGUUF3VE0wUkh0L3NYalFmM2FrUQpJZitoQTV6dXRYckxaQTZSSmE5b0t1Qm40MzVNZXM4RzUyV29UYnpVV1JvCi0+IFgyNTUxOSBUMkh3SkU4K1k1UElmY0xWUWU0cjltY3dnZGRDRzJpdjkySjFRdnNXSlQ0ClFtYzNxaUhOV3lGUXhxRDRpdFM0dXdScWpTcUpUeURDNG81aFNXejlUWTAKLT4gWDI1NTE5IEZxZTBnLzNxSHp6ZFU5VmFCeHJWVDZWQzMvWUxiK0g0aXZRWW5UQXlGejgKTjd1aUNxT1JsL25YRUMwV05Td0NUR1RGNmd6aWFQQzZ0M1Baa0RkMFQxYwotPiAjSF1DKSs6My1ncmVhc2UgNSAxIgppR0x1RVhOYzlTRWZOUExyNHNlYTN4UVRwYUZzRXgxMFlOK1ptOUUKLS0tIE1kTUFaaURnUGVkUGs2Ty9QNnA2dS9hRnBqUlF3WnlESWUrMHMxdm5KTzAKGlqr9VD1Ce205gWsD0a4ccxOXpS0pRDG211QIrIUCIiFSEEwxfjxjh3DuZy3Jbqtb1gEVAHhDY3XshxlGrQpSzo+2gJFmVl0]\n";
    let mut clean = warden_with_policy(&home, &policy, &global_gitconfig)
        .args(["filter-clean", ".gitignore"])
        .current_dir(&repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    clean.stdin.take().unwrap().write_all(plaintext).unwrap();
    let cleaned = clean.wait_with_output().unwrap();
    assert!(
        cleaned.status.success(),
        "filter-clean: {}",
        String::from_utf8_lossy(&cleaned.stderr)
    );
    let ciphertext = cleaned.stdout;
    assert!(
        ciphertext
            .windows(b"DRACON_SECRET".len())
            .any(|window| window == b"DRACON_SECRET"),
        "filter-clean did not produce a Warden ciphertext marker"
    );
    std::fs::write(repo.join(".gitignore"), &ciphertext).unwrap();
    let staged =
        git_cmd_with_private_config(&repo, &global_gitconfig, &["add", "-f", "--", ".gitignore"]);
    assert!(
        staged.status.success(),
        "git add: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let index_before = std::fs::read(repo.join(".git/index")).unwrap();
    let staged_ciphertext =
        git_cmd_with_private_config(&repo, &global_gitconfig, &["show", ":.gitignore"]);
    assert!(staged_ciphertext.status.success());
    assert_eq!(staged_ciphertext.stdout, ciphertext);

    // Hold the same cooperative lock as the apply command. Cancel the real CLI
    // while it is waiting, then prove both the worktree and staged ciphertext
    // remained untouched before releasing the lock.
    let fence_path = repo.join(".git/dracon-canonical-writer-v1.lock");
    let fence = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&fence_path)
        .unwrap();
    assert_eq!(unsafe { libc::flock(fence.as_raw_fd(), libc::LOCK_EX) }, 0);
    let mut blocked = KillChildOnDrop(
        warden_with_policy(&home, &policy, &global_gitconfig)
            .args(["resmudge", "--apply", repo.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_fence_fd(&mut blocked.0, &fence_path);
    std::thread::sleep(Duration::from_millis(25));
    assert_eq!(
        unsafe { libc::kill(blocked.0.id() as libc::pid_t, libc::SIGTERM) },
        0,
        "cancel waiting resmudge"
    );
    let cancelled = blocked.0.wait().unwrap();
    assert_eq!(cancelled.signal(), Some(libc::SIGTERM));
    assert_eq!(std::fs::read(repo.join(".gitignore")).unwrap(), ciphertext);
    assert_eq!(
        std::fs::read(repo.join(".git/index")).unwrap(),
        index_before
    );
    drop(fence);

    let applied = warden_with_policy(&home, &policy, &global_gitconfig)
        .args(["resmudge", "--apply", repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "resmudge --apply: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(std::fs::read(repo.join(".gitignore")).unwrap(), plaintext);
    assert_eq!(
        std::fs::read(repo.join(".git/index")).unwrap(),
        index_before
    );
    let staged_after =
        git_cmd_with_private_config(&repo, &global_gitconfig, &["show", ":.gitignore"]);
    assert!(staged_after.status.success());
    assert_eq!(
        staged_after.stdout, ciphertext,
        "resmudge must not rewrite the Git index"
    );

    // A subsequent writer can acquire immediately after the final worktree
    // write has returned and the resmudge process has exited.
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fence_path)
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "resmudge leaked its canonical-writer fence"
    );
    assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) }, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn resmudge_apply_fences_gitattributes_through_final_close_against_cooperative_writer() {
    use secrecy::ExposeSecret;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("test-repo");
    std::fs::create_dir_all(&repo).unwrap();
    let global_gitconfig = tmp.path().join("gitconfig");
    std::fs::write(&global_gitconfig, "").unwrap();
    for (args, label) in [
        (&["init", "-q", "-b", "main"][..], "git init"),
        (
            &["config", "user.email", "test@example.invalid"][..],
            "git email",
        ),
        (&["config", "user.name", "Warden test"][..], "git name"),
    ] {
        let output = git_cmd_with_private_config(&repo, &global_gitconfig, args);
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let home = private_home(&tmp);
    let identity_dir = home.join(".dracon/keys");
    std::fs::create_dir_all(&identity_dir).unwrap();
    let identity = age::x25519::Identity::generate();
    let identity_text = identity.to_string();
    let identity_path = identity_dir.join("identity.age");
    std::fs::write(
        &identity_path,
        format!("{}\n", identity_text.expose_secret()),
    )
    .unwrap();
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let policy = tmp.path().join("warden.toml");
    std::fs::write(
        &policy,
        "protected_patterns = [\".gitattributes\"]\nrepo_roots = []\n",
    )
    .unwrap();
    let plaintext = b"*.png filter=dracon\n# TOKEN=[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA2MWVIM0V2Mm85QnRqRkoya2VBRDNyT251STVpblQxNXVaeDQ2U1hoWFZFCiszbkFqeU5xNExzNHd6cDlaN0lOY0ovZGFNWCs3bEhhVEJxNDg0Q1Q4ZXMKLT4gWDI1NTE5IHVzeS9lN0VXZzVXREx2UzZML05oM29PMWdHZmpHK0dMUjlWTDFlKzdkbUEKY0piSUpUSzdOeFNGTlNUQVI4aHZldldZdFdUNTdNQlVPTWU2YmYwY0lNNAotPiBYMjU1MTkgNWJidkZWT3lPTnpJYnNwbm1rbW9nOXYvVXlUaXByOW5QNUVGbUFGR1AwYwpER3BBY2pHMm16TEo5NXVZSE03bXc5aW1ERElTSXN1dFJHczNBUzRyVlI4Ci0+IFgyNTUxOSA0NlhhcG04SXhuL1RYRE1BZlJwZC9YU1pxNzBIVmRieS9KcmxkdFZwUHp3CkFCYjVZMDltN0RRdm81MnUvc3FUcHJlK3U5SHJ2UFNud2d5R0VIWEZCb2cKLT4gWDI1NTE5IDVoL0VtYXZDNnpyUXJnNDdyWFNQYThNNmc5RzJrZThvcGxEQjlIOWlkSFkKbDM0eGkwOFVLcnYxdXZoeUpJdU8xQllTYlN0anBEdjJxQ0x3L2tDNTQycwotPiBMQC1ncmVhc2UgfjJ+PSEgPTtoKWZxIDVzTTdLJSBZSXA7CndGa2lNRW8wOXVoUFJ1SXNFM2RDbC9TanJQaFdSc1dRL09WeXBXMERFY29HV056dGJmcld0Qlp2UjNWb0pmd3cKeUEKLS0tIGNsL0hqbktoV3RqK0dQWVd2NDVzU0h5RThWLzNBeWhNeE9iNXh4b2RETHcKomjUfHARQYVft1DwyfOoz0DLYuLBMJxCzc/PJEYtgzGAwTjipgvCm6tdjxjDXNOMrZaLX3BLawQf5kiJTsl1+NmV4P+fY/7M]\n";
    let mut clean = warden_with_policy(&home, &policy, &global_gitconfig)
        .args(["filter-clean", ".gitattributes"])
        .current_dir(&repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    clean.stdin.take().unwrap().write_all(plaintext).unwrap();
    let cleaned = clean.wait_with_output().unwrap();
    assert!(
        cleaned.status.success(),
        "filter-clean: {}",
        String::from_utf8_lossy(&cleaned.stderr)
    );
    let ciphertext = cleaned.stdout;
    assert!(
        ciphertext
            .windows(b"DRACON_SECRET".len())
            .any(|window| window == b"DRACON_SECRET"),
        "filter-clean did not produce a Warden ciphertext marker"
    );
    let target = repo.join(".gitattributes");
    std::fs::write(&target, &ciphertext).unwrap();
    let staged = git_cmd_with_private_config(
        &repo,
        &global_gitconfig,
        &["add", "-f", "--", ".gitattributes"],
    );
    assert!(
        staged.status.success(),
        "git add: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let index_before = std::fs::read(repo.join(".git/index")).unwrap();
    let staged_ciphertext =
        git_cmd_with_private_config(&repo, &global_gitconfig, &["show", ":.gitattributes"]);
    assert!(staged_ciphertext.status.success());
    assert_eq!(staged_ciphertext.stdout, ciphertext);

    // A read lease lets resmudge inspect the target, then blocks its actual
    // write-open. SIGIO marks that exact boundary so a second real Warden CLI
    // writer can be queued behind the same per-worktree fence before we release
    // the lease. The second writer records what it sees after admission.
    let ready = tmp.path().join("lease-ready");
    let breaking = tmp.path().join("lease-breaking");
    let release = tmp.path().join("lease-release");
    let lease_script = r#"
import fcntl, os, signal, sys, time
from pathlib import Path
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_CLOEXEC)
signal.signal(signal.SIGIO, lambda _sig, _frame: Path(sys.argv[2]).write_text("breaking"))
fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
Path(sys.argv[3]).write_text("ready")
while not Path(sys.argv[4]).exists():
    time.sleep(0.005)
fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
os.close(fd)
"#;
    let mut lease_owner = KillChildOnDrop(
        Command::new("python3")
            .arg("-c")
            .arg(lease_script)
            .arg(&target)
            .arg(&breaking)
            .arg(&ready)
            .arg(&release)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let wait_for_path = |path: &Path, label: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {label}");
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    let wait_for_exit = |child: &mut std::process::Child, label: &str| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{label} did not exit within its bounded test deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    wait_for_path(&ready, "the .gitattributes read lease");

    let fence_path = repo.join(".git/dracon-canonical-writer-v1.lock");
    let mut resmudge = KillChildOnDrop(
        warden_with_policy(&home, &policy, &global_gitconfig)
            .args(["resmudge", "--apply"])
            .arg(&repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_path(&breaking, "resmudge's blocked .gitattributes write-open");
    assert!(
        resmudge.0.try_wait().unwrap().is_none(),
        "resmudge exited instead of waiting for the target write-open"
    );

    let after_payload = b"*.png -filter\n# cooperative writer after resmudge\n";
    let after_hex = after_payload
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let observed = tmp.path().join("writer-observed");
    let entered = tmp.path().join("writer-entered");
    let writer_script = "from pathlib import Path; import sys; target=Path(sys.argv[1]); Path(sys.argv[3]).write_bytes(target.read_bytes()); Path(sys.argv[2]).write_text('entered'); target.write_bytes(bytes.fromhex(sys.argv[4]))";
    let mut writer = KillChildOnDrop(
        warden_with_policy(&home, &policy, &global_gitconfig)
            .args(["write-fence", "--repo"])
            .arg(&repo)
            .args([
                "--wait-secs",
                "20",
                "--run-secs",
                "10",
                "--",
                "python3",
                "-c",
            ])
            .arg(writer_script)
            .arg(&target)
            .arg(&entered)
            .arg(&observed)
            .arg(after_hex)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_fence_fd(&mut writer.0, &fence_path);
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !entered.exists(),
        "the cooperative writer crossed the held metadata fence"
    );
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fence_path)
        .unwrap();
    let probe_result = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if probe_result == 0 {
        let _ = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) };
        panic!("resmudge released its fence before the target write completed");
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK),
        "the second writer must be excluded by the canonical metadata fence"
    );

    std::fs::write(&release, b"release").unwrap();
    let lease_status = wait_for_exit(&mut lease_owner.0, "read-lease owner");
    assert!(lease_status.success(), "read-lease owner failed");
    let resmudge_status = wait_for_exit(&mut resmudge.0, "resmudge");
    assert!(resmudge_status.success(), "resmudge failed");
    let writer_status = wait_for_exit(&mut writer.0, "cooperative writer");
    assert!(writer_status.success(), "cooperative writer failed");
    assert!(
        entered.exists(),
        "the second writer never acquired the fence"
    );
    assert_eq!(
        std::fs::read(&observed).unwrap(),
        plaintext,
        "the admitted writer must observe the completed resmudge bytes"
    );
    assert_eq!(std::fs::read(&target).unwrap(), after_payload);
    assert_eq!(
        std::fs::read(repo.join(".git/index")).unwrap(),
        index_before,
        "neither metadata writer may mutate the staged index"
    );
    let staged_after =
        git_cmd_with_private_config(&repo, &global_gitconfig, &["show", ":.gitattributes"]);
    assert!(staged_after.status.success());
    assert_eq!(staged_after.stdout, ciphertext);
    let final_probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fence_path)
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(final_probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB,) },
        0,
        "the final cooperative writer leaked the canonical fence"
    );
    assert_eq!(
        unsafe { libc::flock(final_probe.as_raw_fd(), libc::LOCK_UN) },
        0
    );
}

#[test]
fn test_warden_scrub_markers() {
    let tmp = create_test_repo();
    let repo = tmp.path().join("test-repo");

    // Create a file with a marker
    std::fs::write(repo.join("test.json"), r#"{"key": "DRACON_SECRET_marker"}"#).unwrap();

    let home = private_home(&tmp);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("scrub-markers")
        .arg(&repo)
        .env("HOME", &home)
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

    let home = private_home(&tmp);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("repair")
        .arg("--dry-run")
        .env("HOME", &home)
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
    let home = private_home(&tmp);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("repair")
        .arg(&repo)
        .env("HOME", &home)
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

    let home = private_home(&tmp);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .arg("resmudge")
        .arg("--apply")
        .arg(&repo)
        .env("HOME", &home)
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
    git_cmd(
        &repo,
        &["config", "user.email", "warden-hook-test@example.invalid"],
    );
    git_cmd(&repo, &["config", "user.name", "Hook Test"]);
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

/// Install the warden hooks LOCALLY (repo-local .git/hooks), which is
/// what makes the pre-push test hermetic: no ~/.config/git/hooks writes.
fn install_local_hooks(repo: &std::path::Path) -> PathBuf {
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
        hooks.join("pre-push").exists(),
        "setup-hooks must install a local pre-push hook"
    );
    hooks
}

/// Push with the repo's LOCAL hooks dir only, so no host hook interferes.
fn push_local_hooks(
    repo: &PathBuf,
    hooks: &std::path::Path,
    remote: &str,
    refspec: &str,
) -> std::process::Output {
    git_cmd(
        repo,
        &[
            "-c",
            &format!("core.hooksPath={}", hooks.display()),
            "push",
            remote,
            refspec,
        ],
    )
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
    assert!(
        std::fs::read_dir(&repo).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains('\n')),
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
    git_cmd(
        &repo,
        &["remote", "add", "origin", remote_dir.to_str().unwrap()],
    );

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
    git_cmd(
        &repo,
        &["remote", "add", "origin", remote_dir.to_str().unwrap()],
    );

    let push = push_local_hooks(&repo, &hooks, "origin", "master");
    let stderr = String::from_utf8_lossy(&push.stderr).to_string();
    assert!(
        push.status.success(),
        "paths containing SPACES must still push clean: {stderr}"
    );
}

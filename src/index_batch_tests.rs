//! Deterministic userspace faults; all commands are constructor-injected and
//! isolated from PATH, HOME, production keys, and watched repositories.
use super::*;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, IndexBatch) {
    let dir = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(dir.path())
        .status()
        .unwrap()
        .success());
    std::fs::write(dir.path().join("file"), b"staged").unwrap();
    assert!(Command::new("git")
        .current_dir(dir.path())
        .args(["add", "file"])
        .status()
        .unwrap()
        .success());
    let mut batch = IndexBatch::with_cwd(dir.path().to_owned());
    batch.budget = Duration::from_millis(150);
    (dir, batch)
}

fn failure_then_recovery(script: &str, path: &str, resolver: bool) {
    let (_dir, mut batch) = fixture();
    batch.scripts[usize::from(!resolver)] = Some(script.to_owned());
    let start = Instant::now();
    let indexed = batch.lookup(path, 1024);
    assert_eq!(indexed, None);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "deadline/cleanup exceeded"
    );
    assert!(batch.live.is_none());
    // Fresh, in-memory test identity: no process-global key initialization.
    let mut security = dracon_security_kit::WardenSecurity::new(None)
        .unwrap()
        .with_managed_patterns(vec!["credentials".into()]);
    security.add_memory_identity(age::x25519::Identity::generate());
    for input in [
        b"synthetic protected text".as_slice(),
        b"\0\xffbinary secret".as_slice(),
    ] {
        let ciphertext = security
            .clean_reusing_index(input, "credentials", indexed.as_deref())
            .unwrap();
        assert_ne!(
            ciphertext, input,
            "transport failure must not select plaintext"
        );
        if let Ok(text) = std::str::from_utf8(input) {
            assert_eq!(
                security
                    .smart_smudge(std::str::from_utf8(&ciphertext).unwrap())
                    .unwrap(),
                text
            );
        }
        // Reuse requires an authenticated, byte-exact smudge internally; this
        // also checks binary without converting it through a string API.
        assert_eq!(
            security
                .clean_reusing_index(input, "credentials", Some(&ciphertext))
                .unwrap(),
            ciphertext
        );
        assert_ne!(
            security
                .clean_reusing_index(b"changed", "credentials", Some(&ciphertext))
                .unwrap(),
            ciphertext
        );
    }
    batch.scripts = [None, None];
    batch.budget = Duration::from_secs(2);
    assert_eq!(batch.lookup("file", 1024), Some(b"staged".to_vec()));
    // No lifetime timeout: a session remains valid across arbitrarily idle gaps.
    std::thread::sleep(Duration::from_millis(180));
    assert_eq!(batch.lookup("file", 1024), Some(b"staged".to_vec()));
}

#[test]
fn index_batch_silent_and_partial_response_recover() {
    failure_then_recovery("read query; exec sleep 60", "file", false);
    failure_then_recovery(
        "read query; printf 'abc blob 20\\npartial'; exec sleep 60",
        "file",
        false,
    );
}

#[test]
fn index_batch_nonreading_stdin_recovers() {
    // Far above pipe capacity: the budget must cover write_all, not just read.
    failure_then_recovery("exec sleep 60", &"x".repeat(4 * 1024 * 1024), false);
}

#[test]
fn index_batch_resolver_deadline_recovers() {
    failure_then_recovery("exec sleep 60", "file", true);
}

#[test]
fn index_batch_descendant_retained_stdout_is_cancelled() {
    // The direct helper exits while its child retains stdout. Cleanup must
    // signal the group while the unreaped leader still reserves the PGID.
    failure_then_recovery("sleep 60 & exit 0", "file", false);
    failure_then_recovery("sleep 60 & exit 0", "file", true);
}

#[test]
fn index_batch_drop_reaps_direct_child_and_kills_group() {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "sleep 60 & wait"]);
    let child = PipeChild::spawn(&mut cmd, Instant::now() + Duration::from_secs(1)).unwrap();
    let pid = child.child.id() as i32;
    let start = Instant::now();
    drop(child);
    assert!(start.elapsed() < Duration::from_secs(2));
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn index_batch_descendant_has_no_live_process_after_cleanup() {
    let (dir, mut batch) = fixture();
    let pids = dir.path().join("pids");
    batch.scripts[1] = Some(format!(
        "sleep 60 & echo $$ $! > '{}'; exit 0",
        pids.display()
    ));
    assert_eq!(batch.lookup("file", 1024), None);
    // The pids file is written by the batch's own shell: the redirect
    // creates the file before the write lands, so a read straight after
    // the batch can see an empty file. That happened in the Nix sandbox,
    // where the read lost the race and the next line indexed an empty
    // vector. Wait for the content, with a bound.
    let deadline = Instant::now() + Duration::from_secs(10);
    let ids: Vec<i32> = loop {
        let raw = std::fs::read_to_string(&pids).unwrap_or_default();
        let parsed: Vec<i32> = raw.split_whitespace().map(|s| s.parse().unwrap()).collect();
        if parsed.len() >= 2 {
            break parsed;
        }
        assert!(
            Instant::now() < deadline,
            "the batch never reported its pids: {raw:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(ids[0], &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", ids[1]));
        match stat {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Ok(stat) if stat.rsplit_once(") ").unwrap().1.starts_with('Z') => break,
            _ => {
                assert!(Instant::now() < deadline, "descendant still running");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

#[test]
fn index_batch_invalid_framing_and_exit_recover() {
    failure_then_recovery("read query; printf 'bad\\n'", "file", false);
    failure_then_recovery("read query; printf 'abc blob 67108865\\n'", "file", false);
    failure_then_recovery("exit 1", "file", false);
}

#[test]
fn index_batch_reuses_authenticated_staged_ciphertext() {
    let (dir, mut batch) = fixture();
    let mut security = dracon_security_kit::WardenSecurity::new(None)
        .unwrap()
        .with_managed_patterns(vec!["credentials".into()]);
    security.add_memory_identity(age::x25519::Identity::generate());
    let input = b"isolated synthetic credential";
    let ciphertext = security
        .clean_reusing_index(input, "credentials", None)
        .unwrap();
    std::fs::write(dir.path().join("credentials"), &ciphertext).unwrap();
    assert!(Command::new("git")
        .current_dir(dir.path())
        .args(["add", "credentials"])
        .status()
        .unwrap()
        .success());
    let indexed = batch.lookup("credentials", 1024 * 1024).unwrap();
    assert_eq!(indexed, ciphertext);
    assert_eq!(
        security
            .clean_reusing_index(input, "credentials", Some(&indexed))
            .unwrap(),
        ciphertext
    );
}

// Invoked only as one exact test in a separate process, never a recursive suite.
#[cfg(target_os = "linux")]
#[test]
fn index_batch_abrupt_owner_fixture() {
    let Some(path) = std::env::var_os("WARDEN_ABRUPT_OWNER_READY") else {
        return;
    };
    let mut cmd = Command::new("sh");
    cmd.args([
        "-c",
        "sleep 60 & printf '%s %s\\n' $$ $! > \"$1\"; wait",
        "fixture",
    ])
    .arg(path);
    let _owned = PipeChild::spawn(&mut cmd, Instant::now() + Duration::from_secs(30)).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !stat.rsplit_once(") ").unwrap().1.starts_with(['Z', 'X']),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => panic!("cannot inspect synthetic child: {e}"),
    }
}

#[cfg(target_os = "linux")]
fn abrupt_cleanup_fixture(kill_owner: bool) {
    use std::os::unix::process::CommandExt;
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let mut owner = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "index_batch::tests::index_batch_abrupt_owner_fixture",
            "--nocapture",
        ])
        .env("WARDEN_ABRUPT_OWNER_READY", &ready)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    // This guard owns only the isolated fixture owner, and never signals its
    // PGID after reap. Helper/guardian ownership is exercised, not emulated.
    struct Owner<'a>(&'a mut std::process::Child);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline, "fixture owner did not reap");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    let guard = Owner(&mut owner);
    let deadline = Instant::now() + Duration::from_secs(3);
    let ids = loop {
        if let Ok(text) = std::fs::read_to_string(&ready) {
            let ids: Vec<i32> = text
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            if ids.len() == 2 {
                break ids;
            }
        }
        assert!(Instant::now() < deadline, "fixture did not start");
        std::thread::sleep(Duration::from_millis(2));
    };
    // Discover both the sleep and independently owned guardian. Verify they are
    // live before cancellation, so a missing/failed guardian cannot pass vacuously.
    let children =
        std::fs::read_to_string(format!("/proc/{}/task/{}/children", ids[0], ids[0])).unwrap();
    let children: Vec<i32> = children
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(children.len(), 2, "expected sleep plus guardian");
    assert!(children.contains(&ids[1]));
    assert!(children.iter().all(|pid| process_is_running(*pid)));
    let guardian = *children.iter().find(|pid| **pid != ids[1]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read_dir(format!("/proc/{guardian}/fd"))
            .unwrap()
            .next()
            .is_none()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "guardian retained inherited descriptors"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let pgid = unsafe { libc::getpgid(ids[0]) };
    assert_eq!(pgid, ids[0]);
    assert_ne!(pgid, unsafe { libc::getpgid(guard.0.id() as i32) });
    for pid in &children {
        assert_eq!(unsafe { libc::getpgid(*pid) }, pgid);
    }
    if kill_owner {
        // Production-like outer GroupKillGuard: SIGKILL the owner's group. The
        // separately grouped helper cannot be reached by this signal directly.
        assert_eq!(
            unsafe { libc::kill(-(guard.0.id() as i32), libc::SIGKILL) },
            0
        );
    } else {
        assert_eq!(unsafe { libc::kill(ids[0], libc::SIGKILL) }, 0);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while std::iter::once(&ids[0])
        .chain(children.iter())
        .any(|pid| process_is_running(*pid))
    {
        assert!(
            Instant::now() < deadline,
            "synthetic helper/guardian/descendant survived cancellation"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    // Killing the direct helper must not terminate the still-live owner.
    if !kill_owner {
        assert!(process_is_running(guard.0.id() as i32));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn index_batch_outer_owner_sigkill_cleans_isolated_helper_group() {
    abrupt_cleanup_fixture(true);
}

#[cfg(target_os = "linux")]
#[test]
fn index_batch_direct_helper_sigkill_cleans_descendants_without_drop() {
    abrupt_cleanup_fixture(false);
}

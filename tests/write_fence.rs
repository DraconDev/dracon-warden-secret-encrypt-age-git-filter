//! Actual CLI process/FD controls; synthetic files and owned children only.
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
const BIN: &str = env!("CARGO_BIN_EXE_dracon-warden");

fn fixture() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join(".git")).unwrap();
    d
}
fn command(repo: &Path, run: &str) -> Command {
    let mut c = Command::new(BIN);
    c.args(["write-fence", "--repo"]).arg(repo)
        .args(["--wait-secs", "1", "--run-secs", run, "--"]);
    c
}
struct Family(Child);
impl Drop for Family {
    fn drop(&mut self) {
        // The wrapper execs timeout without changing its owned root PID.
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL); }
        let _ = self.0.wait();
    }
}
fn holder(repo: &Path, marker: &Path) -> Family {
    let mut c = command(repo, "10");
    c.args(["python3", "-c", "import os,time,sys;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(8)"])
        .arg(marker).stdout(Stdio::null()).stderr(Stdio::null());
    let child = Family(c.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "writer never acquired fence");
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}

#[test]
fn cli_fences_same_repo_but_not_unrelated_repo_and_releases_on_close() {
    let a = fixture(); let b = fixture(); let marker = a.path().join("held");
    let held = holder(a.path(), &marker);
    let start = Instant::now();
    let blocked = command(a.path(), "2").arg("true").output().unwrap();
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("deadline expired"));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(command(b.path(), "2").arg("true").status().unwrap().success());
    drop(held);
    assert!(command(a.path(), "2").arg("true").status().unwrap().success());
}

#[test]
fn inherited_fence_is_reentrant_and_wrong_repository_is_refused() {
    let a = fixture(); let b = fixture();
    let out = command(a.path(), "5").arg(BIN).args(["write-fence", "--repo"])
        .arg(a.path()).args(["--wait-secs", "1", "--run-secs", "2", "--", "printf", "fenced"])
        .output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"fenced");
    let out = command(a.path(), "5").arg(BIN).args(["write-fence", "--repo"])
        .arg(b.path()).args(["--wait-secs", "1", "--run-secs", "2", "--", "true"])
        .output().unwrap();
    assert!(!out.status.success(), "a token for repo A must not fence repo B");
}

#[test]
fn killing_wrapper_does_not_release_fence_before_actual_writer_closes() {
    let a = fixture(); let marker = a.path().join("held");
    let mut family = holder(a.path(), &marker);
    family.0.kill().unwrap(); family.0.wait().unwrap();
    let blocked = command(a.path(), "2").arg("true").output().unwrap();
    assert!(!blocked.status.success(), "live orphan writer still holds inherited fence FD");
    drop(family);
    assert!(command(a.path(), "2").arg("true").status().unwrap().success());
}

#[test]
fn operation_deadline_cleans_owned_family_and_does_not_steal_next_lock() {
    let a = fixture(); let start = Instant::now();
    let out = command(a.path(), "1").args(["sh", "-c", "sleep 30 & wait"]).output().unwrap();
    assert_eq!(out.status.code(), Some(124));
    assert!(start.elapsed() < Duration::from_secs(4));
    assert!(command(a.path(), "2").arg("true").status().unwrap().success());
}

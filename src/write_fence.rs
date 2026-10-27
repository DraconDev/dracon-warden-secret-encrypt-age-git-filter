//! Cooperative canonical-metadata writer protocol, version 1.
//!
//! Acquire before looking up/opening the target, retain through the final
//! close/publication, and never unlink the lock file. A daemon-only use does
//! NOT qualify the protocol: every affected producer must participate.
use anyhow::{ensure, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Per-worktree Git directory, not the common directory: unrelated worktrees
/// and repositories must remain independently writable.
pub(crate) const FILE_NAME: &str = "dracon-canonical-writer-v1.lock";
const INHERITED_FD: &str = "DRACON_CANONICAL_WRITER_FD_V1";

/// Owned exclusive flock. Closing the descriptor releases it; no stale-lock
/// deletion or PID-based lock stealing is permitted.
pub(crate) struct WriteFence {
    file: File,
    path: PathBuf,
}

impl WriteFence {
    /// Wait only until the caller's absolute deadline. Opening the lock does
    /// not open or inspect any protected working-tree file.
    pub(crate) fn acquire_until(repo: &Path, deadline: Instant) -> Result<Self> {
        ensure!(Instant::now() < deadline, "canonical writer fence deadline expired");
        let gitdir = super::resolved_git_dir(repo).context("writer fence requires a worktree Git directory")?;
        let path = gitdir.join(FILE_NAME);
        let file = if let Some(raw) = std::env::var_os(INHERITED_FD) {
            // Borrowing an inherited OFD is reentrant, unlike opening the same
            // lock anew. Never trust an env token without checking the actual
            // descriptor against this repository's lock namespace below.
            let fd: i32 = raw.to_str().context("non-text writer fence descriptor")?.parse()?;
            ensure!(fd >= 3, "invalid inherited writer fence descriptor");
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            ensure!(duplicate >= 0, "cannot duplicate inherited writer fence descriptor");
            unsafe { File::from_raw_fd(duplicate) }
        } else {
            OpenOptions::new()
                .read(true).write(true).create(true).truncate(false)
                .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path).context("open canonical writer fence")?
        };
        let fence = Self { file, path };
        fence.verify()?;
        loop {
            ensure!(Instant::now() < deadline, "canonical writer fence deadline expired");
            let result = unsafe { libc::flock(fence.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                fence.verify()?;
                return Ok(fence);
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK) | Some(libc::EINTR)) {
                return Err(error).context("acquire canonical writer fence");
            }
            std::thread::sleep(Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Refuse symlinks, shared hardlinks, foreign ownership, permissive files,
    /// and a namespace replacement. This is not permission to steal a lock.
    pub(crate) fn verify(&self) -> Result<()> {
        let held = self.file.metadata()?;
        let named = std::fs::symlink_metadata(&self.path)?;
        ensure!(held.is_file() && named.is_file(), "writer fence is not a regular file");
        ensure!(held.uid() == unsafe { libc::geteuid() } && held.nlink() == 1
            && held.mode() & 0o077 == 0, "unsafe canonical writer fence ownership/mode/links");
        ensure!(held.dev() == named.dev() && held.ino() == named.ino(), "canonical writer fence was replaced");
        Ok(())
    }
}

/// Run a synchronous owned writer with the fence FD inherited into the actual
/// writing process. Parent death must not release the lock while that process
/// can still write. Participants must retain this FD through their final close
/// and must not launch detached writers that discard it.
pub(crate) fn exec_writer(
    repo: &Path, wait_secs: u64, run_secs: u64, command: &[std::ffi::OsString],
) -> Result<()> {
    ensure!((1..=300).contains(&wait_secs), "writer fence wait must be 1..300 seconds");
    ensure!((1..=3600).contains(&run_secs), "writer deadline must be 1..3600 seconds");
    ensure!(!command.is_empty(), "writer command is required");
    let nested = std::env::var_os(INHERITED_FD).is_some();
    let fence = WriteFence::acquire_until(repo, Instant::now() + Duration::from_secs(wait_secs))?;
    fence.verify()?;
    let fd = fence.file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    ensure!(flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == 0,
        "cannot inherit canonical writer fence");
    // exec keeps the owned root PID. GNU timeout normally owns that root's
    // process group, so the caller's group cancellation and its own deadline
    // address the same family. Nested writers retain the outer owned group.
    let mut child = std::process::Command::new("timeout");
    child.arg("--kill-after=5");
    if nested { child.arg("--foreground"); }
    child.arg(run_secs.to_string()).args(command).env(INHERITED_FD, fd.to_string());
    Err(child.exec()).context("execute bounded canonical writer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        dir
    }
    fn acquire(repo: &Path) -> WriteFence {
        WriteFence::acquire_until(repo, Instant::now() + Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn same_repository_wait_is_bounded_and_drop_recovers_without_unlink() {
        let repo = fixture();
        let held = acquire(repo.path());
        let start = Instant::now();
        assert!(WriteFence::acquire_until(repo.path(), start + Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let inode = held.file.metadata().unwrap().ino();
        drop(held);
        let next = acquire(repo.path());
        assert_eq!(next.file.metadata().unwrap().ino(), inode);
    }

    #[test]
    fn unrelated_repositories_do_not_share_a_fence() {
        let a = fixture(); let b = fixture();
        let _first = acquire(a.path());
        let _second = acquire(b.path());
    }

    #[test]
    fn git_pointer_and_symlink_alias_resolve_the_same_fence() {
        let repo = fixture();
        let alias = tempfile::tempdir().unwrap();
        std::fs::write(alias.path().join(".git"), format!("gitdir: {}\n", repo.path().join(".git").display())).unwrap();
        let link = alias.path().join("linked-root"); symlink(repo.path(), &link).unwrap();
        let _held = acquire(repo.path());
        for path in [alias.path(), link.as_path()] {
            assert!(WriteFence::acquire_until(path, Instant::now() + Duration::from_millis(20)).is_err());
        }
    }

    #[test]
    fn unsafe_lock_files_are_not_followed_truncated_or_stolen() {
        for kind in ["symlink", "hardlink", "permissive"] {
            let repo = fixture(); let outside = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(outside.path(), b"preserve outside bytes").unwrap();
            let lock = repo.path().join(".git").join(FILE_NAME);
            match kind {
                "symlink" => symlink(outside.path(), &lock).unwrap(),
                "hardlink" => std::fs::hard_link(outside.path(), &lock).unwrap(),
                _ => { std::fs::write(&lock, b"preserve lock bytes").unwrap(); std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap(); }
            }
            assert!(WriteFence::acquire_until(repo.path(), Instant::now() + Duration::from_secs(1)).is_err());
            assert_eq!(std::fs::read(outside.path()).unwrap(), b"preserve outside bytes");
        }
    }

    #[test]
    fn replaced_namespace_and_expired_deadline_refuse() {
        let repo = fixture(); let held = acquire(repo.path());
        std::fs::rename(&held.path, held.path.with_extension("displaced")).unwrap();
        std::fs::write(&held.path, b"replacement").unwrap();
        assert!(held.verify().is_err());
        assert!(WriteFence::acquire_until(repo.path(), Instant::now()).is_err());
    }
}

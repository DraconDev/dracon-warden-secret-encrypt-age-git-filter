//! Optional index reuse transport. No worker threads: the owner drives nonblocking
//! pipes under one request deadline and owns process-group teardown before reaping.
//! Index locks and index mtime changes retire the session. Any transport error
//! abandons positional framing wholesale; the caller receives no reusable blob.
//! Ciphertext reuse still requires authenticated equality and current policy in
//! clean_reusing_index; missing blobs select fresh encryption, never plaintext.
use std::path::PathBuf;
use std::time::{Duration, Instant};

const LOOKUP_BUDGET: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(1);
const BLOB_CAP: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct IndexBatch {
    gitdir: Option<PathBuf>,
    live: Option<LiveBatch>,
    cwd: Option<PathBuf>,
    budget: Duration,
    #[cfg(test)]
    scripts: [Option<String>; 2],
}

impl IndexBatch {
    pub(crate) fn new() -> Self {
        Self {
            gitdir: None,
            live: None,
            cwd: None,
            budget: LOOKUP_BUDGET,
            #[cfg(test)]
            scripts: [None, None],
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cwd(path: PathBuf) -> Self {
        Self {
            cwd: Some(path),
            ..Self::new()
        }
    }

    pub(crate) fn lookup(&mut self, path: &str, limit: usize) -> Option<Vec<u8>> {
        #[cfg(unix)]
        {
            let deadline = Instant::now() + self.budget;
            let result = self.lookup_until(path, limit, deadline);
            if result.is_err() {
                self.live = None;
            }
            result.ok().flatten()
        }
        // Optional optimization only: failure always selects fresh encryption.
        #[cfg(not(unix))]
        {
            let _ = (path, limit);
            None
        }
    }

    #[cfg(unix)]
    fn command(&self, resolver: bool) -> std::process::Command {
        #[cfg(test)]
        if let Some(script) = &self.scripts[usize::from(!resolver)] {
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", script]);
            return cmd;
        }
        let _ = resolver;
        let mut cmd = std::process::Command::new("git");
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        cmd
    }

    #[cfg(unix)]
    fn lookup_until(
        &mut self,
        path: &str,
        limit: usize,
        deadline: Instant,
    ) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::{BufRead, Read, Write};
        if path.contains('\n') {
            return Ok(None);
        }
        if self.gitdir.is_none() {
            let mut cmd = self.command(true);
            cmd.args(["rev-parse", "--absolute-git-dir"]);
            let mut resolver = PipeChild::spawn(&mut cmd, deadline)?;
            let mut output = Vec::new();
            (&mut resolver)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut output)?;
            if output.len() > 1024 * 1024 || !resolver.exited_successfully()? {
                return Err(invalid());
            }
            let resolved = String::from_utf8_lossy(&output);
            let resolved = resolved.trim();
            if resolved.is_empty() {
                return Err(invalid());
            }
            let dir = PathBuf::from(resolved);
            let dir = match &self.cwd {
                Some(cwd) if dir.is_relative() => cwd.join(dir),
                _ => dir,
            };
            if !dir.is_dir() {
                return Err(invalid());
            }
            self.gitdir = Some(dir);
        }
        let dir = self.gitdir.as_ref().unwrap();
        if dir.join("index.lock").exists() {
            self.live = None;
            return Ok(None);
        }
        let mtime = std::fs::metadata(dir.join("index"))
            .and_then(|m| m.modified())
            .ok();
        if self
            .live
            .as_ref()
            .is_some_and(|live| live.index_mtime != mtime)
        {
            self.live = None;
        }
        if self.live.is_none() {
            let mut cmd = self.command(false);
            cmd.args(["cat-file", "--batch"]);
            self.live = Some(LiveBatch {
                pipe: PipeChild::spawn(&mut cmd, deadline)?,
                index_mtime: mtime,
            });
        }
        let pipe = &mut self.live.as_mut().unwrap().pipe;
        pipe.deadline = deadline;
        pipe.write_all(format!(":0:{path}\n").as_bytes())?;
        let mut reader = std::io::BufReader::new(pipe);
        let mut header = Vec::new();
        (&mut reader)
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut header)?;
        if header.len() > 1024 * 1024 || header.last() != Some(&b'\n') {
            return Err(invalid());
        }
        let header = String::from_utf8_lossy(&header);
        if header.trim_end().ends_with(" missing") {
            return Ok(None);
        }
        let mut parts = header.split_whitespace();
        let (_, typ, size) = (parts.next(), parts.next(), parts.next());
        let size = size
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|s| *s <= BLOB_CAP)
            .ok_or_else(invalid)?;
        let mut body = vec![0; size + 1];
        reader.read_exact(&mut body)?;
        if body.pop() != Some(b'\n') {
            return Err(invalid());
        }
        Ok((typ == Some("blob") && size <= limit).then_some(body))
    }
}

#[derive(Debug)]
struct LiveBatch {
    #[cfg(unix)]
    pipe: PipeChild,
    index_mtime: Option<std::time::SystemTime>,
}

#[cfg(unix)]
fn invalid() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid index response")
}

#[cfg(unix)]
fn tick(deadline: Instant) -> std::io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "index lookup deadline")
        })?;
    std::thread::sleep(remaining.min(Duration::from_millis(2)));
    Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
struct PipeChild {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    deadline: Instant,
}

#[cfg(unix)]
impl PipeChild {
    fn spawn(cmd: &mut std::process::Command, deadline: Instant) -> std::io::Result<Self> {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "index spawn deadline",
            ));
        }
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        // A new group is mandatory: never signal the invoking Git's group.
        #[cfg(target_os = "linux")]
        {
            let owner = unsafe { libc::getpid() };
            // SAFETY: only async-signal-safe operations/syscalls run after fork.
            unsafe { cmd.pre_exec(move || arm_helper_guardian(owner)) };
        }
        let mut child = cmd
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let pipe = Self {
            child,
            stdin,
            stdout,
            deadline,
        };
        use std::os::fd::AsRawFd;
        for fd in [pipe.stdin.as_raw_fd(), pipe.stdout.as_raw_fd()] {
            // SAFETY: both descriptors are owned and remain live throughout fcntl.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        Ok(pipe)
    }

    fn exited_successfully(&mut self) -> std::io::Result<bool> {
        loop {
            // Observe without reaping: retain PID/PGID ownership until Drop has
            // signalled the group, even if a descendant still holds a pipe.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                return Ok(info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0);
            }
            tick(self.deadline)?;
        }
    }
}

/// The guardian is a member of the helper's isolated group, not a detached
/// thread. Its own live PID pins the PGID until kill(0) signals the group.
#[cfg(target_os = "linux")]
extern "C" fn kill_helper_group(_: libc::c_int) {
    // SAFETY: kill and _exit are async-signal-safe; no allocation or unwinding.
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(1);
    }
}

#[cfg(target_os = "linux")]
unsafe fn arm_helper_guardian(owner: libc::pid_t) -> std::io::Result<()> {
    // Repeat setpgid explicitly before fork: guardian must never join the outer
    // Git's group, regardless of std's process_group/pre_exec ordering.
    if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if libc::getppid() != owner {
        libc::_exit(1);
    }
    let helper = libc::getpid();
    // Raw clone with fork semantics: libc::fork would run arbitrary registered
    // pthread_atfork callbacks in this already-forked, potentially multithreaded
    // runtime snapshot. No CLONE_VM/thread/files flags: memory and FDs are copied.
    // s390x alone reverses the first two raw clone arguments; all remaining
    // optional pointers are null so architecture-specific tail order is immaterial.
    #[cfg(target_arch = "s390x")]
    let guardian = libc::syscall(
        libc::SYS_clone,
        0usize,
        libc::SIGCHLD as libc::c_ulong,
        0usize,
        0usize,
        0usize,
    );
    #[cfg(not(target_arch = "s390x"))]
    let guardian = libc::syscall(
        libc::SYS_clone,
        libc::SIGCHLD as libc::c_ulong,
        0usize,
        0usize,
        0usize,
        0usize,
    );
    match guardian {
        -1 => Err(std::io::Error::last_os_error()),
        0 => {
            // Nothing from Rust's runtime is usable here. Block notification
            // until the handler is installed and parent-death is armed. A death
            // before prctl is caught by getppid; a later one is pending/handled.
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGUSR1);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kill_helper_group as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) != 0
                || libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1) != 0
            {
                kill_helper_group(0);
            }
            if libc::getppid() != helper {
                kill_helper_group(0);
            }
            // Close ALL inherited descriptors, including Rust spawn's exec-error
            // pipe and the filter's input/output. Keeping any of these would
            // itself wedge spawn, EOF, or parent protocol completion. Linux 5.9+
            // close_range is required; failure kills the group, never runs an
            // unguarded helper. This syscall does not execute allocator/runtime.
            if libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0u32) != 0 {
                kill_helper_group(0);
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            loop {
                // Atomic unblock + wait: no check-to-pause lost notification.
                libc::sigsuspend(&empty);
            }
        }
        _ => Ok(()), // direct helper continues exec with Warden-PDEATHSIG intact
    }
}

#[cfg(unix)]
impl std::io::Read for PipeChild {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::ErrorKind;
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "index read deadline",
                ));
            }
            match self.stdout.read(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => tick(self.deadline)?,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

#[cfg(unix)]
impl std::io::Write for PipeChild {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::io::ErrorKind;
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "index write deadline",
                ));
            }
            match self.stdin.write(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => tick(self.deadline)?,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PipeChild {
    fn drop(&mut self) {
        // Signal BEFORE any reap, preventing PGID reuse from targeting strangers.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let deadline = Instant::now() + REAP_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                _ => {
                    // No detached reaper, blocking wait, or successful plaintext
                    // fallback. Kernel-uninterruptible children cannot be boundedly
                    // reaped; terminate this filter nonzero without a core dump.
                    eprintln!("warden: index helper cleanup failed; terminating filter");
                    std::process::exit(1);
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
#[path = "index_batch_tests.rs"]
mod tests;

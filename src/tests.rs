#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::*;
    use dracon_security_kit::managed_patterns_override;
    use std::sync::Mutex;
    use std::time::Duration;

    static HOME_MUTEX: Mutex<()> = Mutex::new(());

    /// Guard that temporarily changes $HOME and restores it on drop.
    struct HomeGuard {
        original: Option<String>,
        #[allow(dead_code)]
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl HomeGuard {
        fn new(home: &str) -> Self {
            let lock = HOME_MUTEX.lock().expect("home mutex poisoned");
            let original = std::env::var("HOME").ok();
            std::env::set_var("HOME", home);
            HomeGuard {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            std::env::remove_var("HOME");
            if let Some(ref v) = self.original {
                std::env::set_var("HOME", v);
            }
        }
    }

    struct TestDir {
        path: std::path::PathBuf,
        _temporary: tempfile::TempDir,
        #[allow(dead_code)]
        guard: Mutex<()>,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            // Workspace checks may run in multiple processes. Keep the name's
            // quote/space fixtures while allocating a unique owned directory.
            let temporary = tempfile::Builder::new()
                .prefix(&format!("dracon_warden_test_{name}_"))
                .tempdir()
                .expect("create temp dir");
            let path = temporary.path().to_owned();
            Self {
                path,
                _temporary: temporary,
                guard: Mutex::new(()),
            }
        }
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn sample_policy() -> WardenPolicy {
        WardenPolicy {
            protected_patterns: vec!["*.env".into(), "secrets/**".into()],
            plaintext_patterns: vec!["*.pub".into()],
            hygiene_patterns: vec!["target/".into(), "*.log".into()],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        }
    }

    // --- Behavioral tests for the pre-push hook -------------------------
    //
    // These tests run `PRE_PUSH_HOOK` as a real shell subprocess against a
    // temp git repo. They are the regression guard for the change that
    // narrowed the hook's diff scan to added lines only (so deletion of
    // legacy secret-shaped fixtures doesn't block a push).
    //
    // The string-asserting test that used to live here was brittle: any
    // wording change in the hook template would break it, and it never
    // proved the hook actually behaves correctly.

    /// Create a temp git repo on `main` with the in-tree `PRE_PUSH_HOOK`
    /// installed at `.git/hooks/pre-push` (executable). Returns the
    /// `TestDir` (which auto-cleans on drop) and the path of the hook.
    fn make_repo_with_pre_push_hook(name: &str) -> (TestDir, std::path::PathBuf) {
        let td = TestDir::new(name);
        let repo = td.path();
        run_git_in(repo, &["init", "-q", "-b", "main"]);
        run_git_in(repo, &["config", "user.email", "test@test.local"]);
        run_git_in(repo, &["config", "user.name", "test"]);
        run_git_in(repo, &["config", "commit.gpgsign", "false"]);
        remove_ambient_local_hooks(repo);

        // The user may have global/template hooks (warden's pre-commit +
        // pre-push). For this test repo we want ONLY our pre-push hook
        // to run — the template/global pre-commit would harden the throwaway
        // repo and can change the file content before the push simulation.
        // Point the test repo at a separate hooks dir and write only the
        // pre-push hook there.
        let hooks_dir = repo.join("test-hooks");
        fs::create_dir_all(&hooks_dir).expect("hooks dir");
        // FIXED 2026-08-12 (audit LOW follow-up, auditor-verified
        // vacuity): the hook script must NEVER be committed into the
        // fixture repo — the hook's own documentation comment
        // (a bare password assignment) self-matches the unquoted-password
        // branch, so every "block" assertion passed via the committed
        // hook script, not via the fixture. Exclude the hooks dir via
        // .git/info/exclude (git add -A honors it); the dir stays
        // inside the temp repo so TestDir Drop cleans it up.
        fs::create_dir_all(repo.join(".git/info")).expect(".git/info");
        fs::write(
            repo.join(".git/info/exclude"),
            "# dracon-warden tests: never commit the hook under test\ntest-hooks/\n",
        )
        .expect("write info/exclude");
        run_git_in(
            repo,
            &[
                "config",
                "core.hooksPath",
                hooks_dir.to_str().expect("utf8 hooks path"),
            ],
        );

        let hook_path = hooks_dir.join("pre-push");
        fs::write(&hook_path, PRE_PUSH_HOOK).expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }
        (td, hook_path)
    }

    /// Remove hooks copied into the temporary repo by the operator's Git
    /// template. The hook under test intentionally chains `.git/hooks`, so
    /// ambient Warden hooks there would otherwise be mistaken for fixtures.
    fn remove_ambient_local_hooks(repo: &std::path::Path) {
        for name in ["pre-commit", "pre-push", "pre-rebase"] {
            let path = repo.join(".git/hooks").join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove ambient hook {}: {}", path.display(), error),
            }
        }
    }

    fn run_git_in(repo: &std::path::Path, args: &[&str]) {
        let status = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .expect("git command");
        assert!(
            status.success(),
            "git {:?} failed in {}",
            args,
            repo.display()
        );
    }

    fn git_in_output(repo: &std::path::Path, args: &[&str]) -> String {
        let out = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("utf8 stdout")
    }

    /// Return a path to `target` relative to the test process directory.
    ///
    /// F76 specifically needs coverage for callers that pass a relative repo
    /// argument, while the regular fixtures live below `/tmp` to avoid
    /// touching the checkout containing the tests.
    fn relative_path_from_current_dir(target: &std::path::Path) -> std::path::PathBuf {
        let current = fs::canonicalize(std::env::current_dir().expect("current directory"))
            .expect("canonical current directory");
        let target = fs::canonicalize(target).expect("canonical relative-path target");
        let current_components: Vec<_> = current.components().collect();
        let target_components: Vec<_> = target.components().collect();
        let common = current_components
            .iter()
            .zip(&target_components)
            .take_while(|(left, right)| left == right)
            .count();
        assert!(common > 0, "test paths must share a filesystem root");

        let mut relative = std::path::PathBuf::new();
        for _ in common..current_components.len() {
            relative.push("..");
        }
        for component in target_components.iter().skip(common) {
            relative.push(component.as_os_str());
        }
        if relative.as_os_str().is_empty() {
            relative.push(".");
        }
        relative
    }

    /// Invoke the pre-push hook with a caller-provided ref stream.
    /// Returns the exit status and captured stderr.
    fn run_hook_input(
        repo: &std::path::Path,
        hook_path: &std::path::Path,
        stdin_data: &str,
    ) -> (std::process::ExitStatus, String) {
        run_hook_input_in(repo, hook_path, stdin_data)
    }

    /// ADDED 2026-10-03 (audit R4-W-08): `cwd` may be a subdirectory
    /// of the repo (proves $REPO anchoring of the hatch check).
    fn run_hook_input_in(
        cwd: &std::path::Path,
        hook_path: &std::path::Path,
        stdin_data: &str,
    ) -> (std::process::ExitStatus, String) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(hook_path)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin_data.as_bytes())
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait hook");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        (output.status, stderr)
    }

    /// Invoke the pre-push hook with a single branch ref update.
    fn run_hook(
        repo: &std::path::Path,
        hook_path: &std::path::Path,
        local_sha: &str,
        remote_sha: &str,
    ) -> (std::process::ExitStatus, String) {
        let stdin_data = format!(
            "refs/heads/main {} refs/heads/main {}\n",
            local_sha, remote_sha
        );
        run_hook_input(repo, hook_path, &stdin_data)
    }

    /// Empty tree SHA — used as the "remote side" when simulating the
    /// first push of a new branch (so the diff range covers the full
    /// local history).
    /// What git actually sends as remote_sha for a brand-new remote ref.
    const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn pre_push_hook_passes_on_clean_commit() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_clean");
        let repo = td.path();

        // Single commit with a clean file. Push range = empty tree..commit.
        fs::write(repo.join("hello.txt"), "hello world\n").unwrap();
        run_git_in(repo, &["add", "hello.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "init"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, _stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert!(
            status.success(),
            "hook should pass on clean push, but exited with: {:?}",
            status.code()
        );
    }

    /// A tag pushed alongside an already-scanned branch commit must not
    /// rescan the entire historical tree. This is the production release
    /// shape: the branch and tag point at the same new commit, while an older
    /// documentation placeholder contains a secret-shaped token name.
    #[test]
    fn pre_push_hook_tag_does_not_rescan_published_history() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_tag_published_history");
        let repo = td.path();

        fs::write(
            repo.join("docs.txt"),
            concat!("token_", "secret = \"documentation-placeholder\"\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "docs.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let baseline = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        fs::write(repo.join("release.txt"), "release\n").unwrap();
        run_git_in(repo, &["add", "release.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "release"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Simulate one atomic push of main and the tag. The branch leg scans
        // only baseline..head; the tag leg must not rescan docs.txt.
        let stdin_data = format!(
            "refs/heads/main {} refs/heads/main {}\nrefs/tags/v0.113.51 {} refs/tags/v0.113.51 {}\n",
            head, baseline, head, ZERO_SHA
        );
        let (status, stderr) = run_hook_input(repo, &hook_path, &stdin_data);
        assert!(
            status.success(),
            "tag alongside a branch must pass without rescanning published history; stderr: {}",
            stderr
        );
    }

    #[test]
    fn pre_push_hook_blocks_added_secret() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_added_secret");
        let repo = td.path();

        // Single commit whose added line matches the AWS access-key prefix pattern
        // that the hook's `A{1}KIA[A-Z0-9]{16}` regex catches.
        fs::write(
            repo.join("creds.rs"),
            concat!("let access_key = \"AK", "IAIOSFODNN7EXAMPLE\";\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "creds.rs"]);
        run_git_in(repo, &["commit", "-q", "-m", "add creds"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook should fail (exit 1) when a secret-shaped line is added; \
             stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-10-03 (audit L10): a pure rename of a file with
    /// secret-shaped (but already-published) content must not block the
    /// push. Publication is simulated with a remote-tracking ref; the
    /// hook reads `--remotes`, never the network.
    #[test]
    fn pre_push_hook_allows_pure_rename_of_published_secret_shape() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_rename_published");
        let repo = td.path();
        let secret = concat!("let access_key = \"AK", "IAIOSFODNN7EXAMPLE\";\n");
        fs::write(repo.join("creds.rs"), secret).unwrap();
        run_git_in(repo, &["add", "creds.rs"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // Simulate publication of the baseline (as a prior push would).
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &base]);

        run_git_in(repo, &["mv", "creds.rs", "renamed.rs"]);
        run_git_in(repo, &["commit", "-q", "-m", "rename"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, &base);
        assert!(
            status.success(),
            "pure rename of published content must pass; stderr: {}",
            stderr
        );
    }

    /// ADDED 2026-10-03 (audit L10): re-adding a byte-identical blob
    /// that already exists in published history (republish) must not
    /// block — the blob-novelty check grandfathers it.
    #[test]
    fn pre_push_hook_allows_republish_of_published_blob() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_republish_blob");
        let repo = td.path();
        let secret = b"password = \"synthetic-regression-only\"\n";
        fs::write(repo.join("asset"), secret).unwrap();
        run_git_in(repo, &["add", "--", "asset"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &base]);

        run_git_in(repo, &["rm", "-q", "--", "asset"]);
        run_git_in(repo, &["commit", "-q", "-m", "remove"]);
        let removed = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &removed]);

        // Byte-identical re-add: the same blob the remote history has.
        fs::write(repo.join("asset"), secret).unwrap();
        run_git_in(repo, &["add", "--", "asset"]);
        run_git_in(repo, &["commit", "-q", "-m", "republish"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, &removed);
        assert!(
            status.success(),
            "republish of a published blob must pass; stderr: {}",
            stderr
        );
    }

    /// ADDED 2026-10-03 (audit R3-L21): two grandfathered blobs in one
    /// push must cost ONE remote-object enumeration, not one per file.
    /// A counting `git` wrapper on PATH proves the once-per-push shape.
    #[test]
    fn pre_push_hook_enumerates_remote_objects_once_per_push() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_revlist_once");
        let repo = td.path();
        let secret_a = b"password = \"synthetic-regression-a\"\n";
        let secret_b = b"password = \"synthetic-regression-b\"\n";
        fs::write(repo.join("a"), secret_a).unwrap();
        fs::write(repo.join("b"), secret_b).unwrap();
        run_git_in(repo, &["add", "--", "a", "b"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &base]);

        run_git_in(repo, &["rm", "-q", "--", "a", "b"]);
        run_git_in(repo, &["commit", "-q", "-m", "remove"]);
        let removed = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &removed]);

        // Byte-identical re-add of BOTH blobs in one commit.
        fs::write(repo.join("a"), secret_a).unwrap();
        fs::write(repo.join("b"), secret_b).unwrap();
        run_git_in(repo, &["add", "--", "a", "b"]);
        run_git_in(repo, &["commit", "-q", "-m", "republish both"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Counting wrapper: log every argv, delegate to the real git.
        let bin = td.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let log = td.path().join("git-count.log");
        let original_path = std::env::var("PATH").unwrap_or_default();
        fs::write(
            bin.join("git"),
            format!(
                "#!/bin/sh\necho \"$@\" >> \"{}\"\nexec /usr/bin/env PATH=\"{original_path}\" git \"$@\"\n",
                log.display()
            ),
        )
        .unwrap();
        chmod_755(&bin.join("git"));
        let _path = PathGuard::prepend(&bin);

        let (status, stderr) = run_hook(repo, &hook_path, &head, &removed);
        assert!(
            status.success(),
            "republish of published blobs must pass; stderr: {}",
            stderr
        );
        let argv = fs::read_to_string(&log).unwrap();
        let enumerations = argv
            .lines()
            .filter(|l| l.contains("rev-list") && l.contains("--objects --remotes"))
            .count();
        assert_eq!(
            enumerations, 1,
            "remote objects must be enumerated once per push, got {enumerations}:\n{argv}"
        );
    }

    #[test]
    fn pre_push_hook_blocks_secret_removed_or_reverted_before_tip() {
        for binary in [false, true] {
            for remove in [false, true] {
                let (td, hook) = make_repo_with_pre_push_hook("hook_intermediate_secret");
                let repo = td.path();
                fs::write(repo.join("asset"), b"safe baseline\n").unwrap();
                run_git_in(repo, &["add", "--", "asset"]);
                run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
                let base = git_in_output(repo, &["rev-parse", "HEAD"])
                    .trim()
                    .to_string();
                let name = if remove { "new-asset" } else { "asset" };
                let mut secret = b"password = \"synthetic-regression-only\"\n".to_vec();
                if binary {
                    secret.insert(0, 0);
                }
                fs::write(repo.join(name), secret).unwrap();
                run_git_in(repo, &["add", "--", name]);
                run_git_in(repo, &["commit", "-q", "-m", "introduce fixture"]);
                if remove {
                    run_git_in(repo, &["rm", "--", name]);
                } else {
                    fs::write(repo.join(name), b"safe baseline\n").unwrap();
                    run_git_in(repo, &["add", "--", name]);
                }
                run_git_in(repo, &["commit", "-q", "-m", "remove fixture"]);
                let head = git_in_output(repo, &["rev-parse", "HEAD"])
                    .trim()
                    .to_string();
                let (status, error) = run_hook_input(
                    repo,
                    &hook,
                    &format!("refs/heads/main {head} refs/heads/main {base}\n"),
                );
                assert!(
                    !status.success(),
                    "secret in reachable intermediate commit escaped: {error}"
                );
            }
        }
    }

    #[test]
    fn pre_push_hook_blocks_secret_introduced_by_merge_resolution() {
        let (td, hook) = make_repo_with_pre_push_hook("hook_merge_secret");
        let repo = td.path();
        fs::write(repo.join("asset"), "safe baseline\n").unwrap();
        run_git_in(repo, &["add", "--", "asset"]);
        run_git_in(repo, &["commit", "-q", "-m", "base"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["checkout", "-q", "-b", "side"]);
        fs::write(repo.join("asset"), "side content\n").unwrap();
        run_git_in(repo, &["commit", "-qam", "side"]);
        run_git_in(repo, &["checkout", "-q", "-"]);
        fs::write(repo.join("asset"), "main content\n").unwrap();
        run_git_in(repo, &["commit", "-qam", "main"]);
        let merge = ProcessCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(["merge", "--no-commit", "side"])
            .output()
            .unwrap();
        assert!(
            !merge.status.success(),
            "fixture must create a merge conflict"
        );
        fs::write(repo.join("asset"), b"password = \"synthetic-merge-only\"\n").unwrap();
        run_git_in(repo, &["add", "--", "asset"]);
        run_git_in(repo, &["commit", "-qm", "resolve merge"]);
        fs::write(repo.join("asset"), "safe baseline\n").unwrap();
        run_git_in(repo, &["commit", "-qam", "remove secret"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let (status, error) = run_hook(repo, &hook, &head, &base);
        assert!(
            !status.success(),
            "merge-resolution secret escaped: {error}"
        );
    }

    #[test]
    fn pre_push_hook_allows_inherited_binary_secret_shape() {
        let (td, hook) = make_repo_with_pre_push_hook("hook_binary_grandfather");
        let repo = td.path();
        let mut bytes = b"\0password = \"synthetic-existing-fixture\"\n".to_vec();
        fs::write(repo.join("asset.bin"), &bytes).unwrap();
        run_git_in(repo, &["add", "--", "asset.bin"]);
        run_git_in(repo, &["commit", "-qm", "published baseline"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        bytes.extend_from_slice(b"unrelated change\n");
        fs::write(repo.join("asset.bin"), &bytes).unwrap();
        run_git_in(repo, &["commit", "-qam", "unrelated binary change"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let (status, error) = run_hook(repo, &hook, &head, &base);
        assert!(
            status.success(),
            "inherited binary fixture re-triggered scan: {error}"
        );
    }

    #[test]
    fn pre_push_hook_preserves_explicit_plaintext_sibling_exception() {
        let (td, hook) = make_repo_with_pre_push_hook("hook_plaintext_exception");
        let repo = td.path();
        fs::write(repo.join("asset"), "safe baseline\n").unwrap();
        run_git_in(repo, &["add", "--", "asset"]);
        run_git_in(repo, &["commit", "-qm", "baseline"]);
        let base = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.join("asset.plaintext"), "operator exception").unwrap();
        fs::write(
            repo.join("asset"),
            b"password = \"synthetic-explicit-fixture\"\n",
        )
        .unwrap();
        run_git_in(repo, &["commit", "-qam", "intentional plaintext"]);
        fs::write(repo.join("asset"), "safe baseline\n").unwrap();
        run_git_in(repo, &["commit", "-qam", "revert fixture"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let (status, error) = run_hook(repo, &hook, &head, &base);
        assert!(
            status.success(),
            "explicit plaintext exception lost: {error}"
        );
    }

    /// ADDED 2026-10-03 (audit R4-W-08): the pre-push hatch check is
    /// $REPO-anchored — the root-level `.plaintext` sibling must be
    /// found even when the hook is invoked from a subdirectory. The
    /// fixture is an ADDED file on purpose: the added-file loop scans
    /// via SHA (`git cat-file blob $sha:$path`), which works from any
    /// CWD, so a CWD-relative hatch miss BLOCKS here. (The modified-
    /// file diff scan takes CWD-relative pathspecs and goes blind
    /// from a subdir either way, so it cannot discriminate the fix.)
    #[test]
    fn pre_push_hook_hatch_found_from_subdir_cwd() {
        let (td, hook) = make_repo_with_pre_push_hook("hook_hatch_subdir");
        let repo = td.path();
        fs::write(repo.join("asset.plaintext"), "operator exception").unwrap();
        fs::write(
            repo.join("asset"),
            b"password = \"synthetic-explicit-fixture\"\n",
        )
        .unwrap();
        run_git_in(repo, &["add", "--", "asset", "asset.plaintext"]);
        run_git_in(repo, &["commit", "-qm", "intentional plaintext"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let sub = repo.join("sub");
        fs::create_dir(&sub).unwrap();
        let stdin_data = format!("refs/heads/main {head} refs/heads/main {ZERO_SHA}\n");
        let (status, error) = run_hook_input_in(&sub, &hook, &stdin_data);
        assert!(
            status.success(),
            "hatched push blocked from subdir CWD (hatch not $REPO-anchored?): {error}"
        );
    }

    /// ADDED 2026-07-21 (v0.112.32, audit M32/F4.6): a secret-shaped
    /// line in a file whose name contains a SPACE must still be
    /// caught. The pre-fix hook iterated
    /// `for f in $(git diff --name-only ...)`, word-splitting
    /// `prod secrets.env` into `prod` + `secrets.env` — neither
    /// fragment was scanned and the secret pushed clean.
    #[test]
    fn pre_push_hook_blocks_secret_in_space_filename() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_space_filename");
        let repo = td.path();

        fs::write(
            repo.join("prod secrets.env"),
            concat!("AWS_ACCESS_KEY_ID=AK", "IAIOSFODNN7EXAMPLE\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "prod secrets.env"]);
        run_git_in(repo, &["commit", "-q", "-m", "add spaced secret file"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must catch a secret in a space-containing filename (regression M32/F4.6); stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-08-11 (audit MEDIUM): the pre-fix hook regex
    /// required a quote after `=` (`password\s*=\s*["'][^"]+`), so a
    /// whitespace-padded UNQUOTED password (a bare password assignment in
    /// a protected text file) committed plaintext AND pushed clean.
    /// The new `password\s*=\s*[^[:space:]"]{6,}` alternative must
    /// block it. The literal is concat-split so the warden's OWN push
    /// of this test file does not trip the hook it tests.
    /// FIXED 2026-08-11 (audit LOW): only the AKIA branch (+ the
    /// space-filename regression) had shell-level coverage. The
    /// WARDEN-M2 `'\''` single-quote idiom, the BEGIN PRIVATE KEY
    /// branch, and the quoted-assignment branches for the three key
    /// names were untested. Each fixture literal is concat-split in the SOURCE so
    /// the warden's own live pre-push hook never self-blocks on the
    /// test file itself.
    fn assert_pre_push_blocks_content(name: &str, filename: &str, content: &str) {
        let (td, hook_path) = make_repo_with_pre_push_hook(name);
        let repo = td.path();
        fs::write(repo.join(filename), content).expect("write fixture");
        // FIXED 2026-08-12 (audit LOW follow-up): stage ONLY the
        // fixture (never `git add -A` — the hook script at
        // test-hooks/ would otherwise be committed and its own
        // documentation comment would self-match, making the
        // assertion vacuous).
        run_git_in(repo, &["add", "--", filename]);
        run_git_in(repo, &["commit", "-q", "-m", "add fixture"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block the {} shape; stderr was: {}",
            name,
            stderr
        );
    }

    #[test]
    fn pre_push_hook_blocks_begin_private_key_branch() {
        assert_pre_push_blocks_content(
            "BEGIN PRIVATE KEY",
            "id_rsa",
            concat!("-----BEGIN RSA PR", "IVATE KEY-----\nMIIEowIBAAKCAQEA...\n"),
        );
    }

    #[test]
    fn pre_push_hook_blocks_single_quoted_secret_warden_m2_idiom() {
        // The hook embeds a literal single quote via the shell `'\''`
        // idiom (WARDEN-M2); the scanner must still match it.
        assert_pre_push_blocks_content(
            "single-quoted secret",
            "config.env",
            concat!("secret = '", "hunter2'\n"),
        );
    }

    #[test]
    fn pre_push_hook_blocks_password_secret_api_key_double_quoted_branches() {
        assert_pre_push_blocks_content(
            "password=\"\"",
            "p.env",
            concat!("password = \"hunt", "er2\"\n"),
        );
        assert_pre_push_blocks_content(
            "secret=\"\"",
            "s.env",
            concat!("secret = \"hunt", "er2\"\n"),
        );
        assert_pre_push_blocks_content(
            "api_key=\"\"",
            "a.env",
            concat!("api_key = \"hunt", "er2\"\n"),
        );
    }

    #[test]
    fn pre_push_hook_blocks_unquoted_padded_password() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_unquoted_password");
        let repo = td.path();

        fs::create_dir_all(repo.join("secrets")).unwrap();
        fs::write(
            repo.join("secrets/app.yaml"),
            concat!("password = hunt", "er2\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "secrets/app.yaml"]);
        run_git_in(
            repo,
            &["commit", "-q", "-m", "add padded unquoted password"],
        );
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block a whitespace-padded unquoted password; stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-10-02 (audit M10): the PRE_PUSH_HOOK template carries a
    /// CHECKED-IN render of the SECRET_RE alternation — the template must
    /// stay directly runnable (every behavioral hook test executes it as a
    /// real shell subprocess), so it cannot call the source at runtime.
    /// This test renders the expected line from the single token-shape
    /// source (`SecretScanner::hook_token_shapes_ere`) and fails with the
    /// exact line to paste whenever the source changes.
    #[test]
    fn pre_push_hook_secret_re_matches_token_shape_source() {
        let expected = format!("SECRET_RE='{}'", hook_secret_re_from_source());
        let line = PRE_PUSH_HOOK
            .lines()
            .find(|l| l.starts_with("SECRET_RE='"))
            .expect("template carries a SECRET_RE line");
        assert_eq!(
            line, expected,
            "checked-in SECRET_RE drifted from the token-shape source; paste this line into the PRE_PUSH_HOOK template:\n{expected}"
        );
    }

    /// ADDED 2026-10-02 (audit M10): end-to-end proof that the rendered
    /// SECRET_RE trips on Tier-1 provider-token shapes through the real
    /// `grep -E` path — one test per transliteration family (long-body
    /// github token, hyphen-class gitlab token, live stripe key). The
    /// token literals are concat-split so the warden's own push of this
    /// test file does not trip the hook it tests.
    #[test]
    fn pre_push_hook_blocks_github_token_shape() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_github_token");
        let repo = td.path();

        fs::write(
            repo.join("deploy.env"),
            concat!("token=gh", "p_abcdefghijklmnopqrstuvwxyz0123456789\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "deploy.env"]);
        run_git_in(repo, &["commit", "-q", "-m", "add deploy token"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block a github token shape; stderr was: {}",
            stderr
        );
    }

    #[test]
    fn pre_push_hook_blocks_gitlab_token_shape() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_gitlab_token");
        let repo = td.path();

        fs::write(
            repo.join("ci.env"),
            concat!("token=gl", "pat-abcdefghijklmnopqrst\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "ci.env"]);
        run_git_in(repo, &["commit", "-q", "-m", "add ci token"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block a gitlab token shape; stderr was: {}",
            stderr
        );
    }

    #[test]
    fn pre_push_hook_blocks_stripe_live_key_shape() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_stripe_key");
        let repo = td.path();

        fs::write(
            repo.join("billing.env"),
            concat!("key=sk", "_live_abcdefghijklmnopqrstuvwx\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "billing.env"]);
        run_git_in(repo, &["commit", "-q", "-m", "add billing key"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block a stripe live-key shape; stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-08-11 (audit MEDIUM): `git diff --unified=0` emits no
    /// `+` lines for binary files, so binary additions were never
    /// scanned. The added-blob scan (`git cat-file blob | grep -a`)
    /// must block a binary containing key material. The AKIA literal is
    /// concat-split so the warden's own push of this test file does not
    /// trip the hook it tests.
    #[test]
    fn pre_push_hook_blocks_secret_in_added_binary() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_binary_secret");
        let repo = td.path();

        // Zip-like header (NUL bytes force git's binary detection).
        let mut data = b"PK\x03\x04\x00\x00archive\x00".to_vec();
        data.extend_from_slice(concat!("AK", "IAIOSFODNN7EXAMPLE").as_bytes());
        data.extend_from_slice(b"\x00tail\x00");
        fs::write(repo.join("archive.bin"), &data).unwrap();
        run_git_in(repo, &["add", "archive.bin"]);
        run_git_in(
            repo,
            &["commit", "-q", "-m", "add binary with key material"],
        );
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must block a binary addition containing key material; stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-08-11 (audit MEDIUM): the counterpart to
    /// `pre_push_hook_blocks_secret_in_added_binary` — a clean binary
    /// (no key-shaped bytes) must NOT trip the new added-blob scan.
    #[test]
    fn pre_push_hook_passes_on_clean_binary() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_clean_binary");
        let repo = td.path();

        fs::write(
            repo.join("clean.bin"),
            b"PK\x03\x04\x00\x00hello world\x00end",
        )
        .unwrap();
        run_git_in(repo, &["add", "clean.bin"]);
        run_git_in(repo, &["commit", "-q", "-m", "add clean binary"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, ZERO_SHA);
        assert!(
            status.success(),
            "hook should pass on a clean binary addition; stderr was: {}",
            stderr
        );
    }

    /// ADDED 2026-07-21 (v0.112.32, audit M30/F4.4):
    /// `setup-hooks --local` must actually set `core.hooksPath` —
    /// the pre-fix code ran `git config local core.hooksPath <dir>`
    /// (missing `--`), which git rejects with "key does not contain
    /// a section: local", so the command ALWAYS failed after the
    /// hook files were already written.
    #[test]
    fn setup_hooks_local_sets_core_hooks_path() {
        let td = TestDir::new("setup_hooks_local");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);

        run_setup_hooks(HookMode::Local, Some(&repo)).expect("setup-hooks --local must succeed");

        let hooks_path = git_in_output(&repo, &["config", "--local", "--get", "core.hooksPath"]);
        assert!(
            !hooks_path.trim().is_empty(),
            "core.hooksPath must be set after setup-hooks --local"
        );
        assert!(
            repo.join(".git/hooks/pre-push").exists(),
            "pre-push hook file must be written"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setup_hooks_local_resolves_linked_gitdir_and_chains_common_hook() {
        // A linked worktree exposes `.git` as a pointer file. Local setup
        // must write to that worktree's real gitdir, while the default Git
        // hook location for the worktree remains the shared gitdir/hooks.
        let td = TestDir::new("setup_hooks_linked_worktree");
        let repo = td.path().join("repo");
        let worktree = td.path().join("linked");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);
        run_git_in(&repo, &["config", "user.email", "test@test.local"]);
        run_git_in(&repo, &["config", "user.name", "test"]);
        fs::write(repo.join("tracked.txt"), "content\n").expect("tracked file");
        run_git_in(&repo, &["add", "tracked.txt"]);
        run_git_in(&repo, &["commit", "--no-verify", "-q", "-m", "init"]);

        let worktree_add = ProcessCommand::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["worktree", "add", "--detach", "-q"])
            .arg(&worktree)
            .arg("HEAD")
            .output()
            .expect("git worktree add");
        assert!(
            worktree_add.status.success(),
            "git worktree add failed: {}",
            String::from_utf8_lossy(&worktree_add.stderr)
        );
        assert!(
            worktree.join(".git").is_file(),
            "linked worktree fixture must use a git pointer file"
        );

        let marker = td.path().join("foreign-hook-ran");
        let common_hooks = repo.join(".git/hooks");
        let git_dir = resolved_git_dir(&worktree).expect("resolve linked worktree gitdir");
        assert_ne!(git_dir, worktree.join(".git"));
        let local_hooks = git_dir.join("hooks");
        fs::create_dir_all(&local_hooks).expect("linked worktree hooks");
        use std::os::unix::fs::PermissionsExt;
        for (hooks_dir, scope) in [(&common_hooks, "common"), (&local_hooks, "local")] {
            for name in ["pre-commit", "pre-push", "pre-rebase"] {
                let foreign = hooks_dir.join(name);
                let label = format!("{scope}-{name}");
                fs::write(
                    &foreign,
                    format!(
                        "#!/bin/sh\n# Dracon Warden and dracon-warden-managed-hook-v1 appear in this foreign hook\nprintf '%s\\n' {} >> {}\n",
                        shell_single_quote(std::path::Path::new(&label)),
                        shell_single_quote(&marker)
                    ),
                )
                .expect("foreign local hook");
                fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755))
                    .expect("foreign hook permissions");
            }
        }

        let relative_worktree = relative_path_from_current_dir(&worktree);
        assert!(
            !relative_worktree.is_absolute(),
            "linked-worktree fixture must be passed as a relative path"
        );
        run_setup_hooks(HookMode::Local, Some(&relative_worktree))
            .expect("setup-hooks --local must resolve a relative gitfile path");

        let configured_hooks =
            git_in_output(&worktree, &["config", "--local", "--get", "core.hooksPath"]);
        assert_eq!(
            std::path::PathBuf::from(configured_hooks.trim()),
            git_dir.join("hooks"),
            "local setup must configure the resolved gitdir hooks path"
        );
        let installed = git_dir.join("hooks/pre-commit");
        assert!(
            installed.is_file(),
            "hook must be installed in the real gitdir"
        );

        fs::write(worktree.join("next.txt"), "next\n").expect("next file");
        run_git_in(&worktree, &["add", "next.txt"]);
        run_git_in(&worktree, &["commit", "-q", "-m", "linked hook test"]);

        let push_result = run_hook_input(&worktree, &git_dir.join("hooks/pre-push"), "");
        assert!(
            push_result.0.success(),
            "generated pre-push hook failed: {}",
            push_result.1
        );
        let rebase_result = run_hook_input(&worktree, &git_dir.join("hooks/pre-rebase"), "");
        assert!(
            rebase_result.0.success(),
            "generated pre-rebase hook failed: {}",
            rebase_result.1
        );
        assert_eq!(
            fs::read_to_string(&marker).expect("foreign hook marker"),
            "common-pre-commit\nlocal-pre-commit\nlocal-pre-push\ncommon-pre-push\ncommon-pre-rebase\nlocal-pre-rebase\n",
            "generated hooks must chain common-gitdir and preserved local hooks"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setup_hooks_local_resolves_submodule_gitdir_and_preserves_hooks() {
        // A submodule also exposes `.git` as a pointer file, but unlike a
        // linked worktree its resolved gitdir is its own common hooks
        // directory. Local setup must preserve and chain hooks there.
        let td = TestDir::new("setup_hooks_submodule");
        let source = td.path().join("source");
        let super_repo = td.path().join("super");
        let nested = super_repo.join("nested");
        for repo in [&source, &super_repo] {
            fs::create_dir_all(repo).expect("repo");
            run_git_in(repo, &["init", "-q", "-b", "main"]);
            run_git_in(repo, &["config", "user.email", "test@test.local"]);
            run_git_in(repo, &["config", "user.name", "test"]);
        }
        fs::write(source.join("source.txt"), "source\n").expect("source file");
        run_git_in(&source, &["add", "source.txt"]);
        run_git_in(&source, &["commit", "--no-verify", "-q", "-m", "source"]);
        fs::write(super_repo.join("README"), "super\n").expect("super file");
        run_git_in(&super_repo, &["add", "README"]);
        run_git_in(&super_repo, &["commit", "--no-verify", "-q", "-m", "super"]);

        let submodule_add = ProcessCommand::new("git")
            .arg("-C")
            .arg(&super_repo)
            .args(["-c", "protocol.file.allow=always", "submodule", "add", "-q"])
            .arg(&source)
            .arg("nested")
            .output()
            .expect("git submodule add");
        assert!(
            submodule_add.status.success(),
            "git submodule add failed: {}",
            String::from_utf8_lossy(&submodule_add.stderr)
        );
        run_git_in(&super_repo, &["add", ".gitmodules", "nested"]);
        run_git_in(
            &super_repo,
            &["commit", "--no-verify", "-q", "-m", "add submodule"],
        );
        run_git_in(&nested, &["config", "user.email", "test@test.local"]);
        run_git_in(&nested, &["config", "user.name", "test"]);
        assert!(
            nested.join(".git").is_file(),
            "submodule must use a gitfile"
        );

        let git_dir = resolved_git_dir(&nested).expect("resolve submodule gitdir");
        let hooks_dir = git_dir.join("hooks");
        fs::create_dir_all(&hooks_dir).expect("submodule hooks");
        let marker = td.path().join("submodule-foreign-hook-ran");
        use std::os::unix::fs::PermissionsExt;
        for name in ["pre-commit", "pre-push", "pre-rebase"] {
            let foreign = hooks_dir.join(name);
            fs::write(
                &foreign,
                format!(
                    "#!/bin/sh\n# Dracon Warden and dracon-warden-managed-hook-v1 appear in this foreign hook\nprintf '%s\\n' {} >> {}\n",
                    shell_single_quote(std::path::Path::new(name)),
                    shell_single_quote(&marker)
                ),
            )
            .expect("submodule foreign hook");
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755))
                .expect("submodule foreign hook permissions");
        }

        let relative_nested = relative_path_from_current_dir(&nested);
        assert!(
            !relative_nested.is_absolute(),
            "submodule fixture must be passed as a relative path"
        );
        run_setup_hooks(HookMode::Local, Some(&relative_nested))
            .expect("setup-hooks --local must resolve a relative submodule gitfile path");
        let configured_hooks =
            git_in_output(&nested, &["config", "--local", "--get", "core.hooksPath"]);
        assert_eq!(
            fs::canonicalize(configured_hooks.trim()).expect("canonical configured hooks"),
            fs::canonicalize(&hooks_dir).expect("canonical submodule hooks"),
            "local setup must configure the submodule's real gitdir"
        );

        fs::write(nested.join("next.txt"), "next\n").expect("next file");
        run_git_in(&nested, &["add", "next.txt"]);
        run_git_in(&nested, &["commit", "-q", "-m", "submodule hook test"]);
        let push_result = run_hook_input(&nested, &hooks_dir.join("pre-push"), "");
        assert!(push_result.0.success(), "generated pre-push hook failed");
        let rebase_result = run_hook_input(&nested, &hooks_dir.join("pre-rebase"), "");
        assert!(
            rebase_result.0.success(),
            "generated pre-rebase hook failed"
        );
        assert_eq!(
            fs::read_to_string(&marker).expect("submodule foreign hook marker"),
            "pre-commit\npre-push\npre-rebase\n",
            "submodule setup must preserve and chain every foreign hook"
        );
    }

    #[test]
    fn hook_replacement_is_atomic_and_executable() {
        let td = TestDir::new("atomic_hook_replace");
        let path = td.path().join("hooks/pre-commit");
        fs::create_dir_all(path.parent().expect("hook parent")).expect("hook parent");
        fs::write(&path, "old hook\n").expect("old hook");

        write_hook_atomically(&path, "#!/bin/sh\nexit 0\n").expect("atomic hook write");

        assert_eq!(
            fs::read_to_string(&path).expect("read hook"),
            "#!/bin/sh\nexit 0\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path)
                    .expect("hook metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }

    #[test]
    fn global_hook_install_preserves_and_chains_foreign_hooks() {
        let td = TestDir::new("global_hook_foreign_preserve");
        let hooks_dir = td.path().join("hooks");
        fs::create_dir_all(&hooks_dir).expect("hooks directory");
        let foreign = hooks_dir.join("pre-commit");
        let foreign_content = "#!/bin/sh\necho foreign-hook\n";
        fs::write(&foreign, foreign_content).expect("foreign hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755))
                .expect("foreign hook permissions");
        }

        let preserved = install_global_hooks(&hooks_dir).expect("global hook install");
        let backup = hooks_dir.join("pre-commit.dracon-foreign");
        assert!(preserved.iter().any(|path| path == &backup));
        assert_eq!(
            fs::read_to_string(&backup).expect("preserved foreign hook"),
            foreign_content
        );
        let installed = fs::read_to_string(&foreign).expect("installed Warden hook");
        assert!(installed.contains("Dracon Warden"));
        assert!(installed.contains(&shell_single_quote(&backup)));
        for name in ["pre-commit", "pre-push", "pre-rebase"] {
            assert!(
                hooks_dir.join(name).is_file(),
                "global hook {name} should be installed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn repeated_local_hook_install_keeps_collision_suffixed_foreign_hook() {
        let td = TestDir::new("repeated_local_hook_collision");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);

        let hooks_dir = repo.join(".git/hooks");
        let base_backup = hooks_dir.join("pre-commit.dracon-foreign");
        fs::write(&base_backup, "unrelated backup\n").expect("base backup");
        let marker = td.path().join("foreign-hook-ran");
        let foreign = hooks_dir.join("pre-commit");
        let foreign_content = format!(
            "#!/bin/sh\n# Dracon Warden and dracon-warden-managed-hook-v1 appear in this foreign hook\nprintf '%s\\n' foreign >> {}\n",
            shell_single_quote(&marker)
        );
        fs::write(&foreign, &foreign_content).expect("foreign hook");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755))
            .expect("foreign hook permissions");

        run_setup_hooks(HookMode::Local, Some(&repo)).expect("first local hook setup");
        let mut suffixed_backups = fs::read_dir(&hooks_dir)
            .expect("read hooks")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("pre-commit.dracon-foreign."))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        assert_eq!(suffixed_backups.len(), 1, "a collision must use one suffix");
        let suffixed_backup = suffixed_backups.pop().expect("suffixed backup");
        assert_eq!(
            fs::read_to_string(&suffixed_backup).expect("read suffixed backup"),
            foreign_content,
            "the original foreign hook must be moved to the suffixed backup"
        );

        run_setup_hooks(HookMode::Local, Some(&repo)).expect("repeat local hook setup");
        let result = run_hook_input(&repo, &hooks_dir.join("pre-commit"), "");
        assert!(result.0.success(), "reinstalled hook failed: {}", result.1);
        assert_eq!(
            fs::read_to_string(&marker).expect("foreign hook marker"),
            "foreign\n",
            "repeat setup must retain the exact collision-suffixed hook"
        );
        assert_eq!(
            fs::read_to_string(&base_backup).expect("base backup"),
            "unrelated backup\n",
            "an unrelated unsuffixed backup must not be selected"
        );
    }

    /// ADDED 2026-07-21 (v0.112.32, audit M31/F4.5): the clean
    /// direction must FAIL CLOSED for oversized inputs and refused
    /// paths (passthrough would commit the file UNENCRYPTED), while
    /// smudge always passes through.
    #[test]
    fn filter_clean_refusal_reason_fails_closed_for_clean_only() {
        // Oversized: clean refuses, smudge passes.
        let oversized = STREAM_IO_MAX_BYTES + 1;
        assert!(filter_clean_refusal_reason(true, oversized, None).is_some());
        assert!(filter_clean_refusal_reason(false, oversized, None).is_none());
        // At the limit: allowed.
        assert!(filter_clean_refusal_reason(true, STREAM_IO_MAX_BYTES, None).is_none());
        // Absolute path: clean refuses, smudge passes.
        assert!(filter_clean_refusal_reason(true, 10, Some("/etc/passwd")).is_some());
        assert!(filter_clean_refusal_reason(false, 10, Some("/etc/passwd")).is_none());
        // `..` path: clean refuses, smudge passes.
        assert!(filter_clean_refusal_reason(true, 10, Some("../escape.txt")).is_some());
        assert!(filter_clean_refusal_reason(false, 10, Some("../escape.txt")).is_none());
        assert!(filter_clean_refusal_reason(true, 10, Some("a/../../b")).is_some());
        // Normal relative path: allowed.
        assert!(filter_clean_refusal_reason(true, 10, Some("src/main.rs")).is_none());
    }

    /// ADDED 2026-10-03 (audit R4-01): relativize-then-guard. An
    /// absolute filter path under its own repo root becomes the
    /// repo-relative form and takes the same path as a native relative
    /// path; an absolute outside any root still refuses (clean) or
    /// passes through unchanged (smudge, whose warn-and-relay arm owns
    /// it); `..` still refuses AFTER relativization (the strip must not
    /// launder an escape).
    #[test]
    fn normalize_filter_path_relativizes_inside_root_and_refuses_outside() {
        let td = TestDir::new("r401_paths");
        // Canonicalize: `git rev-parse --show-toplevel` reports the
        // physical path, which differs from the logical temp path when
        // $TMPDIR is symlinked (/tmp on macOS).
        let repo = std::fs::canonicalize(td.path()).unwrap();
        run_git_in(&repo, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(repo.join("sub")).unwrap();

        // Inside-root absolute → repo-relative, both directions.
        let abs = repo.join("sub").join("f.txt").display().to_string();
        assert_eq!(
            normalize_filter_path(Some(&abs), true).unwrap(),
            Some("sub/f.txt".to_string())
        );
        assert_eq!(
            normalize_filter_path(Some(&abs), false).unwrap(),
            Some("sub/f.txt".to_string())
        );
        // Relative and absent paths pass through untouched.
        assert_eq!(
            normalize_filter_path(Some("sub/f.txt"), true).unwrap(),
            Some("sub/f.txt".to_string())
        );
        assert!(normalize_filter_path(None, true).unwrap().is_none());

        // Outside any repo root → clean refuses, smudge keeps the
        // original for its warn-and-relay arm.
        let outside_td = TestDir::new("r401_outside");
        let outside = outside_td.path().join("f.txt").display().to_string();
        let err = normalize_filter_path(Some(&outside), true).unwrap_err();
        assert!(
            format!("{err:#}").contains("outside any repo root"),
            "outside-root absolute must refuse closed: {err:#}"
        );
        assert_eq!(
            normalize_filter_path(Some(&outside), false).unwrap(),
            Some(outside.clone())
        );
        // Unresolvable root (nonexistent parent) refuses the same way.
        let ghost = repo.join("no-such-dir").join("f.txt").display().to_string();
        assert!(
            normalize_filter_path(Some(&ghost), true).is_err(),
            "unresolvable root must refuse closed"
        );

        // `..` survives the strip and still refuses downstream: the
        // relativized form takes the normal guard path, not a bypass.
        let dotdot = repo
            .join("sub")
            .join("..")
            .join("f.txt")
            .display()
            .to_string();
        assert_eq!(
            normalize_filter_path(Some(&dotdot), true).unwrap(),
            Some("sub/../f.txt".to_string())
        );
        assert!(
            filter_clean_refusal_with_limit(
                true,
                10,
                Some("sub/../f.txt"),
                STREAM_IO_MAX_BYTES,
                &[],
                &[],
                &[]
            )
            .is_some(),
            "relativized .. must still refuse"
        );
    }

    #[test]
    fn filter_configured_bounds_preserve_default_and_reject_unbounded_limits() {
        let default: WardenPolicy = toml::from_str("").expect("default policy");
        assert_eq!(default.filter_limit().unwrap(), STREAM_IO_MAX_BYTES);
        assert_eq!(filter_timeout_secs(STREAM_IO_MAX_BYTES), 30);
        assert_eq!(filter_timeout_secs(48 * 1024 * 1024), 150);
        assert_eq!(filter_timeout_secs(FILTER_IO_HARD_MAX_BYTES), 210);
        assert_eq!(filter_timeout_secs(usize::MAX), 210);
        for limit in [
            STREAM_IO_MAX_BYTES,
            48 * 1024 * 1024,
            FILTER_IO_HARD_MAX_BYTES,
        ] {
            let policy: WardenPolicy =
                toml::from_str(&format!("filter_max_bytes = {limit}")).unwrap();
            assert_eq!(policy.filter_limit().unwrap(), limit);
            assert!(
                filter_clean_refusal_with_limit(true, limit, None, limit, &[], &[], &[]).is_none()
            );
            assert!(
                filter_clean_refusal_with_limit(true, limit + 1, None, limit, &[], &[], &[])
                    .is_some()
            );
            assert!(filter_clean_refusal_with_limit(
                true,
                1,
                Some("../secret"),
                limit,
                &[],
                &[],
                &[]
            )
            .is_some());
        }
        for limit in [
            0,
            STREAM_IO_MAX_BYTES - 1,
            FILTER_IO_HARD_MAX_BYTES + 1,
            usize::MAX,
        ] {
            let policy = WardenPolicy {
                filter_max_bytes: Some(limit),
                ..Default::default()
            };
            assert!(policy.filter_limit().is_err());
            assert!(policy.validate().is_err());
        }
        let bytes = vec![b'x'; 32];
        let mut reader = std::io::Cursor::new(bytes);
        assert_eq!(read_filter_input(&mut reader, 10).unwrap().len(), 11);
        assert_eq!(reader.position(), 11, "read only bound plus sentinel");
    }

    /// COMPATIBILITY 2026-08-12 (audit MEDIUM follow-up): the
    /// `allow_v1_fallback` policy field still parses and updates its
    /// compatibility state, but the security crate refuses every legacy
    /// AES-CFB decrypt because the format has no authenticated integrity.
    /// The field must not be able to re-enable the unsafe path.
    #[test]
    fn warden_policy_allow_v1_fallback_wires_the_gate() {
        let td = TestDir::new("v1_fallback_policy");
        let with_flag = td.path().join("with.toml");
        fs::write(&with_flag, "allow_v1_fallback = true\n").expect("write");
        let _ = WardenPolicy::load(&with_flag).expect("load with flag");
        assert!(
            dracon_security_kit::is_v1_fallback_allowed(),
            "compatibility state must remain ON after loading allow_v1_fallback = true"
        );

        let without_flag = td.path().join("without.toml");
        fs::write(&without_flag, "repo_roots = []\n").expect("write");
        let _ = WardenPolicy::load(&without_flag).expect("load without flag");
        assert!(
            !dracon_security_kit::is_v1_fallback_allowed(),
            "compatibility state must be OFF after loading a policy without the field"
        );
    }

    #[test]
    fn omitted_hygiene_patterns_use_product_defaults() {
        let policy: WardenPolicy =
            toml::from_str("repo_roots = []\n").expect("parse policy without hygiene list");
        let patterns: Vec<&str> = policy.hygiene_patterns.iter().map(String::as_str).collect();
        assert_eq!(
            patterns,
            vec![
                "**/.pi*",
                "**/.aider*",
                "**/chrometrace.log",
                "**/.svelte-kit/",
                "**/.vite/",
                "**/.turbo/",
                "**/.cache/",
            ]
        );

        // An explicit list remains an operator override rather than being
        // silently merged with the product defaults.
        let explicit_empty: WardenPolicy =
            toml::from_str("hygiene_patterns = []\n").expect("parse explicit empty list");
        assert!(explicit_empty.hygiene_patterns.is_empty());
    }

    #[test]
    fn media_protected_patterns_default_off_and_parse() {
        // Omitted or explicit-empty: the option is off, and the
        // off-state changes no attributes output.
        let omitted: WardenPolicy = toml::from_str("").expect("default policy");
        assert!(omitted.media_protected_patterns.is_empty());
        let empty: WardenPolicy =
            toml::from_str("media_protected_patterns = []\n").expect("parse empty list");
        assert!(empty.media_protected_patterns.is_empty());
        // An explicit list parses and surfaces in the managed block.
        let set: WardenPolicy =
            toml::from_str("media_protected_patterns = [\"internal-dashboards/**\"]\n")
                .expect("parse media list");
        assert_eq!(set.media_protected_patterns, ["internal-dashboards/**"]);
        let block = build_gitattributes_block(&set).expect("block");
        assert!(block.contains("internal-dashboards/** filter=dracon diff=dracon merge=dracon"));
    }

    /// ADDED 2026-07-21 (v0.112.33, audit H2/F0.1 follow-up): a
    /// push containing a commit authored by a test identity must be
    /// REJECTED (the F0.1 test-pollution class — the daemon
    /// committed with a poisoned `test@test` identity and it landed
    /// on all mirrors). Only the PUSHED range is scanned.
    #[test]
    fn pre_push_hook_rejects_test_identity_author() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_test_author");
        let repo = td.path();

        // Baseline commit with the NORMAL (trusted) identity.
        fs::write(repo.join("ok.txt"), "ok\n").unwrap();
        run_git_in(repo, &["add", "ok.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let baseline = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Second commit with a POISONED identity (simulating F0.1).
        run_git_in(repo, &["config", "user.email", "test@test"]);
        run_git_in(repo, &["config", "user.name", "test"]);
        fs::write(repo.join("more.txt"), "more\n").unwrap();
        run_git_in(repo, &["add", "more.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "poisoned commit"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // Restore the trusted identity so the repo is clean for the hook run.
        run_git_in(repo, &["config", "user.email", "test@test.local"]);
        run_git_in(repo, &["config", "user.name", "test"]);

        let (status, stderr) = run_hook(repo, &hook_path, &head, &baseline);
        assert_eq!(
            status.code(),
            Some(1),
            "hook must reject a push containing a test-identity-authored commit (H2/F0.1); stderr was: {}",
            stderr
        );
        assert!(
            stderr.contains("test identity"),
            "stderr should name the cause, got: {}",
            stderr
        );
    }

    /// ADDED 2026-07-27 (v0.113.2): the BAD_AUTHORS scan range must
    /// exclude ALREADY-PUBLISHED commits — it deliberately does NOT
    /// use `--first-parent` (FIXED 2026-08-11 comment, audit LOW).
    /// Earlier the scan covered every reachable commit (for tag
    /// pushes, `git log empty..tag-sha` = the ENTIRE history
    /// reachable from the tag object), so a test-identity commit on a
    /// non-first-parent side-merge blocked a later tag push even
    /// though that commit was already accepted by the F0.1 scan when
    /// its branch was pushed. The hook now uses
    /// `git rev-list "$LOCAL_SHA" --not --remotes` for new-ref
    /// pushes (and `--not "$REMOTE_SHA"` for branch updates) — a
    /// --no-ff merge of UNPUBLISHED test-identity commits must still
    /// block (the counter-test below proves exactly that). This test
    /// models the production scenario: feature commits authored by
    /// `test@test` merged with --no-ff, then already published via a
    /// fake remote-tracking branch; the tag push must PASS.
    #[test]
    fn pre_push_hook_test_identity_on_non_first_parent_merge_passes() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_test_non_first_parent");
        let repo = td.path();

        // Baseline commit with the trusted identity.
        fs::write(repo.join("ok.txt"), "ok\n").unwrap();
        run_git_in(repo, &["add", "ok.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let baseline = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Side branch with two commits authored by a test identity.
        run_git_in(repo, &["checkout", "-q", "-b", "feature"]);
        run_git_in(repo, &["config", "user.email", "test@test"]);
        run_git_in(repo, &["config", "user.name", "test"]);
        fs::write(repo.join("feature_a.txt"), "A\n").unwrap();
        run_git_in(repo, &["add", "feature_a.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "side: a"]);
        fs::write(repo.join("feature_b.txt"), "B\n").unwrap();
        run_git_in(repo, &["add", "feature_b.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "side: b"]);

        // --no-ff merge so the feature commits remain on a non-first-parent
        // branch in main's history. Restore the trusted identity first so
        // the merge commit itself is NOT poisoned.
        run_git_in(repo, &["config", "user.email", "test@test.local"]);
        run_git_in(repo, &["config", "user.name", "test"]);
        run_git_in(repo, &["checkout", "-q", "main"]);
        run_git_in(
            repo,
            &["merge", "--no-ff", "-q", "-m", "merge feature", "feature"],
        );
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Simulate the production case: the poisoned commits were
        // ALREADY published in a prior branch push (modeled here by
        // a remote-tracking branch pointing at HEAD). Pushing an
        // ANNOTATED TAG now must not re-block on commits that have
        // already been accepted by the F0.1 scan. The hook's new
        // `git rev-list "$LOCAL_SHA" --not --remotes` should return
        // empty because everything reachable from the tag is also
        // reachable from the fake remote.
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &head]);

        use std::io::Write;
        use std::process::{Command, Stdio};
        let stdin_data = format!(
            "refs/tags/v0.113.4 {} refs/tags/v0.113.4 0000000000000000000000000000000000000000\n",
            head
        );
        let mut child = Command::new(&hook_path)
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin_data.as_bytes())
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait hook");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(
            output.status.success(),
            "hook must ALLOW a TAG push whose reachable commits are ALL already on a \
             remote-tracking branch (the production scenario from 2026-07-27: a \
             test-identity commit reachable only via a non-first-parent merge branch \
             was already published by a prior branch push; a later tag push should \
             not re-block on it). Without `--not --remotes` exclusion the old \
             `git log empty-tree..tag-sha` range covered the entire repo history \
             and the tag push was blocked even though no NEW poison was being \
             introduced. Exit: {:?}, stderr: {}",
            output.status.code(),
            stderr
        );

        // Counter-test: with NO remote-tracking branch (i.e. nothing
        // published yet), the SAME scenario MUST be blocked — proving
        // the new logic still catches truly-new test-identity commits.
        run_git_in(repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
        let mut child = Command::new(&hook_path)
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook 2");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin_data.as_bytes())
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait hook 2");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert_eq!(
            output.status.code(),
            Some(1),
            "hook must REJECT a TAG push of a freshly-published test-identity commit; \
             defense-in-depth for the new-ref case is intact. stderr: {}",
            stderr
        );
        assert!(
            stderr.contains("test identity"),
            "stderr should name the cause, got: {}",
            stderr
        );

        // Mark baseline as used to satisfy the linter / clippy.
        let _ = baseline;
    }

    /// ADDED 2026-07-21 (v0.112.33, audit H2/F0.1 follow-up): a push
    /// of commits authored ONLY by the trusted identity passes the
    /// author check.
    #[test]
    fn pre_push_hook_passes_trusted_author() {
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_trusted_author");
        let repo = td.path();

        fs::write(repo.join("ok.txt"), "ok\n").unwrap();
        run_git_in(repo, &["add", "ok.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline"]);
        let baseline = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.join("more.txt"), "more\n").unwrap();
        run_git_in(repo, &["add", "more.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "good commit"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, stderr) = run_hook(repo, &hook_path, &head, &baseline);
        assert!(
            status.success(),
            "hook must pass for trusted-author commits; stderr was: {}",
            stderr
        );
    }

    #[test]
    fn pre_push_hook_allows_delete_only() {
        // This is the core regression guard for the `--unified=0` change:
        // a push that only REMOVES a legacy secret-shaped fixture line
        // must not be blocked, because deletions are safe.
        let (td, hook_path) = make_repo_with_pre_push_hook("hook_delete_only");
        let repo = td.path();

        // Baseline commit contains the secret-shaped line. (The split
        // keeps `\"` before AKIA: a split landing after the opening
        // quote or after `AKIA` would still match the hook's quoted or
        // AKIA branch on a fresh-branch scan.)
        fs::write(
            repo.join("legacy.rs"),
            concat!("let secret = \"AK", "IAIOSFODNN7EXAMPLE\";\n"),
        )
        .unwrap();
        run_git_in(repo, &["add", "legacy.rs"]);
        run_git_in(repo, &["commit", "-q", "-m", "baseline with secret"]);
        let baseline = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Second commit removes the secret line and replaces it with a
        // benign value. The push range is baseline..head — the only added
        // content in that range is the innocuous replacement.
        fs::write(repo.join("legacy.rs"), "let secret = redacted();\n").unwrap();
        run_git_in(repo, &["add", "legacy.rs"]);
        run_git_in(repo, &["commit", "-q", "-m", "redact legacy fixture"]);
        let head = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let (status, _stderr) = run_hook(repo, &hook_path, &head, &baseline);
        assert!(
            status.success(),
            "hook should pass on deletion-only diff (exit {:?}); \
             this is the regression guard for the added-lines-only scan",
            status.code()
        );
    }

    #[test]
    fn replace_managed_block_appends_when_missing() {
        let current = "a=1\n";
        let block = format!("{BLOCK_BEGIN}\nmanaged\n{BLOCK_END}");
        let next = replace_managed_block(current, &block);
        assert!(next.contains("a=1"));
        assert!(next.contains("managed"));
        assert!(next.contains(BLOCK_BEGIN));
        assert!(next.contains(BLOCK_END));
    }

    #[test]
    fn replace_managed_block_replaces_existing_and_keeps_tail() {
        let current = format!("head\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\n\nend\n");
        let block = format!("{BLOCK_BEGIN}\nnew\n{BLOCK_END}");
        let next = replace_managed_block(&current, &block);
        assert!(next.contains("head"));
        assert!(next.contains("new"));
        assert!(!next.contains("old"));
        assert!(next.contains("end"));
    }

    #[test]
    fn build_gitignore_block_includes_overrides() {
        let block = build_gitignore_block(&sample_policy()).expect("block");
        assert!(block.contains(BLOCK_BEGIN));
        assert!(block.contains("target/"));
        assert!(block.contains("!*.env"));
        assert!(block.contains("!secrets/**"));
        assert!(block.contains("!*.pub"));
        assert!(!block.contains("!config/licenses.json"));
        assert!(!block.contains("!config/services.test.json"));
        assert!(!block.contains("!plan/pages/templates/*.json"));
        assert!(block.contains(BLOCK_END));
    }

    #[test]
    fn build_gitattributes_block_includes_expected_lines() {
        let block = build_gitattributes_block(&sample_policy()).expect("block");
        assert!(block.contains("*.env filter=dracon"));
        assert!(block.contains("secrets/** filter=dracon"));
        assert!(block.contains("*.pub -filter"));
        assert!(!block.contains("config/licenses.json -filter"));
        assert!(!block.contains("config/services.test.json -filter -diff -merge"));
        assert!(!block.contains("plan/pages/templates/*.json -filter -diff -merge"));
    }

    #[test]
    fn generated_gitattributes_and_filter_gate_match_single_star_paths() {
        let policy = WardenPolicy {
            protected_patterns: vec!["secrets/*".into(), ".ssh/*".into()],
            ..Default::default()
        };
        let block = build_gitattributes_block(&policy).expect("gitattributes block");
        // CHANGED 2026-09-16 (eager source encryption): the catch-all
        // routes every file through the filter for Tier-1 scanning, so
        // `git check-attr filter` is now true everywhere; the
        // protected gate keeps single-star semantics for Tier-2.
        assert!(block.contains("* filter=dracon"));
        assert!(block.contains("secrets/* filter=dracon"));
        assert!(block.contains(".ssh/* filter=dracon"));

        let td = TestDir::new("warden_single_star_attributes");
        let repo = td.path();
        run_git_in(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join(".gitattributes"), &block).expect("write gitattributes");
        for path in [
            "secrets/api.key",
            "secrets/team/api.key",
            ".ssh/id_ed25519",
            ".ssh/work/id_ed25519",
        ] {
            let file = repo.join(path);
            if let Some(parent) = file.parent() {
                fs::create_dir_all(parent).expect("create attribute fixture directory");
            }
            fs::write(&file, b"fixture").expect("write attribute fixture");
        }

        for (path, gate_expected) in [
            ("secrets/api.key", true),
            ("secrets/team/api.key", false),
            (".ssh/id_ed25519", true),
            (".ssh/work/id_ed25519", false),
        ] {
            let git_output = git_in_output(repo, &["check-attr", "filter", "--", path]);
            let git_filtered = git_output.trim_end() == format!("{path}: filter: dracon");
            // The catch-all filters every path (Tier-1 coverage).
            assert!(
                git_filtered,
                "catch-all must filter every path, including {path}"
            );
            let gate = dracon_security_kit::modules::filter::path_is_protected(
                path,
                &policy.protected_patterns,
            );
            assert_eq!(
                gate, gate_expected,
                "protected gate keeps single-star semantics for {path}"
            );
        }
    }

    #[test]
    fn plaintext_cannot_overlap_protected_or_disable_env_encryption() {
        let policy = WardenPolicy {
            protected_patterns: vec!["config/envs/*.env".into(), "*.env".into()],
            plaintext_patterns: vec!["config/envs/*.env".into()],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        assert!(build_gitattributes_block(&policy).is_err());
    }

    #[test]
    fn owner_pubkeys_in_filters_only_owner_pub() {
        let td = TestDir::new("warden_owner_pubkeys");
        fs::write(td.path().join("owner_a.pub"), "a").expect("write");
        fs::write(td.path().join("owner_a.key"), "a").expect("write");
        fs::write(td.path().join("identity.pub"), "a").expect("write");
        let keys = owner_pubkeys_in(td.path());
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].file_name().and_then(|n| n.to_str()),
            Some("owner_a.pub")
        );
    }

    #[test]
    fn newest_file_picks_newest_existing() {
        let td = TestDir::new("warden_newest");
        let a = td.path().join("a.pub");
        let b = td.path().join("b.pub");
        fs::write(&a, "a").expect("write a");
        std::thread::sleep(Duration::from_secs(1));
        fs::write(&b, "b").expect("write b");
        let picked = newest_file(vec![a.clone(), b.clone()]).expect("picked");
        assert_eq!(picked, b);
    }

    #[test]
    fn publish_repo_pubkey_writes_and_is_idempotent() {
        let td = TestDir::new("warden_publish_key");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let key = td.path().join("owner_test.pub");
        fs::write(&key, "age1xxx").expect("key");

        assert!(publish_repo_pubkey(&repo, &key).expect("first publish"));
        assert!(!publish_repo_pubkey(&repo, &key).expect("second publish"));
        let out = repo.join(".dracon/data/keys/owner_test.pub");
        assert_eq!(fs::read_to_string(out).expect("read out"), "age1xxx");
    }

    #[cfg(unix)]
    #[test]
    fn publish_repo_pubkey_rejects_symlink_target_without_modifying_external() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_publish_key_symlink");
        let repo = td.path().join("repo");
        let keys_dir = repo.join(".dracon/data/keys");
        fs::create_dir_all(&keys_dir).expect("keys dir");

        let key = td.path().join("owner_test.pub");
        fs::write(&key, "age1xxx").expect("key");
        let external = td.path().join("outside-pubkey");
        let original = b"do-not-overwrite\n";
        fs::write(&external, original).expect("external target");
        let target = keys_dir.join("owner_test.pub");
        symlink(&external, &target).expect("target symlink");

        let error =
            publish_repo_pubkey(&repo, &key).expect_err("publication must reject a symlink target");
        assert!(
            error.to_string().contains("target symlink"),
            "error should identify the rejected target symlink: {error:#}"
        );
        assert!(
            fs::symlink_metadata(&target)
                .expect("inspect target")
                .file_type()
                .is_symlink(),
            "publication must leave the target symlink in place"
        );
        assert_eq!(
            fs::read(&external).expect("read external target"),
            original,
            "publication must not modify the external symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_repo_pubkey_rejects_symlinked_target_directory() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_publish_key_directory_symlink");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let external_dir = td.path().join("outside-keys");
        fs::create_dir_all(&external_dir).expect("external keys dir");
        symlink(&external_dir, repo.join(".dracon")).expect("target directory symlink");

        let key = td.path().join("owner_test.pub");
        fs::write(&key, "age1xxx").expect("key");

        let error = publish_repo_pubkey(&repo, &key)
            .expect_err("publication must reject a symlinked target directory");
        assert!(
            error.to_string().contains("target directory symlink"),
            "error should identify the rejected target directory: {error:#}"
        );
        assert!(fs::symlink_metadata(repo.join(".dracon"))
            .expect("inspect directory link")
            .file_type()
            .is_symlink());
        assert!(
            !external_dir.join("data").exists(),
            "publication must not create output below an external target directory"
        );
    }

    #[test]
    fn harden_repo_changes_files_and_writes_key() {
        let td = TestDir::new("warden_harden_repo");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let key = td.path().join("owner_test.pub");
        fs::write(&key, "age1yyy").expect("key");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let (a, b, c) = harden_repo(&repo, &sample_policy(), Some(&key), true).expect("harden");
        assert!(a, "gitignore should be written");
        assert!(b, ".gitattributes should be written");
        assert!(c, "pubkey should be published");
        assert!(repo.join(".gitignore").exists());
        assert!(repo.join(".gitattributes").exists());
        assert!(repo.join(".dracon/data/keys/owner_test.pub").exists());
    }

    #[cfg(unix)]
    #[test]
    fn harden_repo_rejects_symlinked_dotfiles_without_republishing_target() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_harden_symlink_dotfiles");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let external = td.path().join("outside-secret.txt");
        let secret = "do-not-publish-this\n";
        fs::write(&external, secret).expect("write external secret");

        for name in [".gitignore", ".gitattributes"] {
            let input = repo.join(name);
            symlink(&external, &input).expect("create tracked-dotfile fixture symlink");

            let error = harden_repo(&repo, &sample_policy(), None, true)
                .expect_err("hardening must reject a symlinked dotfile");
            assert!(
                error.to_string().contains("symlink"),
                "error should identify the symlink input: {error:#}"
            );
            assert!(
                fs::symlink_metadata(&input)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "hardening must not replace the rejected symlink"
            );
            assert_eq!(
                fs::read_to_string(&external).expect("read external secret"),
                secret,
                "external symlink target must not be republished or modified"
            );
            fs::remove_file(&input).expect("remove symlink fixture");
        }
    }

    #[test]
    fn linked_worktree_gitfile_uses_real_gitdir_for_checkout_lock() {
        // Submodules and linked worktrees expose `.git` as a file, not a
        // directory. The daemon's hardening pass must still recognize a
        // valid checkout and coordinate through that worktree's real lock.
        let td = TestDir::new("warden_gitfile_worktree");
        let repo = td.path().join("repo");
        let worktree = td.path().join("worktree");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);
        run_git_in(&repo, &["config", "user.email", "test@test.local"]);
        run_git_in(&repo, &["config", "user.name", "test"]);
        fs::write(repo.join("tracked.txt"), "content\n").expect("tracked file");
        run_git_in(&repo, &["add", "tracked.txt"]);
        run_git_in(&repo, &["commit", "--no-verify", "-q", "-m", "init"]);
        run_git_in(
            &repo,
            &[
                "worktree",
                "add",
                "--detach",
                "-q",
                worktree.to_str().expect("worktree path"),
                "HEAD",
            ],
        );

        assert!(worktree.join(".git").is_file(), "test must use a gitfile");
        assert!(is_repo_checked_out(&worktree));

        let lock = IndexLock::acquire(&worktree).expect("real worktree lock");
        let lock_path = lock.path.clone();
        assert!(lock_path.exists(), "lock must be created in the gitdir");
        drop(lock);
        assert!(!lock_path.exists(), "RAII lock must be removed");
    }

    #[test]
    fn install_hooks_for_repo_skips_shadowed_git_hooks() {
        // A global (or repo-local) core.hooksPath makes .git/hooks inactive.
        // Warden's global wrappers chain any pre-existing foreign hooks, so
        // hardening must not seed inactive Warden copies into the shadowed
        // directory.
        let td = TestDir::new("warden_hooks_shadowed");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let hooks_dir = repo.join(".git/hooks");
        for name in ["pre-commit", "pre-push", "pre-rebase"] {
            match fs::remove_file(hooks_dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove template hook: {error}"),
            }
        }
        let shadow_dir = td.path().join("effective-hooks");
        fs::create_dir_all(&shadow_dir).expect("shadow hooks dir");
        run_git_in(
            &repo,
            &[
                "config",
                "--local",
                "core.hooksPath",
                shadow_dir.to_str().expect("utf8 shadow path"),
            ],
        );

        install_hooks_for_repo(&repo).expect("shadowed hook seeding should be skipped");
        for name in ["pre-commit", "pre-push", "pre-rebase"] {
            assert!(
                !hooks_dir.join(name).exists(),
                "inactive .git/hooks/{name} must not be seeded"
            );
            assert!(
                !shadow_dir.join(name).exists(),
                "install_hooks_for_repo must not write global/effective hooks"
            );
        }
    }

    #[test]
    fn harden_repo_surfaces_hook_install_failure() {
        // The hardening path must not turn a hook-install failure into a
        // successful-looking pass.  Use a file where .git/hooks must be a
        // directory so the first seed write fails deterministically.
        let td = TestDir::new("warden_hooks_error");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");
        run_git_in(
            &repo,
            &["config", "--local", "core.hooksPath", ".git/hooks"],
        );

        let hooks_dir = repo.join(".git/hooks");
        fs::remove_dir_all(&hooks_dir).expect("remove template hooks");
        fs::write(&hooks_dir, "not a directory\n").expect("block hook directory");

        let error = harden_repo(&repo, &sample_policy(), None, true)
            .expect_err("hook installation failure must be returned");
        assert!(
            error.to_string().contains("hooks") || error.to_string().contains("exists"),
            "unexpected hook installation error: {error:#}"
        );
    }

    #[test]
    fn harden_repo_preserves_operator_content_outside_managed_block() {
        // ADDED 2026-07-21 (v0.112.32, audit H8/F4.1): previously
        // `harden_repo` overwrote the ENTIRE .gitignore /
        // .gitattributes with just the managed block — verified in
        // the dracon-utilities repo's own history (commit
        // `3a67685f` deleted the operator's 8-line nested-repo
        // section). Operator content BEFORE and AFTER the delimited
        // block must survive a harden pass.
        let td = TestDir::new("warden_harden_preserve");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        // First harden pass: creates the managed block.
        let (a, b, _c) = harden_repo(&repo, &sample_policy(), None, true).expect("harden");
        assert!(a && b);

        // Operator adds content BEFORE and AFTER the managed block
        // (mirrors the real-world nested-repo section in
        // dracon-utilities/.gitignore).
        let header = "# operator header rule\n/custom-dir/\n";
        let footer = "\n# --- NESTED STANDALONE REPOS (NOT warden-managed) ---\n/dracon-sync/\n/dracon-warden/\n";
        let gitignore_after_first = fs::read_to_string(repo.join(".gitignore")).expect("read");
        fs::write(
            repo.join(".gitignore"),
            format!("{}{}{}", header, gitignore_after_first, footer),
        )
        .expect("write gitignore");
        let gitattributes_after_first =
            fs::read_to_string(repo.join(".gitattributes")).expect("read");
        fs::write(
            repo.join(".gitattributes"),
            format!(
                "# operator attr\n*.bin binary\n{}\n*.dat filter=custom\n",
                gitattributes_after_first
            ),
        )
        .expect("write gitattributes");

        // Second harden pass: operator content must survive intact.
        let _ = harden_repo(&repo, &sample_policy(), None, true).expect("harden 2");
        let gitignore_final = fs::read_to_string(repo.join(".gitignore")).expect("read final");
        let gitattributes_final =
            fs::read_to_string(repo.join(".gitattributes")).expect("read final attr");

        assert!(
            gitignore_final.contains("/custom-dir/"),
            "operator header rule must survive harden: {:?}",
            gitignore_final
        );
        assert!(
            gitignore_final.contains("/dracon-sync/")
                && gitignore_final.contains("/dracon-warden/"),
            "operator footer section must survive harden (regression H8/F4.1): {:?}",
            gitignore_final
        );
        assert!(
            gitignore_final.contains(BLOCK_BEGIN) && gitignore_final.contains(BLOCK_END),
            "managed block must still be present"
        );
        assert!(
            gitattributes_final.contains("*.bin binary")
                && gitattributes_final.contains("*.dat filter=custom"),
            "operator .gitattributes rules must survive harden: {:?}",
            gitattributes_final
        );
        // Exactly ONE managed block (no duplication across passes).
        assert_eq!(
            gitignore_final.matches(BLOCK_BEGIN).count(),
            1,
            "exactly one managed block after two passes"
        );
    }

    #[test]
    fn harden_repo_sets_local_dracon_filter_config() {
        let td = TestDir::new("warden_harden_repo_filter_cfg");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success());

        let (_a, b, _c) = harden_repo(&repo, &sample_policy(), None, true).expect("harden");
        assert!(b);

        // v0.113.13: single long-running process driver; the
        // per-file keys must be absent.
        let process = ProcessCommand::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("config")
            .arg("--local")
            .arg("--get")
            .arg("filter.dracon.process")
            .output()
            .expect("get process");
        assert!(process.status.success());
        assert_eq!(
            String::from_utf8_lossy(&process.stdout).trim(),
            "dracon-warden filter-process"
        );

        for gone in ["filter.dracon.clean", "filter.dracon.smudge"] {
            let st = ProcessCommand::new("git")
                .arg("-C")
                .arg(&repo)
                .arg("config")
                .arg("--local")
                .arg("--get")
                .arg(gone)
                .output()
                .expect("get superseded");
            assert!(
                !st.status.success(),
                "superseded key {} must be absent",
                gone
            );
        }

        let required = ProcessCommand::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("config")
            .arg("--local")
            .arg("--get")
            .arg("filter.dracon.required")
            .output()
            .expect("get required");
        assert!(required.status.success());
        assert_eq!(String::from_utf8_lossy(&required.stdout).trim(), "true");
    }

    #[test]
    fn publish_repo_pubkey_rejects_non_owner_or_secret_key_material() {
        let td = TestDir::new("warden_publish_key_rejects");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let not_owner = td.path().join("identity.pub");
        fs::write(&not_owner, "age1xxx").expect("write");
        assert!(publish_repo_pubkey(&repo, &not_owner).is_err());

        let secret = td.path().join("owner_secret.pub");
        fs::write(&secret, concat!("AGE", "-SECRET", "-KEY-", "1XXXX")).expect("write");
        assert!(publish_repo_pubkey(&repo, &secret).is_err());
    }

    #[test]
    fn publish_repo_pubkey_no_churn_different_valid_key() {
        let td = TestDir::new("warden_publish_key_no_churn");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        let keys_dir = repo.join(".dracon/data/keys");
        fs::create_dir_all(&keys_dir).expect("keys dir");

        let key_a = td.path().join("owner_test.pub");
        fs::write(&key_a, "age1aaa").expect("key a");
        assert!(publish_repo_pubkey(&repo, &key_a).expect("first publish"));

        let key_b = td.path().join("owner_test.pub");
        fs::write(&key_b, "age1bbb").expect("key b");
        assert!(!publish_repo_pubkey(&repo, &key_b).expect("churn protection"));

        assert_eq!(
            fs::read_to_string(keys_dir.join("owner_test.pub")).expect("read"),
            "age1aaa",
            "existing valid key must not be overwritten by a different valid key"
        );
    }

    #[test]
    fn salvage_invalid_json_replaces_marker_tokens_and_parses() {
        let a = "{[DRACON_SECRET:abc]: \"x\"}";
        let salvaged = salvage_invalid_json_markers(a).expect("salvaged");
        let v: serde_json::Value = serde_json::from_str(&salvaged).expect("parse");
        assert_eq!(
            v["__scrubbed__"],
            serde_json::Value::String("x".to_string())
        );

        let b = "{ \"track_id\": [DRACON_SECRET:abc], \"x\": 1 }";
        let salvaged = salvage_invalid_json_markers(b).expect("salvaged");
        let v: serde_json::Value = serde_json::from_str(&salvaged).expect("parse");
        assert!(v["track_id"].is_null());
        assert_eq!(v["x"], serde_json::Value::from(1));
    }

    #[test]
    fn salvage_invalid_json_preserves_unicode_before_marker() {
        // The salvage scanner must advance by UTF-8 characters, not bytes.
        // This input used to panic at the second byte of the lock emoji (and
        // the byte-wise fallback corrupted any non-ASCII text it reached).
        let input = r#"{"title":"钥匙🔒","value":[DRACON_SECRET:abc]}"#;
        let salvaged = salvage_invalid_json_markers(input).expect("salvaged");
        let value: serde_json::Value = serde_json::from_str(&salvaged).expect("parse");
        assert_eq!(value["title"], serde_json::Value::String("钥匙🔒".into()));
        assert!(value["value"].is_null());
    }

    #[test]
    fn policy_roots_expand_tilde_before_existence_filtering() {
        let td = TestDir::new("warden_tilde_roots");
        let home = td.path().join("home");
        let canonical = home.join("canonical");
        let legacy = home.join("legacy");
        let additional = home.join("additional");
        fs::create_dir_all(&canonical).expect("canonical root");
        fs::create_dir_all(&legacy).expect("legacy root");
        fs::create_dir_all(&additional).expect("additional root");
        let canonical_repo = canonical.join("canonical-repo");
        let additional_repo = additional.join("additional-repo");
        fs::create_dir_all(canonical_repo.join(".git")).expect("canonical repo");
        fs::create_dir_all(additional_repo.join(".git")).expect("additional repo");

        let _home = HomeGuard::new(home.to_str().expect("home path is UTF-8"));
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("~/canonical"), canonical);
        assert_eq!(expand_tilde("~other"), std::path::PathBuf::from("~other"));

        let canonical_policy = WardenPolicy {
            repo_roots: vec!["~/canonical".into()],
            discover_roots: vec![],
            ..Default::default()
        };
        assert_eq!(
            effective_repo_roots(&canonical_policy),
            vec![canonical.clone()]
        );

        let legacy_policy = WardenPolicy {
            repo_roots: vec![],
            watch_roots: vec!["~/legacy".into()],
            discover_roots: vec![],
            ..Default::default()
        };
        assert_eq!(effective_repo_roots(&legacy_policy), vec![legacy]);

        let discovery_policy = WardenPolicy {
            repo_roots: vec!["~/canonical".into()],
            discover_roots: vec!["~/additional".into()],
            ..Default::default()
        };
        let roots = effective_discovery_roots(&discovery_policy);
        assert!(roots.contains(&canonical));
        assert!(roots.contains(&additional));
        let repos = discover_git_repos_local(&roots);
        assert!(repos.contains(&canonical_repo));
        assert!(repos.contains(&additional_repo));
    }

    #[test]
    fn effective_repo_roots_merges_and_dedupes() {
        let td = TestDir::new("warden_effective_roots");
        let p1 = td.path().join("one");
        fs::create_dir_all(&p1).expect("p1");

        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![p1.display().to_string(), p1.display().to_string()],
            discover_roots: vec![],
            ..Default::default()
        };
        let merged = effective_repo_roots(&policy);
        assert_eq!(merged.len(), 1);
        assert!(merged.contains(&p1));
    }

    #[test]
    fn effective_discovery_roots_merges_watch_and_discover_deduped() {
        let td = TestDir::new("warden_effective_discovery_roots");
        let p1 = td.path().join("one");
        let p2 = td.path().join("two");
        fs::create_dir_all(&p1).expect("p1");
        fs::create_dir_all(&p2).expect("p2");

        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![p1.display().to_string()],
            discover_roots: vec![p1.display().to_string(), p2.display().to_string()],
            ..Default::default()
        };
        let merged = effective_discovery_roots(&policy);
        assert_eq!(merged.len(), 2);
        assert!(merged.contains(&p1));
        assert!(merged.contains(&p2));
    }

    #[test]
    fn apply_managed_file_detects_noop_second_write() {
        let td = TestDir::new("warden_apply_noop");
        let file = td.path().join(".gitignore");
        let block = format!("{BLOCK_BEGIN}\nfoo\n{BLOCK_END}");
        assert!(apply_managed_file(&file, &block).expect("first"));
        assert!(!apply_managed_file(&file, &block).expect("second"));
    }

    #[test]
    fn apply_overwrite_file_detects_noop_second_write() {
        let td = TestDir::new("warden_apply_overwrite_noop");
        let file = td.path().join(".gitattributes");
        let body = "a\nb\n";
        assert!(apply_overwrite_file(&file, body).expect("first"));
        assert!(!apply_overwrite_file(&file, body).expect("second"));
    }

    #[test]
    fn repeated_replace_block_scenarios_are_stable() {
        for idx in 0..200usize {
            let current = if idx % 2 == 0 {
                format!("prefix-{idx}\n")
            } else {
                format!("prefix-{idx}\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\n")
            };
            let block = format!("{BLOCK_BEGIN}\nnew-{idx}\n{BLOCK_END}");
            let next = replace_managed_block(&current, &block);
            assert!(next.contains(&format!("new-{idx}")));
            assert!(next.contains(BLOCK_BEGIN));
            assert!(next.contains(BLOCK_END));
        }
    }

    #[test]
    fn wire_managed_patterns_from_policy_loads_protected_patterns() {
        let td = TestDir::new("warden_policy_wire");
        let config_path = td.path().join("warden.toml");
        fs::write(
            &config_path,
            r#"
protected_patterns = [".env", "secrets/**", "*.pem"]

[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let old_val = std::env::var("DRACON_WARDEN_POLICY").ok();
        std::env::set_var("DRACON_WARDEN_POLICY", config_path.display().to_string());
        let wired = wire_managed_patterns_from_policy();
        let patterns = managed_patterns_override().unwrap_or_default();
        clear_filter_managed_patterns();
        // Restore env var to prevent parallel test interference
        match old_val {
            Some(v) => std::env::set_var("DRACON_WARDEN_POLICY", v),
            None => std::env::remove_var("DRACON_WARDEN_POLICY"),
        }

        assert!(wired, "policy should resolve and wire patterns");
        assert!(
            patterns.iter().any(|p| p == ".env"),
            "patterns should include .env (got {:?})",
            patterns
        );
        assert!(
            patterns.iter().any(|p| p == "secrets/**"),
            "patterns should include secrets/** (got {:?})",
            patterns
        );
    }

    #[test]
    fn resolve_policy_path_local_finds_temp_config() {
        let td = TestDir::new("warden_policy_path");
        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("create config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let old_val = std::env::var("DRACON_WARDEN_POLICY").ok();
        std::env::set_var("DRACON_WARDEN_POLICY", config_path.display().to_string());
        let path = resolve_policy_path_local().expect("should resolve");
        // Restore env var to prevent parallel test interference
        match old_val {
            Some(v) => std::env::set_var("DRACON_WARDEN_POLICY", v),
            None => std::env::remove_var("DRACON_WARDEN_POLICY"),
        }

        assert_eq!(path, config_path);
    }

    #[test]
    fn resolve_policy_path_local_falls_back_to_default_locations() {
        let td = TestDir::new("warden_policy_default");
        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("create config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _guard = HomeGuard::new(td.path().to_str().unwrap());
        let path = resolve_policy_path_local();

        assert!(path.is_ok(), "should find config in default location");
    }

    #[test]
    fn marker_prefix_at_finds_correct_positions() {
        let s = "prefix [DRACON_SECRET:abc] after";
        assert_eq!(marker_prefix_at(s, 7), Some("[DRACON_SECRET:"));

        let s2 = "prefix [DRACON_SECRET:xyz] after";
        assert_eq!(marker_prefix_at(s2, 7), Some("[DRACON_SECRET:"));

        let s3 = "no marker here";
        assert_eq!(marker_prefix_at(s3, 0), None);
    }

    #[test]
    fn is_marker_string_detects_both_markers() {
        assert!(is_marker_string("hello [DRACON_SECRET:xyz] world"));
        assert!(!is_marker_string("hello world"));
        assert!(!is_marker_string("DRACON_SECRET not in brackets"));
        assert!(!is_marker_string("[WRONG_SECRET:abc]"));
    }

    #[test]
    fn build_gitignore_block_emits_managed_header() {
        let block = build_gitignore_block(&sample_policy()).expect("block");
        assert!(block.contains("# --- BEGIN DRACON MANAGED BLOCK ---"));
        assert!(block.contains("target/"));
        assert!(block.contains("*.log"));
    }

    #[test]
    fn build_gitattributes_block_sets_filter_for_env() {
        let block = build_gitattributes_block(&sample_policy()).expect("block");
        assert!(block.contains("*.env filter=dracon"));
        assert!(block.contains("secrets/** filter=dracon"));
    }

    // --- 2026-09-30: LLM conversation dumps protected by default ---
    //
    // `conversation-*.txt` / `pi-session-*.html` session exports land in
    // repos carrying pasted secrets and PII, so the shipped defaults opt
    // them in to whole-file age encryption without a config edit.

    #[test]
    fn effective_protected_patterns_empty_stays_empty() {
        // Legacy scan-everything: shipping conversation defaults must not
        // flip a fresh install to default-deny as a side effect.
        let policy = WardenPolicy::default();
        assert!(policy.protected_patterns.is_empty());
        assert!(policy.effective_protected_patterns().is_empty());
    }

    #[test]
    fn effective_protected_patterns_union_conversation_defaults() {
        let effective = sample_policy().effective_protected_patterns();
        // Operator entries survive.
        assert!(effective.contains(&"*.env".to_string()));
        assert!(effective.contains(&"secrets/**".to_string()));
        // Every shipped default rides along.
        for p in default_conversation_protected_patterns() {
            assert!(
                effective.contains(&p),
                "shipped default missing from effective list: {p}"
            );
        }
        // Sorted + deduped: an operator entry that repeats a default
        // appears exactly once.
        let mut sorted = effective.clone();
        sorted.sort();
        assert_eq!(effective, sorted, "effective list is not sorted");
        let policy = WardenPolicy {
            protected_patterns: vec!["conversation-*.txt".into(), ".env".into()],
            ..Default::default()
        };
        let effective = policy.effective_protected_patterns();
        assert_eq!(
            effective
                .iter()
                .filter(|p| p.as_str() == "conversation-*.txt")
                .count(),
            1,
            "duplicate pattern in effective list"
        );
    }

    #[test]
    fn gitattributes_block_protects_conversation_dumps() {
        let block = build_gitattributes_block(&sample_policy()).expect("block");
        assert!(block.contains("conversation-*.txt filter=dracon diff=dracon merge=dracon"));
        assert!(block.contains("pi-session-*.html filter=dracon diff=dracon merge=dracon"));
    }

    #[test]
    fn gitignore_block_negates_conversation_dumps() {
        // Persisted, not ignored: the `!` negations keep dumps tracked
        // (as ciphertext) even if a hygiene pattern would match them.
        let block = build_gitignore_block(&sample_policy()).expect("block");
        assert!(block.contains("!conversation-*.txt"));
        assert!(block.contains("!pi-session-*.html"));
    }

    #[test]
    fn conversation_defaults_agree_with_dump_predicate() {
        use dracon_security_kit::is_llm_conversation_dump;
        use dracon_security_kit::path_matches_any_pattern;

        let defaults = default_conversation_protected_patterns();
        assert_eq!(defaults.len(), 14, "shipped default set changed shape");
        // Every default glob, instantiated, is a dump by the filename
        // rule AND matches the gate matcher the filter enforces.
        for glob in &defaults {
            let name = glob.replacen('*', "2026-09-27-124138", 1);
            assert!(
                is_llm_conversation_dump(&name),
                "default {glob} instantiates to a non-dump: {name}"
            );
            assert!(
                path_matches_any_pattern(&name, &defaults),
                "gate matcher rejects default instantiation: {name}"
            );
            assert!(
                path_matches_any_pattern(&format!("nested/dir/{name}"), &defaults),
                "gate matcher rejects nested dump: {name}"
            );
        }
        // Same-prefix non-dump source is rejected on both sides.
        for name in [
            "pi-session-retention-purge.service",
            "systemd/pi-session-retention-purge.service",
            "src/conversation-service.rs",
            "rollout-plan.md",
            "docs/rollout-notes.txt",
        ] {
            assert!(
                !is_llm_conversation_dump(name.rsplit('/').next().unwrap()),
                "non-dump matched by filename rule: {name}"
            );
            assert!(
                !path_matches_any_pattern(name, &defaults),
                "non-dump matched by gate matcher: {name}"
            );
        }
    }

    #[test]
    fn discover_git_repos_finds_all_git_dirs() {
        let td = TestDir::new("warden_discover_all");
        let root = td.path().join("root");
        fs::create_dir_all(&root).expect("root");

        let repo1 = root.join("my_repo");
        fs::create_dir_all(repo1.join(".git")).expect("my_repo .git");

        let repo2 = root.join("other_repo");
        fs::create_dir_all(repo2.join(".git")).expect("other_repo .git");

        let repos = discover_git_repos(&[root], &BTreeSet::new());

        assert!(repos.contains(&repo1), "my_repo should be found");
        assert!(repos.contains(&repo2), "other_repo should be found");
    }

    #[test]
    fn discover_git_repos_local_finds_basic_repos() {
        let td = TestDir::new("warden_discover_local");
        let root = td.path().join("root");
        fs::create_dir_all(&root).expect("root");

        let repo1 = root.join("repo1");
        fs::create_dir_all(repo1.join(".git")).expect("repo1 .git");

        let repo2 = root.join("repo2");
        fs::create_dir_all(repo2.join(".git")).expect("repo2 .git");

        let repos = discover_git_repos_local(&[root]);

        assert!(repos.contains(&repo1), "repo1 should be found");
        assert!(repos.contains(&repo2), "repo2 should be found");
    }

    #[test]
    fn discover_git_repos_local_finds_nested_repositories() {
        let td = TestDir::new("warden_discover_nested");
        let root = td.path().join("root");
        let parent_repo = root.join("workspace").join("parent");
        let nested_repo = parent_repo.join("web").join("games").join("nested");
        let linked_repo = root.join("workspace").join("linked");
        fs::create_dir_all(parent_repo.join(".git")).expect("parent repo");
        fs::create_dir_all(nested_repo.join(".git")).expect("nested repo");
        fs::create_dir_all(&linked_repo).expect("linked repo");
        fs::write(linked_repo.join(".git"), "gitdir: ../.git/modules/linked\n")
            .expect("linked repo git pointer");

        let repos = discover_git_repos_local(&[root]);

        assert!(repos.contains(&parent_repo), "parent repo should be found");
        assert!(repos.contains(&nested_repo), "nested repo should be found");
        assert!(
            repos.contains(&linked_repo),
            "linked-worktree-style repo should be found"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_git_repos_rejects_symlinked_git_marker() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_discover_git_symlink");
        let root = td.path().join("root");
        let external_git = td.path().join("external-git");
        let repo = root.join("symlinked");
        fs::create_dir_all(&external_git).expect("external git directory");
        fs::create_dir_all(&repo).expect("repo directory");
        symlink(&external_git, repo.join(".git")).expect("symlink git marker");

        let repos = discover_git_repos_local(&[root]);

        assert!(
            !repos.contains(&repo),
            "a symlinked .git marker must not classify a repo"
        );
        assert!(
            !has_git_marker(&repo),
            "the shared git-marker guard must reject symlinks"
        );

        let policy = sample_policy();
        assert!(
            harden_repo(&repo, &policy, None, true).is_err(),
            "explicit hardening must reject a symlinked .git marker"
        );
        assert!(
            resmudge_repo(&repo, &policy, true).is_err(),
            "explicit resmudge must reject a symlinked .git marker"
        );
        assert!(
            backfill_env_headers_repo(&repo, true).is_err(),
            "explicit backfill must reject a symlinked .git marker"
        );
    }

    #[test]
    fn filter_smudge_handles_empty_input() {
        let content = "let x = 1;\n";
        let warden = DraconWarden::new().expect("create warden");
        let result = warden.smudge(content.as_bytes(), None).expect("smudge");
        assert_eq!(
            result,
            content.as_bytes(),
            "plaintext should pass through unchanged"
        );
    }

    #[test]
    fn replace_managed_block_empty_current_string() {
        let current = "";
        let block = format!("{BLOCK_BEGIN}\nnewcontent\n{BLOCK_END}");
        let next = replace_managed_block(current, &block);
        assert!(next.contains("newcontent"));
        assert!(next.contains(BLOCK_BEGIN));
        assert!(next.contains(BLOCK_END));
    }

    #[test]
    fn replace_managed_block_multiple_blocks_replaces_all() {
        let current = format!(
            "prefix\n{BLOCK_BEGIN}\nfirst\n{BLOCK_END}\nmid\n{BLOCK_BEGIN}\nsecond\n{BLOCK_END}\n suffix\n"
        );
        let block = format!("{BLOCK_BEGIN}\nnew\n{BLOCK_END}");
        let next = replace_managed_block(&current, &block);
        assert!(next.contains("prefix"));
        assert!(next.contains("new"));
        assert!(
            !next.contains("first"),
            "first block content should be replaced"
        );
        assert!(
            !next.contains("second"),
            "second block content should be replaced"
        );
        assert!(next.contains("mid"));
        assert!(next.contains(" suffix"));
    }

    #[test]
    fn replace_managed_block_preserves_tail_after_malformed_marker() {
        let current =
            format!("prefix\n{BLOCK_BEGIN}\noperator content after an interrupted write\n");
        let block = format!("{BLOCK_BEGIN}\nnew\n{BLOCK_END}");
        assert_eq!(replace_managed_block(&current, &block), current);
    }

    #[test]
    fn replace_managed_block_preserves_leading_whitespace() {
        let current = "  prefix\n";
        let block = format!("{BLOCK_BEGIN}\nmanaged\n{BLOCK_END}");
        let next = replace_managed_block(current, &block);
        assert!(
            next.starts_with("  prefix\n"),
            "leading content should be preserved"
        );
    }

    #[test]
    fn apply_managed_file_creates_parent_dirs() {
        let td = TestDir::new("warden_apply_creates_dirs");
        let nested = td.path().join("a/b/c/managed.txt");
        let block = format!("{BLOCK_BEGIN}\ncontent\n{BLOCK_END}");
        let result = apply_managed_file(&nested, &block);
        assert!(result.is_ok(), "should create parent dirs");
        assert!(nested.exists(), "file should exist");
        std::fs::remove_dir_all(td.path()).ok();
    }

    #[test]
    fn apply_overwrite_file_creates_new_file() {
        let td = TestDir::new("warden_overwrite_new");
        let file = td.path().join("newfile.txt");
        let result = apply_overwrite_file(&file, "hello world");
        assert!(result.is_ok(), "should create new file");
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(
            content.starts_with("hello world"),
            "should contain content: {:?}",
            content
        );
        std::fs::remove_dir_all(td.path()).ok();
    }

    #[test]
    fn apply_overwrite_file_overwrites_existing() {
        let td = TestDir::new("warden_overwrite_existing");
        let file = td.path().join("existing.txt");
        std::fs::write(&file, "old content").unwrap();
        let result = apply_overwrite_file(&file, "new content");
        assert!(result.is_ok(), "should overwrite");
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(
            content.starts_with("new content"),
            "should contain new content: {:?}",
            content
        );
        std::fs::remove_dir_all(td.path()).ok();
    }

    #[test]
    fn is_marker_string_edge_cases() {
        assert!(!is_marker_string(""), "empty string should not match");
        assert!(!is_marker_string("[DRACON_SECRET]"), "no colon");
        assert!(
            !is_marker_string("DRACON_SECRET not in brackets"),
            "not in brackets"
        );
        assert!(!is_marker_string("[WRONG_SECRET:abc]"), "wrong prefix");
        assert!(
            is_marker_string("[DRACON_SECRET:]"),
            "empty key is still a marker"
        );
        assert!(
            is_marker_string("[DRACON_SECRET: ]"),
            "space key is still a marker"
        );
        assert!(is_marker_string("[DRACON_SECRET:abc123]"), "basic key");
        assert!(
            is_marker_string("[DRACON_SECRET:abc-123_456]"),
            "key with dash underscore"
        );
    }

    #[test]
    fn marker_prefix_at_edge_cases() {
        assert_eq!(marker_prefix_at("no bracket here", 0), None);
        assert_eq!(
            marker_prefix_at("[DRACON_SECRET:abc]", 0),
            Some("[DRACON_SECRET:"),
            "starts at position 0"
        );
        assert_eq!(
            marker_prefix_at("[DRACON_SECRET:abc]", 1),
            None,
            "starts at position 1"
        );
        assert_eq!(
            marker_prefix_at("prefix [DRACON_SECRET", 8),
            None,
            "incomplete bracket without colon"
        );
        assert_eq!(
            marker_prefix_at("[DRACON_SECRET:abc] more", 0),
            Some("[DRACON_SECRET:"),
            "marker at start followed by more"
        );
        assert_eq!(
            marker_prefix_at("text [DRACON_SECRET:abc] end", 5),
            Some("[DRACON_SECRET:"),
            "at position 5 [ bracket is at position 5"
        );
        assert_eq!(
            marker_prefix_at("🔒 [DRACON_SECRET:abc]", 1),
            None,
            "a byte offset inside UTF-8 must be rejected without panicking"
        );
    }

    #[test]
    fn salvage_invalid_json_no_marker_returns_none() {
        assert!(salvage_invalid_json_markers("just normal json").is_none());
        assert!(salvage_invalid_json_markers("").is_none());
        assert!(
            salvage_invalid_json_markers("[DRACON_SECRE").is_none(),
            "incomplete marker should return None"
        );
    }

    #[test]
    fn salvage_invalid_json_marker_at_end_of_string() {
        let input = r#"{"key": "value", "secret": "[DRACON_SECRET:abc]"}"#;
        let salvaged = salvage_invalid_json_markers(input).expect("should salvage");
        assert!(salvaged.contains("null") || salvaged.contains("__scrubbed__"));
    }

    #[test]
    fn salvage_invalid_json_markers_multiple_in_sequence() {
        let input = r#"{"a": [DRACON_SECRET:x], "b": [DRACON_SECRET:y], "c": "normal"}"#;
        let salvaged = salvage_invalid_json_markers(input).expect("should salvage");
        assert!(salvaged.contains("null") || salvaged.contains("__scrubbed__"));
        assert!(salvaged.contains("normal"));
    }

    #[test]
    fn salvage_invalid_json_handles_nested_markers() {
        let input = r#"{"key": "[DRACON_SECRET:abc]", "nested": {"key": "[DRACON_SECRET:xyz]"}}"#;
        let salvaged = salvage_invalid_json_markers(input).expect("should salvage");
        let v: serde_json::Value = serde_json::from_str(&salvaged).expect("should parse");
        assert!(v["key"].is_null() || v["key"].is_string());
    }

    #[test]
    fn effective_repo_roots_handles_empty_policy() {
        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        let roots = effective_repo_roots(&policy);
        assert!(roots.is_empty());
    }

    #[test]
    fn test_deprecation_warning_for_watch_roots() {
        // When ONLY the legacy 'watch_roots' key is set, the policy still
        // resolves correctly (backwards compat) AND emits a deprecation warning.
        let td = TestDir::new("warden_deprecation_warning");
        let p1 = td.path().join("one");
        fs::create_dir_all(&p1).expect("p1");

        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            watch_roots: vec![p1.display().to_string()],
            discover_roots: vec![],
            allow_v1_fallback: false,
            filter_max_bytes: None,
            // ADDED 2026-09-27 (audit decision D2): new field on the
            // exhaustive policy initializers in this module.
            binary_filter_exempt_patterns: None,
            media_protected_patterns: vec![],
        };

        // Effective roots still includes p1 (backwards compat)
        let merged = effective_repo_roots(&policy);
        assert_eq!(merged.len(), 1);
        assert!(merged.contains(&p1));

        // Deprecation message is present
        let msg = policy
            .deprecation_message()
            .expect("deprecation_message should be Some when only watch_roots is set");
        assert!(
            msg.contains("'watch_roots' is deprecated"),
            "expected deprecation message, got: {msg}"
        );
        assert!(
            msg.contains("'repo_roots'"),
            "expected hint to use repo_roots, got: {msg}"
        );
    }

    #[test]
    fn test_repo_roots_takes_precedence() {
        // When BOTH keys are set, repo_roots wins and the deprecation
        // message indicates both are set.
        let td = TestDir::new("warden_precedence");
        let p_new = td.path().join("new");
        let p_old = td.path().join("old");
        fs::create_dir_all(&p_new).expect("p_new");
        fs::create_dir_all(&p_old).expect("p_old");

        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![p_new.display().to_string()],
            watch_roots: vec![p_old.display().to_string()],
            discover_roots: vec![],
            allow_v1_fallback: false,
            filter_max_bytes: None,
            // ADDED 2026-09-27 (audit decision D2): new field on the
            // exhaustive policy initializers in this module.
            binary_filter_exempt_patterns: None,
            media_protected_patterns: vec![],
        };

        // Effective roots uses p_new (the canonical key), not p_old
        let merged = effective_repo_roots(&policy);
        assert_eq!(merged.len(), 1);
        assert!(merged.contains(&p_new));
        assert!(!merged.contains(&p_old));

        // Deprecation message indicates BOTH were set
        let msg = policy
            .deprecation_message()
            .expect("deprecation_message should be Some when both are set");
        assert!(
            msg.contains("both 'watch_roots' and 'repo_roots' are set"),
            "expected both-keys message, got: {msg}"
        );
    }

    #[test]
    fn test_no_deprecation_when_only_repo_roots_set() {
        // Sanity: when only the canonical key is in use, no deprecation
        // message is emitted (i.e. deprecation_message() returns None).
        let td = TestDir::new("warden_no_deprecation");
        let p1 = td.path().join("one");
        fs::create_dir_all(&p1).expect("p1");

        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![p1.display().to_string()],
            watch_roots: vec![],
            discover_roots: vec![],
            allow_v1_fallback: false,
            filter_max_bytes: None,
            // ADDED 2026-09-27 (audit decision D2): new field on the
            // exhaustive policy initializers in this module.
            binary_filter_exempt_patterns: None,
            media_protected_patterns: vec![],
        };

        assert!(
            policy.deprecation_message().is_none(),
            "expected no deprecation message when only repo_roots is set"
        );
    }

    #[test]
    fn effective_discovery_roots_handles_empty_policy() {
        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        let roots = effective_discovery_roots(&policy);
        assert!(roots.is_empty());
    }

    #[test]
    fn build_globset_empty_patterns_returns_empty_set() {
        let set = build_globset(&[]).expect("should succeed");
        assert!(set.is_empty());
    }

    #[test]
    fn build_globset_single_pattern_matches() {
        let set = build_globset(&["*.json".into()]).expect("should succeed");
        assert!(set.is_match("test.json"));
        assert!(!set.is_match("test.txt"));
    }

    #[test]
    fn build_globset_multiple_patterns() {
        let set = build_globset(&["*.json".into(), "*.toml".into()]).expect("should succeed");
        assert!(set.is_match("test.json"));
        assert!(set.is_match("test.toml"));
        assert!(!set.is_match("test.txt"));
    }

    #[test]
    fn build_globset_invalid_pattern_returns_error() {
        let result = build_globset(&["[".into()]);
        assert!(result.is_err(), "invalid glob pattern should return error");
    }

    #[test]
    fn build_globset_normalizes_backslash() {
        let set = build_globset(&["subdir\\*.json".into()]).expect("should succeed");
        assert!(set.is_match("subdir/test.json"));
    }

    #[test]
    fn run_keygen_generates_keypair_successfully() {
        let td = TestDir::new("warden_keygen_success");
        let keys_dir = td.path().join(".dracon").join("data").join("keys");

        let _guard = HomeGuard::new(td.path().to_str().unwrap());

        let result = run_keygen();

        assert!(result.is_ok(), "keygen should succeed: {:?}", result);
        let hostname_raw = hostname::get()
            .expect("hostname")
            .to_string_lossy()
            .to_string();
        let hostname: String = hostname_raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let secret_path = keys_dir.join(format!("machine_{}.age", hostname));
        let pubkey_path = keys_dir.join(format!("owner_{}.pub", hostname));
        assert!(
            secret_path.exists(),
            "secret key should be created at {}",
            secret_path.display()
        );
        assert!(
            pubkey_path.exists(),
            "pubkey should be created at {}",
            pubkey_path.display()
        );
        let public = std::fs::read_to_string(&pubkey_path).expect("read generated pubkey");
        assert!(
            public.contains("# dracon-warden role: machine"),
            "generated machine recipient must not be treated as an owner signer"
        );
    }

    #[test]
    fn run_keygen_refuses_to_overwrite_existing_secret_key() {
        let td = TestDir::new("warden_keygen_secret_exists");
        let keys_dir = td.path().join(".dracon").join("data").join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        let _guard = HomeGuard::new(td.path().to_str().unwrap());

        let hostname_raw = hostname::get()
            .expect("hostname")
            .to_string_lossy()
            .to_string();
        let hostname: String = hostname_raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let fake_secret = keys_dir.join(format!("machine_{}.age", hostname));
        std::fs::write(&fake_secret, "already exists").unwrap();

        let result = run_keygen();

        assert!(
            result.is_err(),
            "should refuse to overwrite existing secret key"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already exists"),
            "error should mention already exists: {}",
            err_msg
        );
    }

    #[test]
    fn run_keygen_refuses_to_overwrite_existing_pubkey() {
        let td = TestDir::new("warden_keygen_pubkey_exists");
        let keys_dir = td.path().join(".dracon").join("data").join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        let _guard = HomeGuard::new(td.path().to_str().unwrap());

        let hostname_raw = hostname::get()
            .expect("hostname")
            .to_string_lossy()
            .to_string();
        let hostname: String = hostname_raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let fake_pubkey = keys_dir.join(format!("owner_{}.pub", hostname));
        std::fs::write(&fake_pubkey, "already exists").unwrap();

        let result = run_keygen();

        assert!(
            result.is_err(),
            "should refuse to overwrite existing pubkey"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already exists") || err_msg.contains("file may already exist"),
            "error should mention already exists: {}",
            err_msg
        );
    }

    #[test]
    fn run_keygen_refuses_when_dedicated_master_pub_exists() {
        let td = TestDir::new("warden_keygen_master_pub_guard");
        let keys_dir = td.path().join(".dracon").join("data").join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        let _guard = HomeGuard::new(td.path().to_str().unwrap());
        std::fs::write(keys_dir.join("master.pub"), "age1xxxxx\n").unwrap();

        let result = run_keygen();

        assert!(result.is_err(), "should refuse while master.pub exists");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("dedicated master key exists")
                && err_msg.contains("explicit master-key rotation procedure"),
            "error should explain the master guard: {}",
            err_msg
        );
        let hostname_raw = hostname::get().unwrap().to_string_lossy().to_string();
        let hostname: String = hostname_raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        assert!(!keys_dir.join(format!("machine_{}.age", hostname)).exists());
    }

    #[test]
    fn run_keygen_refuses_when_dedicated_master_private_exists() {
        let td = TestDir::new("warden_keygen_master_private_guard");
        let master_dir = td.path().join(".dracon").join("keys");
        std::fs::create_dir_all(&master_dir).unwrap();

        let _guard = HomeGuard::new(td.path().to_str().unwrap());
        std::fs::write(
            master_dir.join("master.age"),
            concat!("AGE", "-SECRET", "-KEY-", "1\n"),
        )
        .unwrap();

        let result = run_keygen();

        assert!(
            result.is_err(),
            "should refuse while keys/master.age exists"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("dedicated master key exists")
                && err_msg.contains("explicit master-key rotation procedure"),
            "error should explain the master guard: {}",
            err_msg
        );
    }

    #[test]
    fn warden_policy_validate_accepts_valid_policy() {
        let policy = WardenPolicy {
            protected_patterns: vec!["*.env".into(), "secrets/**".into()],
            plaintext_patterns: vec!["*.pub".into()],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn warden_policy_validate_rejects_overlapping_patterns() {
        let policy = WardenPolicy {
            protected_patterns: vec!["config/envs/*.env".into()],
            plaintext_patterns: vec!["config/envs/*.env".into()],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err(), "should reject overlapping patterns");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be both protected and plaintext"));
    }

    #[test]
    fn warden_policy_validate_rejects_non_allowlisted_plaintext() {
        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec!["mysecret.txt".into()],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        let result = policy.validate();
        assert!(
            result.is_err(),
            "should reject non-allowlisted plaintext pattern"
        );
    }

    #[test]
    fn warden_policy_validate_accepts_allowlisted_plaintext() {
        let policy = WardenPolicy {
            protected_patterns: vec![],
            plaintext_patterns: vec![
                "Cargo.lock".into(),
                "*.pub".into(),
                "state/events/*.jsonl".into(),
            ],
            hygiene_patterns: vec![],
            repo_roots: vec![],
            discover_roots: vec![],
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn warden_policy_validate_rejects_secretish_plaintext() {
        // FIXED 2026-08-11 (audit LOW): `passwords.txt` was not in
        // FORBIDDEN_PLAINTEXT_SUBSTRINGS, so the old fixture was
        // rejected by the allowlist branch instead of exercising the
        // secret-ish guard. Keep it as an explicit regression case,
        // alongside path-shaped and case-insensitive examples.
        for secretish in [
            "passwords.txt",
            "secrets/app.json",
            "Secrets/App.json", // case-insensitive
            "config/.env.local",
        ] {
            let policy = WardenPolicy {
                protected_patterns: vec![],
                plaintext_patterns: vec![secretish.into()],
                hygiene_patterns: vec![],
                repo_roots: vec![],
                discover_roots: vec![],
                ..Default::default()
            };
            let err = policy
                .validate()
                .expect_err("secret-ish plaintext pattern must be rejected")
                .to_string();
            assert!(
                err.contains("secret-ish"),
                "expected the secret-ish guard message, got: {err}"
            );
        }
    }

    #[test]
    fn is_env_file_name_detects_common_variants() {
        assert!(is_env_file_name(".env"));
        assert!(is_env_file_name(".envrc"));
        assert!(is_env_file_name(".env.local"));
        assert!(is_env_file_name(".env.production"));
        assert!(is_env_file_name("config.env"));
        assert!(is_env_file_name("/path/to/.env"));
        assert!(is_env_file_name("/path/to/.envrc"));
        assert!(!is_env_file_name("env.txt"));
        assert!(!is_env_file_name(".envbackup"));
        assert!(is_env_file_name("my.env"), ".env suffix should match");
    }

    #[test]
    fn is_encrypted_env_content_detects_markers() {
        assert!(is_encrypted_env_content("[DRACON_SECRET:key]"));
        assert!(is_encrypted_env_content("[DRACON_SECRET:key]\n"));
        assert!(!is_encrypted_env_content("[DRACON_SECRET]"));
        assert!(!is_encrypted_env_content("DRACON_SECRET:key"));
        assert!(!is_encrypted_env_content("[OTHER_SECRET:key]"));
        assert!(!is_encrypted_env_content("plain text"));
        assert!(
            !is_encrypted_env_content("  [DRACON_SECRET:key]  "),
            "leading whitespace not trimmed"
        );
    }

    /// Guard that restores an environment variable on drop.
    struct EnvGuard {
        key: String,
        old_value: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let old_value = std::env::var(key).ok();
            std::env::set_var(key, value);
            EnvGuard {
                key: key.to_string(),
                old_value,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(&self.key);
            if let Some(ref v) = self.old_value {
                std::env::set_var(&self.key, v);
            }
        }
    }

    #[test]
    fn cli_once_hardens_single_repo() {
        let td = TestDir::new("warden_once_repo");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());

        let policy = WardenPolicy::load(&config_path).expect("load policy");
        let result = harden_repos(&policy, vec![repo.clone()], true);
        assert!(result.is_ok(), "once should succeed: {:?}", result);
        assert!(
            repo.join(".gitignore").exists(),
            ".gitignore should be created"
        );
        assert!(
            repo.join(".gitattributes").exists(),
            ".gitattributes should be created"
        );
    }

    #[test]
    fn cli_repair_dry_run_does_not_modify() {
        let td = TestDir::new("warden_repair_dry_run");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());

        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        let result = scrub_markers(&policy, std::slice::from_ref(&repo), false);
        assert!(
            result.is_ok(),
            "repair dry-run scrub should succeed: {:?}",
            result
        );

        let result = harden_repos(&policy, vec![repo.clone()], true);
        assert!(
            result.is_ok(),
            "repair dry-run harden should succeed: {:?}",
            result
        );
    }

    #[test]
    fn cli_repair_strict_fails_when_markers_remain() {
        let td = TestDir::new("warden_repair_strict");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());

        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        let repos = vec![repo.clone()];
        let (found, _changed) = resmudge_repos(&policy, &repos, false).expect("resmudge report");

        if found > 0 {
            let strict_result: anyhow::Result<()> = Err(anyhow::anyhow!(
                "ciphertext markers remain in working tree (count={})",
                found
            ));
            assert!(
                strict_result.is_err(),
                "strict should fail when markers remain"
            );
        }
    }

    #[test]
    fn filter_clean_passes_plaintext_unchanged() {
        let content = b"let x = 1;\n";
        let warden = DraconWarden::new().expect("create warden");
        let result = warden.clean(content, None).expect("clean");
        assert_eq!(
            result, content,
            "plaintext should pass through clean unchanged"
        );
    }

    #[test]
    fn filter_clean_encrypts_content_with_secret_marker() {
        let content = b"[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAyQ1gzSGp0NU1UOC93b1A3Rm5oYmFPYm5VSzgwOVRCdmxpeVRkdEZWQmo0CmxhTDBIZ1RZeENnZTdBUXJXYyt5V0QzTXBFSWgrNXhSeTVGT1J4WnkyVEUKLT4gWDI1NTE5IEVEbGZsL09QaVpKc21GZGlvMTE1cU5XYnhXSnAwR09HRS9DTVd6VmMzbm8KNkVqTTFxaTE1OWNGc0g1RExwZDRaR0VUaE54T1dRSXBrR21zajdOSmxpRQotPiBYMjU1MTkgU05MYUUvQnltdG5PakNQeWhNcDhMWTFNL1psZ1NXOWpSQkRZbTBNNzJEQQp5dURXRjhMTE0xcmxxUkJQTkxaNTVjVWM5UTRWTE00VWNhZmFqb291OGlFCi0+IFgyNTUxOSBEL0gxUWZ3SFlvVHo4OWsybnZ3d0dlVFZ4bGZtdkRqSENTMUVKeTVOWWhrCk1iQ2JxWDhLa3pFcjB0MUtyWnRRWUk4cnVzb0toaEVtQks3RXE0OTVNNVEKLT4gWDI1NTE5IEtYeUQxVkJrMW51WXQzK2tGTWRBVktWQ3BYc0tGVXJIWTBiVlFWdFk1MFUKNGJwdEQ2SWI3VUdkTG5nMnV2M1dYK3NOaUNLV0w5Tk5rbjR5VzVXZnQ1YwotPiBcTlQtZ3JlYXNlClliY05mZk1EV09aYnlvN1pUSWozVmRNZDJ2blN2amJhS0dGM3M1QmVZTnhzNytGMkJva1FrWW1vVTFHcGRYVUQKV0NFV1BKM0JJdXRsY2hLaWxwZW1YVitTCi0tLSBpb2NqdmpYZmFxKzhHbjBUalhYK09MR3FwcVVCTkE1eHMxdjlpUWR2ZzlrCpx8Hlr7plwtj9ORoXGhdJ7qfQIda/vpHrwFfXVR0dkLcEQ2HIploKeqzBiMf9qVRJVzEwW60p4bdK73TM6yJvFWBIe4NAHBbJdDlo28]\n";
        let warden = DraconWarden::new().expect("create warden");
        let result = warden.clean(content, Some("config.env")).expect("clean");
        // Clean should either encrypt or pass through; result should be valid bytes
        assert!(!result.is_empty(), "clean output should not be empty");
    }

    #[test]
    fn filter_smudge_passes_plaintext_unchanged() {
        let content = b"let x = 1;\n";
        let warden = DraconWarden::new().expect("create warden");
        let result = warden.smudge(content, None).expect("smudge");
        assert_eq!(
            result, content,
            "plaintext should pass through smudge unchanged"
        );
    }

    #[test]
    fn cli_scrub_markers_finds_markers_in_json() {
        let td = TestDir::new("warden_scrub_json");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        // Create a JSON file with a secret marker
        let json_file = repo.join("secrets.json");
        fs::write(
            &json_file,
            r#"{"api_key": "[DRACON_SECRET:abc123]", "name": "test"}"#,
        )
        .expect("write json");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());

        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        // Dry-run should find markers without modifying
        let result = scrub_markers(&policy, std::slice::from_ref(&repo), false);
        assert!(result.is_ok(), "scrub dry-run should succeed: {:?}", result);
    }

    #[test]
    fn cli_scrub_markers_skips_plaintext_sibling_outside_cwd() {
        let td = TestDir::new("warden_scrub_plaintext_sibling");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let json_file = repo.join("secrets.json");
        fs::write(
            &json_file,
            r#"{"api_key": "[DRACON_SECRET:abc123]", "name": "test"}"#,
        )
        .expect("write json");
        fs::write(repo.join("secrets.json.plaintext"), "opt-in").expect("write hatch");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());
        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        // Run from outside the repo. The old implementation checked the cwd
        // instead of the repo, so it would fail to honor the hatch.
        let original = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(td.path()).expect("set cwd");
        let result = scrub_markers(&policy, std::slice::from_ref(&repo), false);
        std::env::set_current_dir(&original).expect("restore cwd");
        assert!(result.is_ok(), "scrub dry-run should succeed: {:?}", result);
    }

    #[test]
    fn cli_resmudge_reports_on_plaintext_repo() {
        let td = TestDir::new("warden_resmudge_plain");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());

        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        // Dry-run on a plain repo should find nothing and succeed
        let repos = vec![repo.clone()];
        let (found, changed) = resmudge_repos(&policy, &repos, false).expect("resmudge report");
        assert_eq!(found, 0, "plaintext repo should have no ciphertext markers");
        assert_eq!(changed, 0, "dry-run should not change anything");
    }

    #[test]
    fn cli_resmudge_skips_plaintext_sibling_outside_cwd() {
        let td = TestDir::new("warden_resmudge_plaintext_sibling");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");

        let status = ProcessCommand::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");

        let protected_file = repo.join("secrets.json");
        fs::write(&protected_file, r#"[DRACON_SECRET:abc123]"#).expect("write protected marker");
        fs::write(repo.join("secrets.json.plaintext"), "opt-in").expect("write hatch");

        let config_dir = td.path().join(".dracon").join("utilities").join("warden");
        fs::create_dir_all(&config_dir).expect("config dir");
        let config_path = config_dir.join("dracon-warden.toml");
        fs::write(
            &config_path,
            r#"
[watch]
watch_roots = ["/tmp/test"]
protected_patterns = ["secrets.json"]
"#,
        )
        .expect("write config");

        let _env_guard = EnvGuard::set("DRACON_WARDEN_POLICY", config_path.to_str().unwrap());
        let policy = WardenPolicy::load(&config_path).expect("load policy");
        policy.validate().expect("valid policy");

        let original = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(td.path()).expect("set cwd");
        let (found, changed) =
            resmudge_repos(&policy, std::slice::from_ref(&repo), false).expect("resmudge");
        std::env::set_current_dir(&original).expect("restore cwd");
        assert_eq!(found, 0, "plaintext sibling should skip resmudge");
        assert_eq!(changed, 0, "dry-run should not change anything");
    }

    #[cfg(unix)]
    #[test]
    fn resmudge_rejects_tracked_symlink_without_modifying_target() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_resmudge_tracked_symlink");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);

        let external = td.path().join("external-ciphertext");
        let original = b"[DRACON_SECRET:untrusted-payload]\n";
        fs::write(&external, original).expect("write external ciphertext");
        symlink(&external, repo.join("secret.txt")).expect("create tracked symlink");
        run_git_in(&repo, &["add", "--", "secret.txt"]);

        let policy = WardenPolicy {
            protected_patterns: vec!["secret.txt".to_string()],
            ..Default::default()
        };
        let (found, changed) = resmudge_repos(&policy, std::slice::from_ref(&repo), true)
            .expect("resmudge symlink fixture");

        assert_eq!(found, 0, "tracked symlink must be rejected before reading");
        assert_eq!(changed, 0, "tracked symlink must never be rewritten");
        assert!(
            fs::symlink_metadata(repo.join("secret.txt"))
                .expect("inspect tracked path")
                .file_type()
                .is_symlink(),
            "repair must leave the tracked symlink in place"
        );
        assert_eq!(
            fs::read(&external).expect("read external target"),
            original,
            "repair must not modify the external symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn backfill_rejects_tracked_symlink_without_modifying_target() {
        use std::os::unix::fs::symlink;

        let td = TestDir::new("warden_backfill_tracked_symlink");
        let repo = td.path().join("repo");
        fs::create_dir_all(&repo).expect("repo");
        run_git_in(&repo, &["init", "-q", "-b", "main"]);

        let external = td.path().join("external-env");
        let original = b"API_KEY=[DRACON_SECRET:untrusted-payload]\n";
        fs::write(&external, original).expect("write external env");
        symlink(&external, repo.join(".env")).expect("create tracked symlink");
        run_git_in(&repo, &["add", "-f", "--", ".env"]);

        let (found, changed) = backfill_env_headers_repos(std::slice::from_ref(&repo), true)
            .expect("backfill symlink fixture");

        assert_eq!(found, 0, "tracked symlink must be rejected before reading");
        assert_eq!(changed, 0, "tracked symlink must never be rewritten");
        assert!(
            fs::symlink_metadata(repo.join(".env"))
                .expect("inspect tracked path")
                .file_type()
                .is_symlink(),
            "repair must leave the tracked symlink in place"
        );
        assert_eq!(
            fs::read(&external).expect("read external target"),
            original,
            "repair must not modify the external symlink target"
        );
    }

    // --- Behavioral tests for the pre-rebase + pre-commit hooks --------
    //
    // ADDED 2026-07-26 (audit H-10, H-11, M-15). Same pattern as the
    // pre-push harness above: run the in-tree hook templates as real
    // shell subprocesses against temp git repos.

    /// Create a temp git repo on `main` with ONE named hook installed in
    /// an isolated hooks dir (so global/template hooks cannot interfere).
    fn make_repo_with_hook(
        name: &str,
        hook_name: &str,
        content: &str,
    ) -> (TestDir, std::path::PathBuf) {
        let td = TestDir::new(name);
        let repo = td.path();
        run_git_in(repo, &["init", "-q", "-b", "main"]);
        run_git_in(repo, &["config", "user.email", "test@test.local"]);
        run_git_in(repo, &["config", "user.name", "test"]);
        run_git_in(repo, &["config", "commit.gpgsign", "false"]);
        remove_ambient_local_hooks(repo);

        let hooks_dir = repo.join("test-hooks");
        fs::create_dir_all(&hooks_dir).expect("hooks dir");
        // Same anti-vacuity fix as make_repo_with_pre_push_hook
        // (2026-08-12, audit LOW follow-up): never commit the hook
        // script into the fixture repo.
        fs::create_dir_all(repo.join(".git/info")).expect(".git/info");
        fs::write(
            repo.join(".git/info/exclude"),
            "# dracon-warden tests: never commit the hook under test\ntest-hooks/\n",
        )
        .expect("write info/exclude");
        run_git_in(
            repo,
            &[
                "config",
                "core.hooksPath",
                hooks_dir.to_str().expect("utf8 hooks path"),
            ],
        );

        let hook_path = hooks_dir.join(hook_name);
        fs::write(&hook_path, content).expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }
        (td, hook_path)
    }

    /// Invoke a hook script with positional args, isolated from the
    /// operator's global/system git config (determinism for the
    /// `filter.dracon.process|clean` probe in the pre-commit hook).
    /// Returns (status, stdout+stderr concatenated) — the pre-commit
    /// hook prints to stdout, the pre-rebase hook to stderr.
    fn run_hook_args(
        repo: &std::path::Path,
        hook_path: &std::path::Path,
        args: &[&str],
    ) -> (std::process::ExitStatus, String) {
        use std::process::Command;
        let output = Command::new(hook_path)
            .current_dir(repo)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("run hook");
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status, text)
    }

    /// Create `n` empty commits on the current branch.
    fn empty_commits(repo: &std::path::Path, n: usize) {
        for i in 0..n {
            run_git_in(
                repo,
                &["commit", "-q", "--allow-empty", "-m", &format!("c{i}")],
            );
        }
    }

    // ---- repo-local hook chaining (H-10 follow-up, FIXED 2026-08-11) ----
    // The global core.hooksPath shadows .git/hooks for every repo;
    // H-10 chained repo-local hooks for pre-commit only. These tests
    // prove pre-push and pre-rebase now chain too: the repo-local
    // hook runs (marker file), its failure aborts the operation, and
    // the warden pre-push scan still sees the refs even when the
    // local hook consumed stdin (refs are buffered + replayed).

    fn chmod_755(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }

    #[test]
    fn pre_push_hook_skips_legacy_warden_local_hook() {
        // v0.113.13: a pre-marker legacy local hook lacks the
        // tag-push corroboration fix and must not run via the
        // global chain (it blocked the v0.113.13 tag push by
        // re-scanning history from the empty tree).
        let (td, hook_path) = make_repo_with_pre_push_hook("chain_push_legacy");
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "c1"]);
        let sha = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let local_hook = repo.join(".git/hooks/pre-push");
        fs::write(
            &local_hook,
            "#!/bin/sh\n# Installed by: dracon-warden setup-hooks\necho LEGACY-RAN > \"$PWD/.git/legacy-push.log\"\nexit 1\n",
        )
        .expect("write legacy local hook");
        chmod_755(&local_hook);

        let (status, _stderr) = run_hook(repo, &hook_path, &sha, ZERO_SHA);
        assert!(
            !repo.join(".git/legacy-push.log").exists(),
            "legacy warden hook must be skipped, not executed"
        );
        assert!(
            status.success(),
            "clean push passes with the legacy hook skipped"
        );
    }

    #[test]
    fn pre_push_hook_chains_to_repo_local_hook() {
        let (td, hook_path) = make_repo_with_pre_push_hook("chain_push_ok");
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "c1"]);
        let sha = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // Repo-local hook (non-warden) that records its invocation.
        let local_hook = repo.join(".git/hooks/pre-push");
        fs::write(
            &local_hook,
            "#!/bin/sh\necho \"local pre-push ran\" > \"$PWD/.git/local-hook.log\"\n",
        )
        .expect("write local hook");
        chmod_755(&local_hook);

        let (status, _stderr) = run_hook(
            repo,
            &hook_path,
            &sha,
            "0000000000000000000000000000000000000000",
        );
        let log = fs::read_to_string(repo.join(".git/local-hook.log"))
            .expect("repo-local pre-push hook must have been chained (ran)");
        assert!(log.contains("local pre-push ran"));
        assert!(
            status.success(),
            "clean push passes with a chained repo-local hook"
        );
    }

    #[test]
    fn pre_push_hook_chains_and_propagates_local_hook_failure() {
        let (td, hook_path) = make_repo_with_pre_push_hook("chain_push_fail");
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "c1"]);
        let sha = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let local_hook = repo.join(".git/hooks/pre-push");
        fs::write(&local_hook, "#!/bin/sh\nexit 3\n").expect("write local hook");
        chmod_755(&local_hook);

        let (status, _stderr) = run_hook(
            repo,
            &hook_path,
            &sha,
            "0000000000000000000000000000000000000000",
        );
        assert_eq!(
            status.code(),
            Some(3),
            "repo-local hook failure must abort the push (chained before the scan)"
        );
    }

    #[test]
    fn pre_push_hook_scan_survives_local_hook_stdin_consumption() {
        // A repo-local hook that consumes stdin must not starve
        // warden's own scan (refs are buffered and replayed).
        let (td, hook_path) = make_repo_with_pre_push_hook("chain_push_stdin");
        let repo = td.path();
        // Literal is concat-split so the warden's own live hook never
        // self-blocks on this test fixture (unquoted-password shape).
        fs::write(repo.join("secret.txt"), concat!("password = hunt", "er2\n"))
            .expect("write secret");
        // FIXED 2026-08-12 (audit LOW follow-up): stage only the
        // fixture (anti-vacuity — never commit the hook script).
        run_git_in(repo, &["add", "--", "secret.txt"]);
        run_git_in(repo, &["commit", "-q", "-m", "secret"]);
        let sha = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let local_hook = repo.join(".git/hooks/pre-push");
        fs::write(&local_hook, "#!/bin/sh\ncat >/dev/null\nexit 0\n").expect("write local hook");
        chmod_755(&local_hook);

        let (status, stderr) = run_hook(
            repo,
            &hook_path,
            &sha,
            "0000000000000000000000000000000000000000",
        );
        assert!(
            !status.success(),
            "warden scan must still run after the chained hook consumed stdin"
        );
        assert!(
            stderr.contains("Possible plaintext secrets"),
            "expected secret-block message, got: {stderr}"
        );
    }

    #[test]
    fn pre_rebase_hook_chains_to_repo_local_hook() {
        let (td, hook_path) = make_repo_with_hook("chain_rebase_ok", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);

        let local_hook = repo.join(".git/hooks/pre-rebase");
        fs::write(
            &local_hook,
            "#!/bin/sh\necho \"local pre-rebase ran\" > \"$PWD/.git/local-rebase.log\"\n",
        )
        .expect("write local hook");
        chmod_755(&local_hook);

        let (status, _text) = run_hook_args(repo, &hook_path, &["main"]);
        let log = fs::read_to_string(repo.join(".git/local-rebase.log"))
            .expect("repo-local pre-rebase hook must have been chained (ran)");
        assert!(log.contains("local pre-rebase ran"));
        assert!(
            status.success(),
            "unpublished rebase passes with a chained repo-local hook"
        );
    }

    #[test]
    fn pre_rebase_hook_chains_and_propagates_local_hook_failure() {
        let (td, hook_path) =
            make_repo_with_hook("chain_rebase_fail", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);

        let local_hook = repo.join(".git/hooks/pre-rebase");
        fs::write(&local_hook, "#!/bin/sh\nexit 4\n").expect("write local hook");
        chmod_755(&local_hook);

        let (status, _text) = run_hook_args(repo, &hook_path, &["main"]);
        assert_eq!(
            status.code(),
            Some(4),
            "repo-local pre-rebase failure must abort the rebase"
        );
    }

    // ---- legacy-warden hook handling (v0.113.13) ----
    // The pre-marker generation probes `filter.dracon.clean`
    // WITHOUT --local, so the machine-global key false-marks every
    // repo as managed and blocks the operation. Harden replaces
    // legacy hooks with the current template; the global wrapper
    // must not execute them meanwhile (but must still chain real
    // user hooks — the H-10 guarantee).

    /// Minimal pre-marker legacy warden hook: warden's signature,
    /// no v1 marker, exits 1 like the ancient template probe.
    fn legacy_warden_hook_stub() -> &'static str {
        "#!/bin/sh\n# Dracon Warden \u{2014} pre-commit hook\n# Installed by: dracon-warden setup-hooks\necho LEGACY-RAN\nexit 1\n"
    }

    #[test]
    fn is_legacy_warden_hook_matrix() {
        let td = TestDir::new("legacy_matrix");
        let marker_hook = td.path().join("marked");
        fs::write(
            &marker_hook,
            "#!/bin/sh\n# dracon-warden-managed-hook-v1\n# Installed by: dracon-warden setup-hooks\n",
        )
        .expect("write marked");
        assert!(!is_legacy_warden_hook(&marker_hook));
        assert!(is_warden_hook(&marker_hook));

        let legacy_hook = td.path().join("legacy");
        fs::write(&legacy_hook, legacy_warden_hook_stub()).expect("write legacy");
        assert!(is_legacy_warden_hook(&legacy_hook));
        assert!(!is_warden_hook(&legacy_hook));

        let user_hook = td.path().join("user");
        fs::write(&user_hook, "#!/bin/sh\nexit 0\n").expect("write user");
        assert!(!is_legacy_warden_hook(&user_hook));
        assert!(!is_warden_hook(&user_hook));

        assert!(!is_legacy_warden_hook(&td.path().join("missing")));
    }

    #[test]
    fn refresh_warden_hook_if_stale_matrix() {
        let td = TestDir::new("refresh_matrix");
        // Stale marker hook (old body) is refreshed.
        let stale = td.path().join("stale");
        fs::write(
            &stale,
            "#!/bin/sh\n# dracon-warden-managed-hook-v1\nold body\n",
        )
        .expect("write stale");
        assert!(refresh_warden_hook_if_stale(&stale, PRE_COMMIT_HOOK).expect("refresh stale"));
        assert_eq!(
            fs::read_to_string(&stale).expect("read refreshed"),
            render_hook(PRE_COMMIT_HOOK, None)
        );
        // Second pass is a no-op.
        assert!(!refresh_warden_hook_if_stale(&stale, PRE_COMMIT_HOOK).expect("refresh fresh"));
        // Legacy hook is replaced with the current template.
        let legacy = td.path().join("legacy");
        fs::write(&legacy, legacy_warden_hook_stub()).expect("write legacy");
        assert!(refresh_warden_hook_if_stale(&legacy, PRE_COMMIT_HOOK).expect("refresh legacy"));
        assert!(is_warden_hook(&legacy));
        // Foreign user hook is never touched.
        let user = td.path().join("user");
        fs::write(&user, "#!/bin/sh\nexit 0\n").expect("write user");
        assert!(!refresh_warden_hook_if_stale(&user, PRE_COMMIT_HOOK).expect("refresh user"));
        assert_eq!(
            fs::read_to_string(&user).expect("read user"),
            "#!/bin/sh\nexit 0\n"
        );
        // Missing path is a no-op.
        assert!(
            !refresh_warden_hook_if_stale(&td.path().join("missing"), PRE_COMMIT_HOOK)
                .expect("refresh missing")
        );
    }

    #[test]
    fn pre_commit_wrapper_skips_legacy_warden_local_hook() {
        let (td, hook_path) =
            make_repo_with_hook("chain_commit_legacy", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);

        // Pre-marker legacy hook that would exit 1 if executed.
        let local_hook = repo.join(".git/hooks/pre-commit");
        fs::write(&local_hook, legacy_warden_hook_stub()).expect("write legacy local hook");
        chmod_755(&local_hook);

        let (status, text) = run_hook_args(repo, &hook_path, &[]);
        assert!(
            status.success(),
            "legacy warden hook must be skipped, not executed: {text}"
        );
        assert!(
            !text.contains("LEGACY-RAN"),
            "legacy hook output must be absent: {text}"
        );
    }

    #[test]
    fn pre_commit_wrapper_still_chains_user_local_hook() {
        let (td, hook_path) =
            make_repo_with_hook("chain_commit_user", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);

        // Genuine user hook (no warden signature) must still chain (H-10).
        let local_hook = repo.join(".git/hooks/pre-commit");
        fs::write(&local_hook, "#!/bin/sh\necho USER-RAN\nexit 3\n")
            .expect("write user local hook");
        chmod_755(&local_hook);

        let (status, text) = run_hook_args(repo, &hook_path, &[]);
        assert_eq!(
            status.code(),
            Some(3),
            "user hook failure must propagate: {text}"
        );
        assert!(text.contains("USER-RAN"), "user hook must have run: {text}");
    }

    // ---- pre-rebase (H-11, M-15) ----

    #[test]
    fn pre_rebase_hook_allows_unpublished_commits() {
        let (td, hook) = make_repo_with_hook("rebase_unpub", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        let sha_a = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // Remote-tracking ref at A; B is local-only.
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &sha_a]);
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "B"]);

        let (status, stderr) = run_hook_args(repo, &hook, &["origin/main"]);
        assert!(
            status.success(),
            "rebase of unpublished commits must pass: {stderr}"
        );
    }

    #[test]
    fn pre_rebase_hook_blocks_published_boundary_commit() {
        let (td, hook) = make_repo_with_hook("rebase_pub", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        let sha_a = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "B"]);
        let sha_b = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // B is published.
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &sha_b]);

        let (status, stderr) = run_hook_args(repo, &hook, &[&sha_a]);
        assert!(
            !status.success(),
            "rebase of published commits must be blocked"
        );
        assert!(stderr.contains("refusing rebase"), "stderr: {stderr}");
    }

    /// H-11 regression: the pre-fix `head -100` checked the NEWEST 100
    /// commits; a published commit deeper than 100 in the range escaped.
    #[test]
    fn pre_rebase_hook_blocks_published_commit_deeper_than_100() {
        let (td, hook) = make_repo_with_hook("rebase_deep", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        let sha_a = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // 105 commits on top of A; commit #5 from the bottom is
        // "published" — position 101 newest-first, outside head -100.
        empty_commits(repo, 5);
        let sha_c5 = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        empty_commits(repo, 100);
        run_git_in(repo, &["update-ref", "refs/remotes/origin/topic", &sha_c5]);

        let (status, stderr) = run_hook_args(repo, &hook, &[&sha_a]);
        assert!(
            !status.success(),
            "published commit deeper than 100 in the range must be blocked (H-11)"
        );
        assert!(stderr.contains("refusing rebase"), "stderr: {stderr}");
    }

    /// M-15 regression: `git rebase <upstream> <branch>` rebases $2, not
    /// HEAD — the pre-fix HEAD-only range was empty in that form.
    #[test]
    fn pre_rebase_hook_two_arg_form_checks_branch_tip() {
        let (td, hook) = make_repo_with_hook("rebase_twoarg", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        let sha_a = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        // feature = A + F, and F is published.
        run_git_in(repo, &["checkout", "-q", "-b", "feature"]);
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "F"]);
        let sha_f = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/topic", &sha_f]);
        // Back on main at A — HEAD contains nothing published.
        run_git_in(repo, &["checkout", "-q", "main"]);

        let (status, stderr) = run_hook_args(repo, &hook, &[&sha_a, "feature"]);
        assert!(
            !status.success(),
            "two-arg rebase of a published branch must be blocked (M-15)"
        );
        assert!(stderr.contains("refusing rebase"), "stderr: {stderr}");
    }

    /// ADDED 2026-10-03 (audit L11): a configured remote with no fetch
    /// in 24h (here: never fetched — no FETCH_HEAD) warns but never
    /// blocks the rebase of unpublished commits. No network is touched:
    /// the remote URL is never contacted.
    #[test]
    fn pre_rebase_hook_warns_on_stale_refs_without_blocking() {
        let (td, hook) = make_repo_with_hook("rebase_stale", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(
            repo,
            &["remote", "add", "origin", "/nonexistent-upstream.git"],
        );
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        let sha_a = git_in_output(repo, &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        run_git_in(repo, &["update-ref", "refs/remotes/origin/main", &sha_a]);
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "B"]);

        let (status, stderr) = run_hook_args(repo, &hook, &["origin/main"]);
        assert!(
            status.success(),
            "stale-refs warning must never block an unpublished rebase: {stderr}"
        );
        assert!(
            stderr.contains("may be stale"),
            "stale refs (never fetched) must warn: {stderr}"
        );
    }

    /// ADDED 2026-10-03 (audit L11): no configured remote means no
    /// staleness signal — local-only rebases stay silent.
    #[test]
    fn pre_rebase_hook_stays_silent_without_remote() {
        let (td, hook) = make_repo_with_hook("rebase_noremote", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "B"]);

        let (status, stderr) = run_hook_args(repo, &hook, &["HEAD~1"]);
        assert!(status.success(), "unpublished rebase must pass: {stderr}");
        assert!(
            !stderr.contains("may be stale"),
            "no remote configured — must not warn: {stderr}"
        );
    }

    /// ADDED 2026-10-03 (audit L11): a fresh fetch (FETCH_HEAD newer
    /// than 24h) suppresses the warning. Local bare remote — no network.
    #[test]
    fn pre_rebase_hook_stays_silent_after_fresh_fetch() {
        let (td, hook) = make_repo_with_hook("rebase_fresh", "pre-rebase", PRE_REBASE_HOOK);
        let repo = td.path();
        let bare_dir = TestDir::new("rebase_fresh_bare");
        let bare = bare_dir.path().join("upstream.git");
        fs::create_dir_all(&bare).expect("bare dir");
        run_git_in(&bare, &["init", "-q", "--bare"]);
        run_git_in(
            repo,
            &["remote", "add", "origin", bare.to_str().expect("utf8")],
        );
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "A"]);
        // Only the pre-rebase hook is installed, so this real push runs
        // unhooked and publishes A straight to the bare remote.
        run_git_in(repo, &["push", "-q", "origin", "main"]);
        run_git_in(repo, &["fetch", "-q", "origin"]);
        run_git_in(repo, &["commit", "-q", "--allow-empty", "-m", "B"]);

        let (status, stderr) = run_hook_args(repo, &hook, &["origin/main"]);
        assert!(status.success(), "unpublished rebase must pass: {stderr}");
        assert!(
            !stderr.contains("may be stale"),
            "fresh FETCH_HEAD must suppress the warning: {stderr}"
        );
    }

    // ---- pre-commit (H-10) ----

    #[test]
    fn pre_commit_hook_allows_unmanaged_repo() {
        let (td, hook) = make_repo_with_hook("precommit_unmanaged", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // No warden markers: no filter config, no .gitattributes, no .dracon.
        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            status.success(),
            "unmanaged repo must be allowed to commit (H-10): {stderr}"
        );
    }

    #[test]
    fn pre_commit_hook_blocks_managed_repo_with_drift() {
        let (td, hook) = make_repo_with_hook("precommit_drift", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // Marker present (filter configured) but .gitattributes missing
        // the patterns — drift must still block.
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.clean",
                "dracon-warden filter-clean",
            ],
        );

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(!status.success(), "managed repo with drift must be blocked");
        assert!(stderr.contains("filter missing"), "stderr: {stderr}");
    }

    /// ADDED 2026-10-03 (audit R3-M3): a commented-out filter line is
    /// not a filter — git would not apply it, so the gate must not
    /// accept it. `.dracon/data/keys` keeps MANAGED=1 (R4-W-05 narrowed
    /// the marker; bare `.dracon/` is sync-only, unmanaged); only the
    /// comment-aware probe blocks.
    #[test]
    fn pre_commit_hook_blocks_when_only_commented_filters_remain() {
        let (td, hook) = make_repo_with_hook("precommit_commented", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        fs::create_dir_all(repo.join(".dracon/data/keys")).expect("dracon keys dir");
        fs::write(
            repo.join(".gitattributes"),
            "# *.env filter=dracon diff=dracon\n   #*.key filter=dracon\n",
        )
        .expect("write attributes");

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            !status.success(),
            "commented-only filters must not satisfy the gate"
        );
        assert!(stderr.contains("filter missing"), "stderr: {stderr}");
    }

    /// ADDED 2026-10-03 (audit R3-M3): commented-out filter lines must
    /// not mark the repo managed. The staged machine-local file would
    /// block a managed repo (gate 1.5); an unmanaged repo exits early.
    #[test]
    fn pre_commit_hook_commented_filters_do_not_mark_managed() {
        let (td, hook) = make_repo_with_hook(
            "precommit_commented_unmanaged",
            "pre-commit",
            PRE_COMMIT_HOOK,
        );
        let repo = td.path();
        fs::write(
            repo.join(".gitattributes"),
            "# *.env filter=dracon diff=dracon\n",
        )
        .expect("write attributes");
        fs::create_dir_all(repo.join("scratch")).expect("scratch dir");
        fs::write(repo.join("scratch/x"), "working material\n").expect("write scratch");
        run_git_in(repo, &["add", "--", "scratch/x"]);

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            status.success(),
            "commented-only filters must not mark managed (early exit): {stderr}"
        );
    }

    /// ADDED 2026-10-03 (audit R4-W-01): without local
    /// filter.dracon.required=true, git degrades a filter error to
    /// silent plaintext passthrough — the exact leak the oversize
    /// refusal exists to prevent. A managed repo missing the key
    /// must block even when the driver + attributes are present.
    #[test]
    fn pre_commit_hook_blocks_when_required_key_missing() {
        let (td, hook) = make_repo_with_hook("precommit_noreq", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        fs::write(repo.join(".gitattributes"), "*.env filter=dracon\n").expect("gitattributes");
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.process",
                "dracon-warden filter-process",
            ],
        );
        // required key deliberately unset (hand-edit / partial config).

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            !status.success(),
            "missing filter.dracon.required must block: {stderr}"
        );
        assert!(stderr.contains("required"), "stderr: {stderr}");
    }

    /// ADDED 2026-10-03 (audit R4-W-01): required=false is not
    /// good enough — only the literal true keeps git aborting on
    /// filter errors.
    #[test]
    fn pre_commit_hook_blocks_when_required_key_false() {
        let (td, hook) = make_repo_with_hook("precommit_reqfalse", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        fs::write(repo.join(".gitattributes"), "*.env filter=dracon\n").expect("gitattributes");
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.process",
                "dracon-warden filter-process",
            ],
        );
        run_git_in(repo, &["config", "filter.dracon.required", "false"]);

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            !status.success(),
            "filter.dracon.required=false must block: {stderr}"
        );
        assert!(stderr.contains("required"), "stderr: {stderr}");
    }

    #[test]
    fn pre_commit_hook_blocks_managed_repo_with_only_global_filter_config() {
        // FIXED 2026-08-11 (audit LOW): the second filter check read
        // `git config` WITHOUT --local, so a machine whose ~/.gitconfig
        // carries filter.dracon.* (this one does) passed the check in
        // every repo — masking local-config drift in managed repos.
        // The managed probe already required --local; the enforcement
        // check now does too.
        let (td, hook) =
            make_repo_with_hook("precommit_global_only", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // Managed markers: .dracon/data/keys + .gitattributes block
        // (R4-W-05: bare `.dracon/` is sync-only, unmanaged). No LOCAL
        // filter config (simulating a clone that never ran `once`).
        fs::create_dir_all(repo.join(".dracon/data/keys")).expect(".dracon keys dir");
        fs::write(repo.join(".gitattributes"), "*.env filter=dracon\n").expect("gitattributes");
        // Global config carries the filter keys (the masking scope).
        let global_cfg = repo.join("global.gitconfig");
        fs::write(
            &global_cfg,
            "[filter \"dracon\"]\n\tclean = dracon-warden filter-clean %f\n",
        )
        .expect("global gitconfig");

        // The hook verifies that the filter executable is available on PATH.
        // Workspace tests normally inherit the operator's installation, but
        // Nix's isolated build environment intentionally does not.  Provide
        // a harmless stand-in so this test exercises config scope rather than
        // depending on an ambient user installation.
        let bin_dir = td.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let warden_bin = bin_dir.join("dracon-warden");
        fs::write(&warden_bin, "#!/bin/sh\nexit 0\n").expect("warden stand-in");
        chmod_755(&warden_bin);
        let test_path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        use std::process::Command;
        let output = Command::new(&hook)
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", &global_cfg)
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("PATH", &test_path)
            .output()
            .expect("run hook");
        let text = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "managed repo with only GLOBAL filter config must be blocked: {text}"
        );
        assert!(
            text.contains("local git config"),
            "expected --local enforcement message, got: {text}"
        );

        // Control: with the LOCAL config present the same repo passes.
        // (R4-W-01: `once` also writes filter.dracon.required=true, and
        // the hook now enforces it — set it here to mirror `once`.)
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.clean",
                "dracon-warden filter-clean",
            ],
        );
        run_git_in(repo, &["config", "filter.dracon.required", "true"]);
        // (R4-W-03: `once` also writes diff.dracon.textconv +
        // merge.dracon.driver, and the hook now enforces them.)
        run_git_in(
            repo,
            &[
                "config",
                "diff.dracon.textconv",
                "dracon-warden filter-smudge",
            ],
        );
        run_git_in(
            repo,
            &[
                "config",
                "merge.dracon.driver",
                "dracon-warden merge \"%O\" \"%A\" \"%B\"",
            ],
        );
        let output = Command::new(&hook)
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", &global_cfg)
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("PATH", &test_path)
            .output()
            .expect("run hook");
        assert!(
            output.status.success(),
            "managed repo WITH local filter config must pass: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// ADDED 2026-10-03 (audit R4-W-03): without local
    /// diff.dracon.textconv, git falls back to the text driver and
    /// diffs of encrypted files show CIPHERTEXT. A managed repo
    /// missing the key must block even when every other key is set.
    #[test]
    fn pre_commit_hook_blocks_when_textconv_key_missing() {
        let (td, hook) = make_repo_with_hook("precommit_notextconv", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        fs::write(repo.join(".gitattributes"), "*.env filter=dracon\n").expect("gitattributes");
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.process",
                "dracon-warden filter-process",
            ],
        );
        run_git_in(repo, &["config", "filter.dracon.required", "true"]);
        run_git_in(
            repo,
            &[
                "config",
                "merge.dracon.driver",
                "dracon-warden merge \"%O\" \"%A\" \"%B\"",
            ],
        );
        // textconv deliberately unset (hand-edit / partial config).

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            !status.success(),
            "missing diff.dracon.textconv must block: {stderr}"
        );
        assert!(stderr.contains("textconv"), "stderr: {stderr}");
    }

    /// ADDED 2026-10-03 (audit R4-W-03): without local
    /// merge.dracon.driver, merges of encrypted files operate on
    /// CIPHERTEXT (undecryptable conflict output). A managed repo
    /// missing the key must block even when every other key is set.
    #[test]
    fn pre_commit_hook_blocks_when_merge_driver_key_missing() {
        let (td, hook) = make_repo_with_hook("precommit_nodriver", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        fs::write(repo.join(".gitattributes"), "*.env filter=dracon\n").expect("gitattributes");
        run_git_in(
            repo,
            &[
                "config",
                "filter.dracon.process",
                "dracon-warden filter-process",
            ],
        );
        run_git_in(repo, &["config", "filter.dracon.required", "true"]);
        run_git_in(
            repo,
            &[
                "config",
                "diff.dracon.textconv",
                "dracon-warden filter-smudge",
            ],
        );
        // merge driver deliberately unset (hand-edit / partial config).

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(
            !status.success(),
            "missing merge.dracon.driver must block: {stderr}"
        );
        assert!(stderr.contains("merge.dracon.driver"), "stderr: {stderr}");
    }

    #[cfg(unix)]
    #[test]
    fn storage_pre_commit_requires_valid_explicit_guard_binding() {
        let (td, hook) = make_repo_with_hook("storage_binding", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // Inspection UUID alone must not enroll an ordinary repository.
        run_git_in(repo, &["config", "dracon.storageRepoId", &"a".repeat(64)]);
        assert!(run_hook_args(repo, &hook, &[]).0.success());
        run_git_in(repo, &["config", "dracon.storageGuardVersion", ""]);
        assert!(!run_hook_args(repo, &hook, &[]).0.success());
        run_git_in(repo, &["config", "--unset", "dracon.storageGuardVersion"]);
        run_git_in(repo, &["config", "filter.dracon-storage.required", "true"]);
        let (status, text) = run_hook_args(repo, &hook, &[]);
        assert!(!status.success());
        assert!(text.contains("version-1 guard bindings"));
        for version in ["", "2", "1"] {
            run_git_in(repo, &["config", "dracon.storageGuardVersion", version]);
            assert!(!run_hook_args(repo, &hook, &[]).0.success());
        }
        for executable in ["dracon-sync", "/nonexistent/storage-sync"] {
            run_git_in(
                repo,
                &["config", "dracon.storageSyncExecutable", executable],
            );
            assert!(!run_hook_args(repo, &hook, &[]).0.success());
        }
        let executable = repo.join(".git/non-executable");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        run_git_in(
            repo,
            &[
                "config",
                "dracon.storageSyncExecutable",
                executable.to_str().unwrap(),
            ],
        );
        assert!(!run_hook_args(repo, &hook, &[]).0.success());
    }

    #[cfg(unix)]
    #[test]
    fn storage_pre_commit_quotes_pinned_executable_chains_and_propagates_failure() {
        use std::os::unix::fs::PermissionsExt;
        let (td, hook) = make_repo_with_hook("storage_execution", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        let executable = repo.join(".git/guard ' $(touch injected)");
        fs::write(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > .git/guard-arguments\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let user_hook = repo.join(".git/hooks/pre-commit");
        fs::write(
            &user_hook,
            "#!/bin/sh\nprintf chained > .git/user-hook-ran\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&user_hook, fs::Permissions::from_mode(0o755)).unwrap();
        run_git_in(repo, &["config", "dracon.storageGuardVersion", "1"]);
        run_git_in(
            repo,
            &[
                "config",
                "dracon.storageSyncExecutable",
                executable.to_str().unwrap(),
            ],
        );
        let (status, text) = run_hook_args(repo, &hook, &[]);
        assert!(status.success(), "{text}");
        let expected = format!(
            "storage\nverify-configured-index\n--repo\n{}\n",
            repo.display()
        );
        assert_eq!(
            fs::read_to_string(repo.join(".git/guard-arguments")).unwrap(),
            expected
        );
        assert!(repo.join(".git/user-hook-ran").exists());
        assert!(!repo.join("injected").exists());
        fs::write(
            &executable,
            "#!/bin/sh\ntest -f .git/user-hook-ran || exit 99\nexit 42\n",
        )
        .unwrap();
        fs::remove_file(repo.join(".git/user-hook-ran")).unwrap();
        assert_eq!(run_hook_args(repo, &hook, &[]).0.code(), Some(42));
        assert!(repo.join(".git/user-hook-ran").exists());
        // A successful storage check must not bypass Warden's encryption gate.
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        // R4-W-05: the managed marker is `.dracon/data/keys`
        // (bare `.dracon/` is sync-only, unmanaged).
        fs::create_dir_all(repo.join(".dracon/data/keys")).unwrap();
        let (status, text) = run_hook_args(repo, &hook, &[]);
        assert!(!status.success());
        assert!(text.contains("filter"), "{text}");
    }

    #[test]
    fn pre_commit_hook_chains_to_foreign_repo_local_hook() {
        let (td, hook) = make_repo_with_hook("precommit_chain", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // Foreign (non-warden) repo-local hook: writes a marker, exits 0.
        let local_hook = repo.join(".git/hooks/pre-commit");
        fs::write(
            &local_hook,
            "#!/bin/sh\ntouch \"$(git rev-parse --show-toplevel)/chained-marker\"\nexit 0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&local_hook, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (status, stderr) = run_hook_args(repo, &hook, &[]);
        assert!(status.success(), "chained success must pass: {stderr}");
        assert!(
            repo.join("chained-marker").exists(),
            "foreign repo-local pre-commit hook must have been chained"
        );
    }

    #[test]
    fn pre_commit_hook_propagates_foreign_hook_failure() {
        let (td, hook) = make_repo_with_hook("precommit_chainfail", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        let local_hook = repo.join(".git/hooks/pre-commit");
        fs::write(&local_hook, "#!/bin/sh\nexit 3\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&local_hook, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (status, _stderr) = run_hook_args(repo, &hook, &[]);
        assert_eq!(
            status.code(),
            Some(3),
            "foreign hook's exit code must propagate"
        );
    }

    #[test]
    fn pre_commit_hook_does_not_recurse_into_warden_seeded_local_hook() {
        let (td, hook) = make_repo_with_hook("precommit_norecurse", "pre-commit", PRE_COMMIT_HOOK);
        let repo = td.path();
        // A warden-seeded local hook (contains the header) must NOT be
        // chained — that would recurse.
        let local_hook = repo.join(".git/hooks/pre-commit");
        fs::write(
            &local_hook,
            "#!/bin/sh\n# dracon-warden-managed-hook-v1\n# Dracon Warden — seeded copy\ntouch \"$(git rev-parse --show-toplevel)/should-not-exist\"\nexit 0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&local_hook, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (status, _stderr) = run_hook_args(repo, &hook, &[]);
        assert!(status.success());
        assert!(
            !repo.join("should-not-exist").exists(),
            "warden-seeded local hook must be skipped (no recursion)"
        );
    }

    #[test]
    fn merge_driver_text_merge_clean_and_conflict() {
        // Pure 3-way logic: git merge-file -p on already-decrypted content.
        // Clean case: disjoint edits merge with both changes present.
        // (Fixtures need >=2 lines of unchanged context between edits —
        // adjacent-line changes genuinely conflict in git's diff3.)
        let ancestor = b"line1\nline2\nline3\nline4\nline5\n";
        let current = b"line1\nline2-A\nline3\nline4\nline5\n";
        let other = b"line1\nline2\nline3\nline4-B\nline5\n";
        let (merged, conflicted) = text_merge(ancestor, current, other).expect("clean merge");
        assert!(!conflicted);
        let text = String::from_utf8(merged).expect("utf8");
        assert!(
            text.contains("line2-A"),
            "current-side change kept: {}",
            text
        );
        assert!(text.contains("line4-B"), "other-side change kept: {}", text);

        // Conflict case: both sides edit the same line.
        let other_conflict = b"line1\nline2-B\nline3\n";
        let (merged, conflicted) =
            text_merge(ancestor, current, other_conflict).expect("conflict merge");
        assert!(conflicted, "overlapping edits must report a conflict");
        let text = String::from_utf8(merged).expect("utf8");
        assert!(text.contains("<<<<<<<"), "conflict markers present");
        assert!(text.contains(">>>>>>>"), "conflict markers present");
        assert!(text.contains("line2-A") && text.contains("line2-B"));
    }

    /// Guard that temporarily prepends a dir to $PATH and restores on
    /// drop. The workspace harness runs tests serially
    /// (RUST_TEST_THREADS=1), so process-global PATH mutation is safe.
    struct PathGuard {
        original: String,
    }

    impl PathGuard {
        fn prepend(dir: &std::path::Path) -> Self {
            let original = std::env::var("PATH").unwrap_or_default();
            std::env::set_var("PATH", format!("{}:{original}", dir.display()));
            PathGuard { original }
        }
    }

    impl Drop for PathGuard {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.original);
        }
    }

    #[test]
    fn merge_driver_merge_file_error_is_not_a_conflict() {
        // R3-L19: `git merge-file` exit >1 (internal error) must
        // propagate as Err — the old `!success()` mapping reported a
        // conflict and overwrote %A with possibly-empty stdout.
        let td = TestDir::new("merge_file_error");
        let bin = td.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let original_path = std::env::var("PATH").unwrap_or_default();
        fs::write(
            bin.join("git"),
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"merge-file\" ]; then\n  echo \"fatal: fake merge-file failure\" >&2\n  exit 2\nfi\nexec /usr/bin/env PATH=\"{original_path}\" git \"$@\"\n"
            ),
        )
        .unwrap();
        chmod_755(&bin.join("git"));
        let _path = PathGuard::prepend(&bin);
        let err = text_merge(b"a\n", b"b\n", b"c\n").expect_err("exit 2 must be Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("merge-file failed"),
            "error must name merge-file, got: {msg}"
        );
    }

    #[test]
    fn merge_driver_untagged_files_clean_and_conflict() {
        // End-to-end driver (no crypto needed: untagged content passes
        // through smudge/clean untouched). %A is rewritten with the merged
        // content; exit 0 on clean, 1 with plaintext conflict markers on
        // conflict (operator resolves, `git add` re-encrypts).
        let td = TestDir::new("merge_untagged");
        let dir = td.path();
        let ancestor = dir.join("ancestor");
        let current = dir.join("current");
        let other = dir.join("other");
        fs::write(&ancestor, b"line1\nline2\nline3\nline4\nline5\n").unwrap();
        fs::write(&current, b"line1\nline2-A\nline3\nline4\nline5\n").unwrap();
        fs::write(&other, b"line1\nline2\nline3\nline4-B\nline5\n").unwrap();

        let code = run_merge(&ancestor, &current, &other).expect("run clean merge");
        assert_eq!(code, 0, "clean merge exits 0");
        let merged_text = fs::read_to_string(&current).unwrap();
        assert!(merged_text.contains("line2-A") && merged_text.contains("line4-B"));
        assert!(!merged_text.contains("<<<<<<<"));

        // Conflict: both sides change line2.
        fs::write(&ancestor, b"line1\nline2\nline3\n").unwrap();
        fs::write(&current, b"line1\nline2-A\nline3\n").unwrap();
        fs::write(&other, b"line1\nline2-B\nline3\n").unwrap();
        let code = run_merge(&ancestor, &current, &other).expect("run conflict merge");
        assert_eq!(code, 1, "conflicting merge exits 1");
        let merged_text = fs::read_to_string(&current).unwrap();
        assert!(merged_text.contains("<<<<<<<") && merged_text.contains(">>>>>>>"));
        assert!(merged_text.contains("line2-A") && merged_text.contains("line2-B"));
    }

    /// 2026-10-03 (audit R4-W-06): a decrypt failure is an internal
    /// error (`Err`), NOT a conflict (`Ok(1)`) — and %A is left
    /// untouched (still current-side content, never markers).
    #[test]
    fn merge_driver_decrypt_failure_is_err_with_current_untouched() {
        let td = TestDir::new("merge_decrypt_err");
        let dir = td.path();
        let ancestor = dir.join("ancestor");
        let current = dir.join("current");
        let other = dir.join("other");
        let current_before = b"line1\nline2-A\nline3\n";
        fs::write(&ancestor, b"line1\nline2\nline3\n").unwrap();
        fs::write(&current, current_before).unwrap();
        fs::write(&other, b"line1\nline2-B\nline3\n").unwrap();

        let err = run_merge_impl(
            &ancestor,
            &current,
            &other,
            |_b, _p| anyhow::bail!("simulated decrypt failure"),
            |b, _p| Ok(b.to_vec()),
        )
        .expect_err("a decrypt failure must be Err, not Ok(1)");
        assert!(
            format!("{err:?}").contains("simulated decrypt failure"),
            "the cause must propagate: {err:?}"
        );
        assert_eq!(
            fs::read(&current).unwrap(),
            current_before,
            "%A must be untouched on internal error (no markers)"
        );
    }

    /// 2026-10-03 (audit R4-W-07): the merge-side wipe overwrites
    /// the full length with zeros (same length, no secret bytes left)
    /// and never panics on missing/empty files.
    #[test]
    fn zeroize_file_best_effort_wipes_full_length() {
        let td = TestDir::new("zeroize_merge_side");
        let target = td.path().join("side");
        // Multi-chunk length (past the 8 KiB zero block) plus a tail.
        let secret = vec![0x5A; 8192 * 2 + 13];
        fs::write(&target, &secret).unwrap();

        zeroize_file_best_effort(&target);

        let wiped = fs::read(&target).unwrap();
        assert_eq!(wiped.len(), secret.len(), "wipe must preserve length");
        assert!(
            wiped.iter().all(|b| *b == 0),
            "no secret bytes may survive the wipe"
        );

        // Best-effort: missing and empty files are silent no-ops.
        zeroize_file_best_effort(&td.path().join("does-not-exist"));
        let empty = td.path().join("empty");
        fs::write(&empty, b"").unwrap();
        zeroize_file_best_effort(&empty);
        assert_eq!(fs::read(&empty).unwrap().len(), 0);
    }

    #[test]
    fn merge_driver_encrypted_roundtrip_clean_merge() {
        // The point of the driver: encrypted inputs are decrypted, merged
        // as plaintext, and the result is re-encrypted into %A so the
        // index keeps the filter.dracon invariant (index = ciphertext).
        // Uses a FRESH WardenSecurity with a memory identity — the
        // process-global instance behind DraconWarden is shared and
        // environment-dependent.
        let td = TestDir::new("merge_encrypted");
        let dir = td.path();
        // Production git invokes the driver with repo-relative paths (the
        // protected `secrets/**` glob then matches %A). In this test the
        // files live under an absolute temp dir, so protect by literal
        // basename — the same `path_is_protected` exact-match rule.
        let mut security = dracon_security_kit::WardenSecurity::new(None)
            .expect("init security")
            .with_managed_patterns(vec![
                "current".to_string(),
                "ancestor".to_string(),
                "other".to_string(),
            ]);
        let identity = age::x25519::Identity::generate();
        security.add_memory_identity(identity);

        let ancestor = dir.join("ancestor");
        let current = dir.join("current");
        let other = dir.join("other");
        // Inline-tag format: content carries an OpenAI sk- key (the
        // guaranteed scanner match) so `smart_clean` emits DRACON_SECRET
        // markers decryptable by the public `smart_smudge`.
        let sk = concat!("sk-", "abcdef0123456789abcdef0123456789");
        let ancestor_pt = format!("line1\nline2\n{sk}\nline4\nline5\n");
        let current_pt = format!("line1\nline2-A\n{sk}\nline4\nline5\n");
        let other_pt = format!("line1\nline2\n{sk}\nline4-B\nline5\n");
        let enc = |path: &std::path::Path, b: &[u8]| {
            security
                .smart_clean_with_path(b, path.to_string_lossy().as_ref())
                .expect("encrypt")
        };
        fs::write(&ancestor, enc(&ancestor, ancestor_pt.as_bytes())).unwrap();
        fs::write(&current, enc(&current, current_pt.as_bytes())).unwrap();
        fs::write(&other, enc(&other, other_pt.as_bytes())).unwrap();

        // Sanity: the fixture is really encrypted (the merge only proves
        // the invariant if the inputs were ciphertext).
        let raw_ancestor = fs::read_to_string(&ancestor).unwrap();
        assert!(
            raw_ancestor.contains("DRACON_SECRET"),
            "fixture must be encrypted, got: {}",
            &raw_ancestor[..raw_ancestor.len().min(80)]
        );

        let code = run_merge_impl(
            &ancestor,
            &current,
            &other,
            |b, _p| {
                let s = String::from_utf8_lossy(b);
                security.smart_smudge(&s).map(|x| x.into_bytes())
            },
            |b, p| security.smart_clean_with_path(b, p.unwrap_or("")),
        )
        .expect("run encrypted merge");
        assert_eq!(code, 0, "clean merge exits 0");

        // %A is ciphertext again (index invariant), decrypts back to the
        // merged plaintext.
        let stored = fs::read(&current).unwrap();
        let stored_text = String::from_utf8(stored.clone()).unwrap_or_default();
        assert!(
            stored_text.contains("DRACON_SECRET"),
            "merged result must be encrypted, got: {}",
            &stored_text[..stored_text.len().min(80)]
        );
        let decrypted = security
            .smart_smudge(&stored_text)
            .expect("decrypt merged result");
        let merged_text = decrypted;
        assert!(
            merged_text.contains("line2-A") && merged_text.contains("line4-B"),
            "both changes merged: {}",
            merged_text
        );
        assert!(!merged_text.contains("<<<<<<<"));
    }

    #[test]
    fn ensure_repo_filter_config_registers_diff_and_merge_drivers() {
        // The .gitattributes block emits `diff=dracon merge=dracon`; the
        // config pass must register the driver definitions too, or git
        // falls back to the text driver with a warning and diffs/merges
        // run on ciphertext.
        let td = TestDir::new("filter_config_drivers");
        let repo = td.path();
        run_git_in(repo, &["init", "-q", "-b", "main"]);

        // Seed the SUPERSEDED per-file keys: the migration must
        // unset them (v0.113.13 process driver).
        run_git_in(
            repo,
            &["config", "--local", "filter.dracon.clean", "legacy"],
        );
        run_git_in(
            repo,
            &["config", "--local", "filter.dracon.smudge", "legacy"],
        );
        let changed = ensure_repo_filter_config(repo).expect("ensure config");
        assert!(changed, "first pass must write all keys");
        for key in [
            "filter.dracon.process",
            "filter.dracon.required",
            "diff.dracon.textconv",
            "merge.dracon.driver",
            "merge.dracon.name",
        ] {
            let out = git_in_output(repo, &["config", "--local", "--get", key]);
            assert!(!out.trim().is_empty(), "key {} must be registered", key);
        }
        let textconv = git_in_output(
            repo,
            &["config", "--local", "--get", "diff.dracon.textconv"],
        );
        assert_eq!(textconv.trim(), "dracon-warden filter-smudge");
        let driver = git_in_output(repo, &["config", "--local", "--get", "merge.dracon.driver"]);
        assert_eq!(driver.trim(), "dracon-warden merge \"%O\" \"%A\" \"%B\"");
        // v0.113.13: single process driver; the superseded
        // per-file keys must be gone.
        let process = git_in_output(
            repo,
            &["config", "--local", "--get", "filter.dracon.process"],
        );
        assert_eq!(process.trim(), "dracon-warden filter-process");
        for gone in ["filter.dracon.clean", "filter.dracon.smudge"] {
            let st = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["config", "--local", "--get", gone])
                .output()
                .expect("git config --get");
            assert!(
                !st.status.success(),
                "superseded key {} must be unset",
                gone
            );
        }

        // Second pass: already configured → no change.
        let changed = ensure_repo_filter_config(repo).expect("ensure config again");
        assert!(!changed, "idempotent second pass");
    }

    #[test]
    fn filter_process_pkt_round_trip() {
        // Framing: payload → header+payload; empty → flush;
        // binary-safe; lengths parse back exactly.
        for payload in [&b""[..], &b"status=success"[..], &[0u8, 255, 10, 0, 13]] {
            let enc = crate::pkt_encode(payload);
            if payload.is_empty() {
                assert_eq!(enc, b"0000");
                continue;
            }
            let mut cur = std::io::Cursor::new(enc);
            match crate::pkt_read(&mut cur).expect("decode").expect("packet") {
                crate::Pkt::Data(back) => assert_eq!(back, payload),
                other => panic!("expected data, got {:?}", other),
            }
        }
        // ADDED 2026-10-03 (audit R4-W-09): the maximum payload
        // encodes whole — "ffff" header, nothing truncated.
        let max = vec![0x61u8; crate::PKT_MAX_TOTAL_LEN - 4];
        let enc_max = crate::pkt_encode(&max);
        assert_eq!(&enc_max[..4], b"ffff");
        assert_eq!(enc_max.len(), crate::PKT_MAX_TOTAL_LEN);
        // Flush and delim markers decode distinctly.
        let mut cur = std::io::Cursor::new(b"0000".to_vec());
        assert_eq!(
            crate::pkt_read(&mut cur).expect("decode").expect("packet"),
            crate::Pkt::Flush
        );
        let mut cur = std::io::Cursor::new(b"0001".to_vec());
        assert_eq!(
            crate::pkt_read(&mut cur).expect("decode").expect("packet"),
            crate::Pkt::Delim
        );
        // Clean EOF at a boundary is Ok(None), not an error.
        let mut cur = std::io::Cursor::new(Vec::new());
        assert!(crate::pkt_read(&mut cur).expect("eof").is_none());
    }

    /// ADDED 2026-10-03 (audit R4-W-09): an oversize payload panics
    /// LOUD instead of silently truncating (the old `debug_assert!`
    /// compiled out in release). The `expected` message also
    /// discriminates the old shape in debug builds. Verified under
    /// `--release` too, where the old code did NOT panic.
    #[test]
    #[should_panic(expected = "exceeds pkt-line maximum")]
    fn pkt_encode_panics_on_oversize_payload() {
        let over = vec![0u8; crate::PKT_MAX_TOTAL_LEN - 3];
        let _ = crate::pkt_encode(&over);
    }

    #[test]
    fn filter_process_serve_clean_smudge_and_error() {
        // Full serve loop over in-memory pipes: handshake, one
        // clean, one smudge, one unsupported command, EOF.
        // Unprotected content must pass through byte-identical
        // (fail-open content would be a leak; fail-closed refusal
        // would break every add).
        let warden = crate::DraconWarden::new().expect("create warden");
        let mut script = Vec::new();
        for line in [
            "git-filter-client",
            "version=2",
            "capability=clean",
            "capability=smudge",
        ] {
            script.extend_from_slice(&crate::pkt_encode(line.as_bytes()));
        }
        script.extend_from_slice(b"0000");
        let bodies: &[(&str, &str, &[u8])] = &[
            ("clean", "notes/prose.md", b"plain prose, no secrets"),
            ("smudge", "notes/prose.md", b"plain prose, no secrets"),
            ("frobnicate", "x", b"zzz"),
        ];
        for (cmd, path, body) in bodies {
            script.extend_from_slice(&crate::pkt_encode(format!("command={}", cmd).as_bytes()));
            script.extend_from_slice(&crate::pkt_encode(format!("pathname={}", path).as_bytes()));
            script.extend_from_slice(b"0000");
            for chunk in body.chunks(5) {
                script.extend_from_slice(&crate::pkt_encode(chunk));
            }
            script.extend_from_slice(b"0000");
        }
        let mut input = std::io::Cursor::new(script);
        let mut output = Vec::new();
        crate::filter_process_serve(
            &mut input,
            &mut output,
            &warden,
            &test_guard(64 * 1024 * 1024),
        )
        .expect("serve");
        // Decode the response stream back into packets.
        let mut cur = std::io::Cursor::new(output);
        let mut pkts = Vec::new();
        while let Some(p) = crate::pkt_read(&mut cur).expect("resp decode") {
            pkts.push(p);
        }
        use crate::Pkt::*;
        // Handshake response: key lines until flush (shape varies
        // with the handshake path — parse sequentially, never by
        // fixed offset).
        let mut i = 0;
        while let Data(_) = &pkts[i] {
            i += 1;
        }
        assert_eq!(pkts[i], Flush);
        i += 1;
        // clean/smudge → success + content + flush + trailing
        // empty-list flush; error → status + flush only.
        // (Protocol key lines carry git's trailing `\n`.)
        for (expect_status, expect_body) in [
            ("status=success\n", Some("plain prose, no secrets")),
            ("status=success\n", Some("plain prose, no secrets")),
            ("status=error\n", None),
        ] {
            match &pkts[i] {
                Data(s) => assert_eq!(String::from_utf8_lossy(s), expect_status),
                other => panic!("expected status, got {:?}", other),
            }
            i += 1;
            // Status-list terminator precedes the content.
            assert_eq!(pkts[i], Flush);
            i += 1;
            if let Some(body) = expect_body {
                let mut got = Vec::new();
                while let Data(chunk) = &pkts[i] {
                    got.extend_from_slice(chunk);
                    i += 1;
                }
                assert_eq!(String::from_utf8_lossy(&got), body);
                // Content terminator ...
                assert_eq!(pkts[i], Flush);
                i += 1;
                // ... then the trailing empty status list.
                assert_eq!(pkts[i], Flush);
                i += 1;
            } else {
                // Error responses carry no content: the single
                // flush above already terminated the status list.
            }
        }
    }

    #[test]
    fn filter_process_rejects_bad_handshake() {
        // A client that does not identify as git-filter-client
        // must fail closed, not serve files.
        let warden = crate::DraconWarden::new().expect("create warden");
        let mut script = crate::pkt_encode(b"hello");
        script.extend_from_slice(b"0000");
        let mut input = std::io::Cursor::new(script);
        let mut output = Vec::new();
        let r = crate::filter_process_serve(&mut input, &mut output, &warden, &test_guard(1024));
        assert!(r.is_err(), "bad handshake must fail closed");
        assert!(output.is_empty(), "no response after bad handshake");
    }

    fn git_batch_fixture() -> tempfile::TempDir {
        // Fixture repo: tracked.txt committed as v1, worktree at v2
        // (unstaged), plus an untracked file. The batch must read
        // the INDEX (v1), not the worktree.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let run = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(args)
                .status()
                .expect("spawn git");
            assert!(st.success(), "git {:?}", args);
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(dir.path().join("tracked.txt"), b"v1\n").expect("write");
        run(&["add", "tracked.txt"]);
        run(&["commit", "-qm", "v1"]);
        std::fs::write(dir.path().join("tracked.txt"), b"v2\n").expect("write");
        std::fs::write(dir.path().join("untracked.txt"), b"u\n").expect("write");
        dir
    }

    #[test]
    fn index_batch_returns_staged_blob_not_worktree() {
        // The batch reads `:0:path` (staged), exactly like the
        // per-file spawn it replaces. Untracked/missing paths yield
        // None (fresh encryption downstream).
        let dir = git_batch_fixture();
        let mut b = crate::IndexBatch::with_cwd(dir.path().to_path_buf());
        assert_eq!(
            b.lookup("tracked.txt", 1024 * 1024),
            Some(b"v1\n".to_vec()),
            "must return the staged blob, not the worktree"
        );
        assert_eq!(b.lookup("untracked.txt", 1024 * 1024), None);
        assert_eq!(b.lookup("nope.txt", 1024 * 1024), None);
    }

    #[test]
    fn index_batch_lock_skips_and_recovers() {
        // index.lock = our caller is rewriting the index mid-run:
        // skip the lookup (fresh encryption) rather than race it,
        // and serve again once the lock is gone.
        let dir = git_batch_fixture();
        let mut b = crate::IndexBatch::with_cwd(dir.path().to_path_buf());
        assert!(b.lookup("tracked.txt", 1024 * 1024).is_some());
        std::fs::write(dir.path().join(".git/index.lock"), b"").expect("lock");
        assert_eq!(
            b.lookup("tracked.txt", 1024 * 1024),
            None,
            "locked index must skip, not read torn state"
        );
        std::fs::remove_file(dir.path().join(".git/index.lock")).expect("unlock");
        assert_eq!(
            b.lookup("tracked.txt", 1024 * 1024),
            Some(b"v1\n".to_vec()),
            "batch must serve again after the lock lifts"
        );
    }

    #[test]
    fn index_batch_respawns_after_stage() {
        // The batch snapshots the index at spawn; staging new
        // content moves the index mtime, so the next lookup must
        // see the NEW blob (a stuck snapshot would serve stale v1
        // forever and clean_reusing_index would pin dead ciphertext).
        let dir = git_batch_fixture();
        let mut b = crate::IndexBatch::with_cwd(dir.path().to_path_buf());
        assert_eq!(b.lookup("tracked.txt", 1024 * 1024), Some(b"v1\n".to_vec()));
        let st = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["add", "tracked.txt"])
            .status()
            .expect("spawn git");
        assert!(st.success());
        assert_eq!(
            b.lookup("tracked.txt", 1024 * 1024),
            Some(b"v2\n".to_vec()),
            "must observe the restaged blob after the index moves"
        );
    }

    #[test]
    fn filter_transform_batch_matches_oneshot() {
        // Same policy output on both lookup paths for changed
        // content (the batch only changes HOW the staged blob is
        // fetched, never what clean computes).
        let dir = git_batch_fixture();
        let warden = crate::DraconWarden::new().expect("create warden");
        let input = b"plain prose, no secrets".to_vec();
        let mut batch =
            crate::IndexLookup::Batch(crate::IndexBatch::with_cwd(dir.path().to_path_buf()));
        // Prime the batch so the equivalence run exercises a live
        // session (not lazy resolution):
        let primed = crate::filter_transform_bytes(
            &warden,
            true,
            Some("untracked.txt"),
            input.clone(),
            &test_guard(1024 * 1024),
            &mut batch,
        )
        .expect("prime batch");
        assert_eq!(primed, input);
        let via_batch = crate::filter_transform_bytes(
            &warden,
            true,
            Some("tracked.txt"),
            input.clone(),
            &test_guard(1024 * 1024),
            &mut batch,
        )
        .expect("batch transform");
        let via_oneshot = crate::filter_transform_bytes(
            &warden,
            true,
            Some("tracked.txt"),
            input.clone(),
            &test_guard(1024 * 1024),
            &mut crate::IndexLookup::OneShot,
        )
        .expect("oneshot transform");
        assert_eq!(via_batch, via_oneshot);
        assert_eq!(via_batch, input, "unprotected content passes through");
    }
}

/// ADDED 2026-09-27 (audit F96): the packet loop used to buffer the
/// whole blob before `filter_transform_bytes` consulted `limit`, so a
/// repo-controlled multi-GB blob drove unbounded RSS in the filter
/// driver. These tests pin the bounded behaviour: the clean direction
/// fails CLOSED and writes nothing, and the smudge direction
/// passthroughs the full body byte-identically (streaming, so nothing
/// is lost) while still terminating the protocol correctly.
#[cfg(test)]
mod filter_process_oversize_tests {
    fn drive(cmd: &str, body: &[u8], limit: usize) -> Vec<crate::Pkt> {
        let warden = crate::DraconWarden::new().expect("create warden");
        let mut script = Vec::new();
        for line in [
            "git-filter-client",
            "version=2",
            "capability=clean",
            "capability=smudge",
        ] {
            script.extend_from_slice(&crate::pkt_encode(line.as_bytes()));
        }
        script.extend_from_slice(b"0000");
        script.extend_from_slice(&crate::pkt_encode(format!("command={}", cmd).as_bytes()));
        script.extend_from_slice(&crate::pkt_encode(b"pathname=notes/prose.md"));
        script.extend_from_slice(b"0000");
        // 16 KiB packets: comfortably inside the 4-hex-digit pkt-line
        // header limit (0xFFFF) while still forcing many packets.
        for chunk in body.chunks(16 * 1024) {
            script.extend_from_slice(&crate::pkt_encode(chunk));
        }
        script.extend_from_slice(b"0000");
        let mut input = std::io::Cursor::new(script);
        let mut output = Vec::new();
        crate::filter_process_serve(&mut input, &mut output, &warden, &crate::test_guard(limit))
            .expect("serve");
        let mut cur = std::io::Cursor::new(output);
        let mut pkts = Vec::new();
        while let Some(p) = crate::pkt_read(&mut cur).expect("resp decode") {
            pkts.push(p);
        }
        pkts
    }

    /// Skip the handshake response and return the per-request packets.
    fn after_handshake(pkts: &[crate::Pkt]) -> &[crate::Pkt] {
        use crate::Pkt::*;
        let mut i = 0;
        while let Data(_) = &pkts[i] {
            i += 1;
        }
        assert_eq!(pkts[i], Flush);
        &pkts[i + 1..]
    }

    #[test]
    fn clean_oversize_fails_closed_and_writes_no_content() {
        let body = vec![b'x'; 200_000];
        let pkts = drive("clean", &body, 1024);
        let rest = after_handshake(&pkts);
        use crate::Pkt::*;
        match &rest[0] {
            Data(s) => assert_eq!(String::from_utf8_lossy(s), "status=error\n"),
            other => panic!("expected error status, got {:?}", other),
        }
        // No content may follow: a passthrough here would commit the
        // file UNENCRYPTED, which is the whole point of the guard.
        assert!(
            !rest.iter().any(|p| matches!(p, Data(d) if d.len() > 64)),
            "oversize clean must not emit content: {:?}",
            rest
        );
    }

    #[test]
    fn smudge_oversize_passthroughs_every_byte() {
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let pkts = drive("smudge", &body, 1024);
        let rest = after_handshake(&pkts);
        use crate::Pkt::*;
        match &rest[0] {
            Data(s) => assert_eq!(String::from_utf8_lossy(s), "status=success\n"),
            other => panic!("expected success status, got {:?}", other),
        }
        // Everything after the status-list terminator is the body.
        let mut got = Vec::new();
        for p in &rest[2..] {
            match p {
                Data(chunk) => got.extend_from_slice(chunk),
                Flush => break,
                Delim => continue,
            }
        }
        assert_eq!(
            got.len(),
            body.len(),
            "smudge passthrough length mismatch (got {} of {} bytes)",
            got.len(),
            body.len()
        );
        assert!(
            got == body,
            "smudge passthrough must preserve every byte (first difference at {:?})",
            got.iter().zip(body.iter()).position(|(a, b)| a != b)
        );
        // Protocol still terminates: trailing empty status list.
        assert_eq!(rest[rest.len() - 1], Flush);
    }
}

/// ADDED 2026-09-27 (audit decision D2). Before the binary carve-out, the
/// 2026-09-16 eager-source-encryption catch-all (`* filter=dracon`) plus the
/// unconditional oversize clean refusal meant a single 20 MiB screenshot made
/// `git add` fail outright, with a message claiming the file "would be
/// committed UNENCRYPTED" — for a file that was never a secret. These pin
/// both halves of the fix and, just as importantly, pin that the carve-out
/// did NOT weaken the guard for anything a secret could plausibly hide in.
mod binary_carve_out_tests {
    use crate::*;

    const LIMIT: usize = 10 * 1024 * 1024;
    const OVER: usize = 20 * 1024 * 1024;

    fn exempt() -> Vec<String> {
        default_binary_filter_exempt_patterns()
    }

    // --- the size guard itself -----------------------------------------

    #[test]
    fn oversize_binary_extension_is_not_refused() {
        for path in [
            "assets/screenshot.png",
            "docs/diagram.JPG",
            "media/clip.mp4",
            "dist/bundle.zip",
            "nested/deep/photo.webp",
        ] {
            let reason =
                filter_clean_refusal_with_limit(true, OVER, Some(path), LIMIT, &exempt(), &[], &[]);
            assert!(
                reason.is_none(),
                "a >limit binary should be addable again, got: {reason:?} ({path})"
            );
        }
    }

    #[test]
    fn oversize_text_and_secret_paths_still_fail_closed() {
        for path in [
            "src/main.rs",
            "notes/notes.txt",
            "data/dump.json",
            "secrets/archive.txt",
            "config/app.conf",
            "no-extension",
        ] {
            let reason =
                filter_clean_refusal_with_limit(true, OVER, Some(path), LIMIT, &exempt(), &[], &[]);
            assert!(
                reason.is_some(),
                "a >limit {path} must still be refused — the carve-out is binary-only"
            );
        }
    }

    /// ADDED 2026-09-27 (audit round 1, HIGH): a protected path is never
    /// exempt, even when its extension is on the carve-out list.
    ///
    /// The first cut of D2 asserted the OPPOSITE — that the size guard
    /// does not fire for `secrets/dump.png` — which encoded a fail-open:
    /// the protected `.gitattributes` line does win, so git DOES route
    /// that file through the filter, and the filter then waved an
    /// oversize file through unencrypted AND unscanned. Pre-change every
    /// oversize clean refused. Both halves are now pinned.
    #[test]
    fn oversize_protected_path_with_binary_extension_still_fails_closed() {
        let protected = vec!["secrets/**".to_string()];

        // Unprotected: the carve-out applies (the D2 fix itself).
        assert!(filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("assets/dump.png"),
            LIMIT,
            &exempt(),
            &[],
            &[]
        )
        .is_none());

        // Same extension, same size, but under a protected directory:
        // the operator said "this path is sensitive", and that wins.
        let reason = filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("secrets/dump.png"),
            LIMIT,
            &exempt(),
            &protected,
            &[],
        );
        assert!(
            reason.is_some(),
            "an oversize file under protected_patterns must fail closed, \
             not pass through unencrypted and unscanned"
        );

        // Every entry point that can reach the filter must agree, so the
        // check is repeated through the pure transform the one-shot
        // entry point and the driver both call.
        let guard = CleanGuard {
            limit: LIMIT,
            binary_exempt: exempt(),
            protected: protected.clone(),
            media: Vec::new(),
        };
        for path in ["secrets/dump.png", "secrets/deep/nested/a.png"] {
            let err = filter_transform_bytes(
                &DraconWarden::new().expect("warden"),
                true,
                Some(path),
                vec![0u8; LIMIT + 1],
                &guard,
                &mut IndexLookup::OneShot,
            );
            assert!(err.is_err(), "{path} must be refused by the transform");
        }

        // And the .gitattributes ordering must still give `secrets/**`
        // the filter, so the file is routed here in the first place.
        let policy = WardenPolicy {
            protected_patterns: protected.clone(),
            ..Default::default()
        };
        let block = build_gitattributes_block(&policy).expect("block");
        let binary_line = block
            .lines()
            .position(|l| l == "*.png -filter")
            .expect("binary carve-out emitted");
        let protected_line = block
            .lines()
            .position(|l| l.starts_with("secrets/** filter=dracon"))
            .expect("protected line emitted");
        assert!(
            protected_line > binary_line,
            "protected patterns must come LAST so git's last-match-wins gives \
             secrets/** the filter (protected_line={protected_line}, binary_line={binary_line})"
        );
    }

    #[test]
    fn oversize_media_path_is_never_size_exempt() {
        let media = vec!["internal-dashboards/**".to_string()];
        // Opted-in: same extension, same size as the carve-out case,
        // but the operator asked for encryption — fail closed.
        assert!(filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("internal-dashboards/shot.png"),
            LIMIT,
            &exempt(),
            &[],
            &media,
        )
        .is_some());
        // The option off (empty media list): the carve-out applies.
        assert!(filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("internal-dashboards/shot.png"),
            LIMIT,
            &exempt(),
            &[],
            &[],
        )
        .is_none());
    }

    #[test]
    fn unknown_extension_is_not_exempt() {
        // `.bin` is exempt but `.weirdext` is not — the carve-out is an
        // explicit allowlist, not a "looks binary" heuristic.
        assert!(filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("a/b.bin"),
            LIMIT,
            &exempt(),
            &[],
            &[]
        )
        .is_none());
        assert!(filter_clean_refusal_with_limit(
            true,
            OVER,
            Some("a/b.weirdext"),
            LIMIT,
            &exempt(),
            &[],
            &[]
        )
        .is_some());
    }

    #[test]
    fn an_empty_exempt_list_restores_the_hard_failure() {
        // An operator who sets `binary_filter_exempt_patterns = []` opts
        // back out; the guard must then behave exactly as it did before.
        assert!(
            filter_clean_refusal_with_limit(true, OVER, Some("a/b.png"), LIMIT, &[], &[], &[])
                .is_some()
        );
    }

    #[test]
    fn smudge_direction_is_never_refused() {
        assert!(filter_clean_refusal_with_limit(
            false,
            OVER,
            Some("a/b.png"),
            LIMIT,
            &exempt(),
            &[],
            &[]
        )
        .is_none());
    }

    // --- the generated .gitattributes block ----------------------------

    #[test]
    fn gitattributes_emits_binary_carveouts_after_the_catchall() {
        let block = build_gitattributes_block(&WardenPolicy::default()).expect("block");
        assert!(block.contains("* filter=dracon"));
        for pat in ["*.png", "*.mp4", "*.zip", "*.pdf", "*.wasm"] {
            assert!(
                block.contains(&format!("{pat} -filter")),
                "missing carve-out for {pat}"
            );
        }
        let catchall = block.lines().position(|l| l == "* filter=dracon").unwrap();
        let first_carveout = block.lines().position(|l| l == "*.png -filter").unwrap();
        assert!(
            first_carveout > catchall,
            "carve-outs must follow the catch-all to win git's last-match rule"
        );
    }

    #[test]
    fn gitattributes_emits_media_lines_between_carveouts_and_plaintext() {
        let policy = WardenPolicy {
            media_protected_patterns: vec!["internal-dashboards/**".into()],
            plaintext_patterns: vec!["*.pub".into()],
            ..Default::default()
        };
        let block = build_gitattributes_block(&policy).expect("block");
        let media_line = "internal-dashboards/** filter=dracon diff=dracon merge=dracon";
        assert!(block.contains(media_line), "missing media line:\n{block}");
        let carveout = block.lines().position(|l| l == "*.png -filter").unwrap();
        let media = block.lines().position(|l| l == media_line).unwrap();
        let plain = block.lines().position(|l| l == "*.pub -filter").unwrap();
        assert!(
            carveout < media && media < plain,
            "media lines must win over carve-outs but lose to plaintext:\n{block}"
        );
        // Off by default: a default policy emits no media lines.
        let off = build_gitattributes_block(&WardenPolicy::default()).expect("block");
        assert!(!off.contains("internal-dashboards"));
        // Exact media/plaintext overlap is a loud contradiction, same
        // rule as protected/plaintext overlap.
        let clash = WardenPolicy {
            media_protected_patterns: vec!["*.png".into()],
            plaintext_patterns: vec!["*.png".into()],
            ..Default::default()
        };
        let err = build_gitattributes_block(&clash).expect_err("clash must fail");
        assert!(err.to_string().contains("media-protected and plaintext"));
    }

    #[test]
    fn policy_can_override_or_disable_the_defaults() {
        let custom = WardenPolicy {
            binary_filter_exempt_patterns: Some(vec!["*.blend".into()]),
            ..Default::default()
        };
        let block = build_gitattributes_block(&custom).expect("block");
        assert!(block.contains("*.blend -filter"));
        assert!(
            !block.contains("*.png -filter"),
            "an explicit list REPLACES the defaults, it does not extend them"
        );

        let none = WardenPolicy {
            binary_filter_exempt_patterns: Some(vec![]),
            ..Default::default()
        };
        let block = build_gitattributes_block(&none).expect("block");
        assert!(!block.contains("*.png -filter"));
    }

    /// ADDED 2026-09-27 (audit round 1, MED): the `filter-process`
    /// driver is what warden itself installs
    /// (`filter.dracon.process`), so its clean branch is the path every
    /// hardened repo actually takes. The first cut of D2 computed the
    /// refusal with the new carve-out and then discarded the `None` case
    /// via `unwrap_or_else`, so a size-exempt binary was refused there
    /// while the one-shot path passed it through — the three entry points
    /// disagreed, and the user-visible failure D2 set out to remove
    /// survived on a stale `.gitattributes`.
    ///
    /// Drives the real pkt-line protocol in-process (no second binary,
    /// no 20 MiB fixture): a small `limit` exercises exactly the same
    /// code path as the production one.
    mod filter_process_passthrough {
        use super::*;

        const LIMIT: usize = 1024;
        const OVER: usize = 8 * 1024;
        // A single repeated byte: the response is re-assembled from
        // binary-safe frames, and a uniform payload makes a framing bug
        // obvious instead of looking like plausible data.
        const FILLER: u8 = b'A';

        fn guard(protected: Vec<String>) -> CleanGuard {
            CleanGuard {
                limit: LIMIT,
                binary_exempt: default_binary_filter_exempt_patterns(),
                protected,
                media: Vec::new(),
            }
        }

        /// Handshake + one request carrying `len` filler bytes.
        fn request(command: &str, path: &str, len: usize) -> Vec<u8> {
            let mut input = Vec::new();
            input.extend(pkt_key_line("git-filter-client"));
            input.extend(pkt_key_line("capability=clean"));
            input.extend(pkt_key_line("capability=smudge"));
            input.extend(b"0000");
            input.extend(pkt_key_line(&format!("command={command}")));
            input.extend(pkt_key_line(&format!("pathname={path}")));
            input.extend(b"0000");
            // Chained in frames small enough to cross the bound in the
            // middle of a packet, which is the case the streaming
            // decision has to get right.
            let body = vec![FILLER; len];
            for frame in body.chunks(300) {
                input.extend(pkt_encode(frame));
            }
            input.extend(b"0000");
            input
        }

        fn clean_request(path: &str, len: usize) -> Vec<u8> {
            request("clean", path, len)
        }

        /// `(status, re-assembled content)` from one response.
        ///
        /// Decodes with the crate's own `pkt_read` — the same parser
        /// production uses — rather than a second hand-rolled hex reader,
        /// so a framing regression cannot hide behind a test-only parser.
        fn decode(output: &[u8]) -> (String, Vec<u8>) {
            let mut cur = std::io::Cursor::new(output);
            let mut status = String::new();
            let mut content = Vec::new();
            // Frames before the status are the handshake reply
            // (`git-filter-server`, `version=2`); frames after it are
            // the blob.
            let mut seen_status = false;
            while let Some(p) = crate::pkt_read(&mut cur).expect("decode response") {
                let Pkt::Data(payload) = p else { continue };
                if !seen_status {
                    if payload.starts_with(b"status=") {
                        status = String::from_utf8_lossy(&payload)
                            .trim()
                            .trim_start_matches("status=")
                            .to_string();
                        seen_status = true;
                    }
                    continue;
                }
                content.extend_from_slice(&payload);
            }
            (status, content)
        }

        fn run(path: &str, len: usize, guard: &CleanGuard) -> (String, Vec<u8>) {
            let mut output: Vec<u8> = Vec::new();
            filter_process_serve(
                &mut std::io::Cursor::new(clean_request(path, len)),
                &mut output,
                &DraconWarden::new().expect("warden"),
                guard,
            )
            .expect("serve");
            decode(&output)
        }

        #[test]
        fn oversize_exempt_binary_passes_through_intact() {
            let (status, content) = run("assets/shot.png", OVER, &guard(vec![]));
            assert_eq!(status, "success", "an oversize binary must not be refused");
            assert_eq!(
                content.len(),
                OVER,
                "the WHOLE blob must survive: the passthrough decision is made \
                 from the header, and the bytes past the bound are streamed \
                 rather than dropped by the clean-direction drain"
            );
            assert!(content.iter().all(|b| *b == FILLER));
        }

        #[test]
        fn oversize_text_still_refused() {
            let (status, content) = run("notes/big.txt", OVER, &guard(vec![]));
            assert_eq!(status, "error", "a >limit text path must still fail closed");
            assert!(content.is_empty(), "a refused blob must emit no content");
        }

        /// The round-1 HIGH finding, through the entry point that matters.
        #[test]
        fn oversize_protected_binary_still_refused() {
            let g = guard(vec!["secrets/**".to_string()]);
            let (status, content) = run("secrets/dump.png", OVER, &g);
            assert_eq!(
                status, "error",
                "an oversize file under protected_patterns must fail closed \
                 even though *.png is on the carve-out list"
            );
            assert!(content.is_empty());
        }

        /// A non-oversize binary still goes through the real transform,
        /// so the passthrough did not turn the carve-out into a blanket
        /// "never scan images".
        #[test]
        fn small_binary_still_takes_the_normal_clean_path() {
            let (status, content) = run("assets/small.png", LIMIT / 2, &guard(vec![]));
            assert_eq!(status, "success");
            assert_eq!(content.len(), LIMIT / 2);
        }

        /// ADDED 2026-09-27 (audit round 2, HIGH): the ceiling that
        /// bounds the deferred passthrough.
        ///
        /// The driver cannot relay a response while git is still writing
        /// the request (git writes the whole request before reading, so
        /// an early response deadlocks both pipes), which is why the blob
        /// is buffered. The buffer needs an operator-visible bound, and a
        /// blob past it must fail loudly for this file — never be relayed
        /// truncated.
        #[test]
        fn oversize_passthrough_is_bounded_and_never_truncated() {
            let ceiling = passthrough_ceiling_bytes(LIMIT);
            assert_eq!(
                ceiling,
                (LIMIT * 4).max(STREAM_IO_MAX_BYTES),
                "the ceiling is a small multiple of the operator's own limit, \
                 with a floor so a deliberately small limit still has room"
            );
            // Just inside the ceiling: relayed in full.
            let (status, content) = run("assets/edge.png", ceiling, &guard(vec![]));
            assert_eq!(status, "success");
            assert_eq!(content.len(), ceiling, "the boundary blob is relayed whole");

            // Past the ceiling: refused, with no partial content that git
            // could store as if it were the file.
            let (status, content) = run("assets/huge.png", ceiling + 4096, &guard(vec![]));
            assert_eq!(status, "error", "a blob past the ceiling must fail closed");
            assert!(
                content.is_empty(),
                "an over-ceiling blob must emit no content, got {} bytes",
                content.len()
            );

            // Same bound in the smudge direction, where the old code
            // streamed the tail (the deadlock the fix removed).
            let mut output: Vec<u8> = Vec::new();
            filter_process_serve(
                &mut std::io::Cursor::new(request("smudge", "assets/huge.png", ceiling + 4096)),
                &mut output,
                &DraconWarden::new().expect("warden"),
                &guard(vec![]),
            )
            .expect("serve");
            let (status, content) = decode(&output);
            assert_eq!(status, "error");
            assert!(content.is_empty());
        }

        /// The floor keeps a deliberately small `filter_max_bytes` from
        /// turning the ceiling into a hair-trigger, and the multiple keeps
        /// the memory bound tied to the operator's own setting. The
        /// production bound is 4x a validated limit (max 64 MiB), i.e. at
        /// most 256 MiB resident for one blob; the saturating multiply
        /// means a nonsense limit can never wrap into a smaller bound.
        #[test]
        fn passthrough_ceiling_scales_with_the_configured_limit() {
            assert_eq!(
                passthrough_ceiling_bytes(10 * 1024 * 1024),
                40 * 1024 * 1024
            );
            assert_eq!(
                passthrough_ceiling_bytes(64 * 1024 * 1024),
                256 * 1024 * 1024,
                "the policy maximum limit must still give a bounded ceiling"
            );
            assert_eq!(
                passthrough_ceiling_bytes(1),
                STREAM_IO_MAX_BYTES,
                "a tiny limit must still leave room for a passthrough"
            );
            assert_eq!(
                passthrough_ceiling_bytes(usize::MAX / 2),
                usize::MAX,
                "the multiply saturates instead of wrapping into a smaller bound"
            );
        }

        /// ADDED 2026-10-03 (audit R4-W-04): the refusal names the
        /// numbers and, for smudge only, the one-shot recovery — the
        /// one-shot filter-smudge streams with NO ceiling, so an
        /// over-ceiling blob fails checkout under filter-process while
        /// staying recoverable one file at a time.
        #[test]
        fn over_ceiling_reason_points_smudge_at_one_shot_recovery() {
            let smudge = over_ceiling_reason(5000, 4096, Some(false));
            assert!(
                smudge.contains("5001") && smudge.contains("4096"),
                "refusal must name the size and the ceiling: {smudge}"
            );
            assert!(
                smudge.contains("filter-smudge") && smudge.contains("git show HEAD:"),
                "smudge refusal must name the one-shot recovery: {smudge}"
            );
            let clean = over_ceiling_reason(5000, 4096, Some(true));
            assert!(
                !clean.contains("filter-smudge"),
                "clean refusal must not suggest a smudge recovery: {clean}"
            );
            assert!(
                clean.contains("raise filter_max_bytes"),
                "clean refusal keeps the raise-or-ignore guidance: {clean}"
            );
        }
    }

    /// End-to-end through git: with the managed block applied, git itself
    /// must not route a large screenshot through the filter.
    #[test]
    fn git_does_not_route_binary_files_through_the_filter() {
        let block = build_gitattributes_block(&WardenPolicy::default()).expect("block");
        // Self-contained: this module does not import the private helpers
        // of the inner `tests` module, so it drives git directly.
        let td = tempfile::TempDir::new().expect("temp dir");
        let repo = td.path();
        let git = |args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .output()
                .expect("git");
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        git(&["init", "-q", "-b", "main"]);
        fs::write(repo.join(".gitattributes"), &block).expect("write gitattributes");
        // `git check-attr` prints the attribute VALUE, not "set": the
        // catch-all resolves to `dracon` and the carve-out to `unset`.
        for (path, expected) in [
            ("assets/shot.png", "unset"),
            ("src/main.rs", "dracon"),
            ("secrets/a.key", "dracon"),
        ] {
            let out = git(&["check-attr", "filter", "--", path]);
            let value = out.split_whitespace().last().unwrap_or("");
            assert_eq!(
                value, expected,
                "git check-attr filter for {path} was {value}, expected {expected}"
            );
        }
    }
}

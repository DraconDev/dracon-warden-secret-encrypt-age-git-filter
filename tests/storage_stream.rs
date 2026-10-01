//! End-to-end streaming adapter checks with isolated identities and repositories.
use age::x25519;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
    identity: x25519::Identity,
}

fn private_file(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap()
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let repo = temp.path().join("repo");
    std::fs::create_dir_all(home.join(".dracon/keys")).unwrap();
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let identity = x25519::Identity::generate();
    private_file(&home.join(".dracon/keys/identity.age"))
        .write_all(identity.to_string().expose_secret().as_bytes())
        .unwrap();
    Fixture {
        _temp: temp,
        home,
        repo,
        identity,
    }
}

fn transform(fixture: &Fixture, encrypt: bool, input: &Path, output: &Path, budget: u64) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dracon-warden"))
        .args([
            if encrypt {
                "storage-encrypt"
            } else {
                "storage-decrypt"
            },
            "--repo",
        ])
        .arg(&fixture.repo)
        .args(["--max-bytes", &budget.to_string()])
        .env("HOME", &fixture.home)
        .env_remove("ARCANE_MACHINE_KEY")
        .stdin(File::open(input).unwrap())
        .stdout(Stdio::from(private_file(output)))
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn file_hash(path: &Path) -> String {
    let mut input = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    format!("{:x}", hash.finalize())
}

#[test]
fn warden_streams_more_than_git_filter_limit_and_restores_exact_bytes() {
    let fixture = fixture();
    let source = fixture.repo.join("large.bin");
    let mut file = private_file(&source);
    let chunk = [0x39u8; 64 * 1024];
    for _ in 0..(101 * 1024 / 64) {
        file.write_all(&chunk).unwrap();
    }
    drop(file);
    let bytes = 101 * 1024 * 1024;
    let encrypted = fixture.repo.join("payload.age");
    assert!(transform(&fixture, true, &source, &encrypted, bytes)
        .status
        .success());
    let mut header = [0u8; 22];
    File::open(&encrypted)
        .unwrap()
        .read_exact(&mut header)
        .unwrap();
    assert_eq!(&header, b"age-encryption.org/v1\n");
    let restored = fixture.repo.join("restored.bin");
    assert!(transform(&fixture, false, &encrypted, &restored, bytes)
        .status
        .success());
    assert_eq!(file_hash(&source), file_hash(&restored));
    assert_eq!(std::fs::metadata(&restored).unwrap().len(), bytes);
    assert!(!fixture.repo.join(".gitattributes").exists());
    assert!(!fixture.repo.join(".git/arcane").exists());
}

#[test]
fn forged_repo_recipient_wrong_identity_corruption_and_budget_fail_closed() {
    let owner = fixture();
    let attacker = fixture();
    std::fs::create_dir_all(owner.repo.join(".dracon/data/keys")).unwrap();
    std::fs::write(
        owner.repo.join(".dracon/data/keys/owner_attacker.pub"),
        attacker.identity.to_public().to_string(),
    )
    .unwrap();
    let source = owner.repo.join("source.bin");
    std::fs::write(&source, b"private bytes for authorized owner only").unwrap();
    let cipher = owner.repo.join("cipher.age");
    assert!(transform(&owner, true, &source, &cipher, 100)
        .status
        .success());
    let stolen = attacker.repo.join("stolen.bin");
    assert!(!transform(&attacker, false, &cipher, &stolen, 100)
        .status
        .success());
    let too_small = owner.repo.join("too-small.age");
    assert!(!transform(&owner, true, &source, &too_small, 10)
        .status
        .success());
    let too_small_restore = owner.repo.join("too-small.bin");
    assert!(!transform(&owner, false, &cipher, &too_small_restore, 10)
        .status
        .success());
    let mut bytes = std::fs::read(&cipher).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let corrupt = owner.repo.join("corrupt.age");
    std::fs::write(&corrupt, bytes).unwrap();
    let bad_restore = owner.repo.join("bad-restore.bin");
    assert!(!transform(&owner, false, &corrupt, &bad_restore, 100)
        .status
        .success());
    assert_eq!(
        std::fs::read(&source).unwrap(),
        b"private bytes for authorized owner only"
    );
}

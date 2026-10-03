//! Tests for the plaintext-sibling escape hatch.
//!
//! A file with a `<path>.plaintext` sibling is treated as intentionally
//! plaintext: the clean filter returns it unchanged, and the smudge filter
//! never sees it. See `docs/design/warden-plaintext-sibling.md`.

use dracon_security::modules::filter::{is_hatched, is_hatched_in_repo};
use dracon_security::WardenSecurity;
use std::fs;
use tempfile::TempDir;

#[test]
fn is_hatched_returns_false_for_empty_path() {
    assert!(!is_hatched(""));
}

#[test]
fn is_hatched_returns_false_when_sibling_missing() {
    // Rooted form: an existing file under the root with no sibling.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config").join("secrets.env");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "secret=hunter2\n").unwrap();
    assert!(!is_hatched_in_repo(dir.path(), path.to_str().unwrap()));
    assert!(!is_hatched_in_repo(
        dir.path(),
        "config/secrets.env"
    ));
}

/// 2026-10-03 (audit R4-W-08): the unrooted helper resolves
/// CWD-relative, so absolute paths and `..` escapes fail closed
/// (false = encrypt) — a foreign directory must never hatch a file.
#[test]
fn is_hatched_rejects_absolute_and_dotdot() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secrets.env");
    let sibling = dir.path().join("secrets.env.plaintext");
    fs::write(&path, "secret=hunter2\n").unwrap();
    fs::write(&sibling, "").unwrap();
    // The sibling EXISTS — rejection is by shape, not absence.
    assert!(
        !is_hatched(path.to_str().unwrap()),
        "absolute paths must fail closed even with a sibling present"
    );
    assert!(!is_hatched("../escape.env"));
    assert!(!is_hatched("a/../../escape.env"));
    assert!(!is_hatched("/absent.env"));
}

#[test]
fn is_hatched_in_repo_accepts_contained_paths() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let path = root.join("sub").join("secrets.env");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "secret=hunter2\n").unwrap();
    fs::write(root.join("sub").join("secrets.env.plaintext"), "").unwrap();
    // Absolute-under-root and relative-under-root both hatch.
    assert!(is_hatched_in_repo(root, path.to_str().unwrap()));
    assert!(is_hatched_in_repo(root, "sub/secrets.env"));
    // `./` normalization stays contained.
    assert!(is_hatched_in_repo(root, "sub/./secrets.env"));
}

/// 2026-10-03 (audit R4-W-08): `..` escaping the root fails closed
/// even when the escaped sibling EXISTS on disk.
#[test]
fn is_hatched_in_repo_rejects_escape_even_when_sibling_exists() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside.env.plaintext");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(&outside, "").unwrap();
    assert!(
        !is_hatched_in_repo(&root, "sub/../../outside.env"),
        "a .. escape must fail closed despite the existing sibling"
    );
    assert!(
        !is_hatched_in_repo(&root, outside.to_str().unwrap()),
        "an absolute path outside the root must fail closed"
    );
    assert!(!is_hatched_in_repo(&root, ""));
    assert!(!is_hatched_in_repo(
        std::path::Path::new("relative-root"),
        "sub/x.env"
    ));
}

/// Fixture dir under `target/` (gitignored, auto-removed): lets tests
/// exercise CWD-relative hatch paths exactly as the filter protocol
/// passes them — without chdir races (process-global CWD under
/// parallel tests) and without polluting the repo. Returns the TempDir
/// guard plus the CWD-relative dir prefix. Cargo runs test binaries
/// with CWD at the package root, so `target/` always exists there.
fn target_fixture_dir() -> (TempDir, String) {
    fs::create_dir_all("target").unwrap();
    let dir = TempDir::new_in("target").unwrap();
    // tempfile canonicalizes to absolute; strip the CWD back off so
    // the paths exercise the CWD-relative production shape.
    let rel = dir
        .path()
        .strip_prefix(std::env::current_dir().unwrap())
        .expect("target fixture must sit under the test CWD")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !std::path::Path::new(&rel).is_absolute(),
        "fixture must be CWD-relative"
    );
    (dir, rel)
}

fn age_secret() -> &'static str {
    concat!(
        "AGE",
        "-SECRET",
        "-KEY-",
        "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
    )
}

#[test]
fn clean_skips_encryption_when_plaintext_sibling_exists() {
    // CWD-relative path, the production filter-protocol shape: the
    // hatch must cause the content to be returned VERBATIM.
    let (_dir, prefix) = target_fixture_dir();
    let path = format!("{prefix}/example.env");
    let sibling = format!("{prefix}/example.env.plaintext");
    let secret = age_secret();

    fs::write(&path, secret).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), &path)
        .expect("clean should succeed");

    assert_eq!(cleaned, secret.as_bytes());
}

/// 2026-10-03 (audit R4-W-08): an ABSOLUTE hatched path fails closed
/// (encrypts) — the sibling may live in a foreign directory, so the
/// unrooted helper refuses the shape instead of checking it.
#[test]
fn clean_encrypts_absolute_hatched_path_fail_closed() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.env");
    let sibling = dir.path().join("example.env.plaintext");
    let secret = age_secret();

    fs::write(&path, secret).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), path.to_str().unwrap())
        .expect("clean should succeed");

    let cleaned_str = String::from_utf8_lossy(&cleaned);
    assert!(
        !cleaned_str.contains(secret),
        "absolute hatched path must fail closed (encrypt), got: {cleaned_str}"
    );
}

#[test]
fn clean_encrypts_normally_without_plaintext_sibling() {
    // Negative test: when the sibling does not exist, the filter still
    // encrypts the file (this proves the hatch is a real opt-in, not a no-op).
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secrets.env");
    let secret = concat!(
        "AGE",
        "-SECRET",
        "-KEY-",
        "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
    );

    fs::write(&path, secret).unwrap();
    // No `.plaintext` sibling

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), path.to_str().unwrap())
        .expect("clean should succeed");

    // Without the hatch, the secret content must NOT appear verbatim.
    let cleaned_str = String::from_utf8_lossy(&cleaned);
    assert!(
        !cleaned_str.contains(secret),
        "secret leaked through clean filter without hatch: {}",
        cleaned_str
    );
}

#[test]
fn clean_with_plaintext_sibling_does_not_add_env_version_header() {
    // Even for .env files (which normally get a Dracon Warden version
    // header), the hatch must cause pass-through with NO modification.
    // CWD-relative (R4-W-08): absolute paths fail closed.
    let (_dir, prefix) = target_fixture_dir();
    let path = format!("{prefix}/.env");
    let sibling = format!("{prefix}/.env.plaintext");
    let secret = age_secret();

    fs::write(&path, secret).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), &path)
        .expect("clean should succeed");

    assert_eq!(cleaned, secret.as_bytes());
    let s = String::from_utf8_lossy(&cleaned);
    assert!(
        !s.contains("Dracon Warden"),
        "hatch should suppress version header"
    );
}

#[test]
fn clean_with_plaintext_sibling_preserves_binary_content() {
    // CWD-relative (R4-W-08): absolute paths fail closed.
    let (_dir, prefix) = target_fixture_dir();
    let path = format!("{prefix}/blob.bin");
    let sibling = format!("{prefix}/blob.bin.plaintext");
    // Real binary content (PNG header)
    let bytes: Vec<u8> = vec![
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    ];

    fs::write(&path, &bytes).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(&bytes, &path)
        .expect("clean should succeed");

    assert_eq!(cleaned, bytes);
}

#[test]
fn clean_with_empty_sibling_path_is_a_noop() {
    // Defensive: empty path_str must NOT match `<empty>.plaintext` at CWD
    // and accidentally skip encryption. The hatch is opt-in: empty path = no
    // hatch decision.
    let security = WardenSecurity::new(None).unwrap();
    let secret = concat!(
        "AGE",
        "-SECRET",
        "-KEY-",
        "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
    );
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), "")
        .expect("clean should succeed");
    // The cleaned output should NOT contain the plaintext secret.
    let s = String::from_utf8_lossy(&cleaned);
    assert!(!s.contains(secret), "empty path leaked plaintext: {}", s);
}

//! Tests for the plaintext-sibling escape hatch.
//!
//! A file with a `<path>.plaintext` sibling is treated as intentionally
//! plaintext: the clean filter returns it unchanged, and the smudge filter
//! never sees it. See `docs/design/warden-plaintext-sibling.md`.

use dracon_security::modules::filter::is_hatched;
use dracon_security::WardenSecurity;
use std::fs;
use tempfile::TempDir;

#[test]
fn is_hatched_returns_false_for_empty_path() {
    assert!(!is_hatched(""));
}

#[test]
fn is_hatched_returns_false_when_sibling_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config").join("secrets.env");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "secret=hunter2\n").unwrap();
    let rel = path.to_str().unwrap();
    assert!(!is_hatched(rel));
}

#[test]
fn is_hatched_returns_true_when_sibling_exists() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secrets.env");
    let sibling = dir.path().join("secrets.env.plaintext");
    fs::write(&path, "secret=hunter2\n").unwrap();
    fs::write(&sibling, "").unwrap();
    assert!(is_hatched(path.to_str().unwrap()));
}

#[test]
fn clean_skips_encryption_when_plaintext_sibling_exists() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.env");
    let sibling = dir.path().join("example.env.plaintext");
    let secret = concat!("AGE", "-SECRET", "-KEY-", "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L");

    fs::write(&path, secret).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), path.to_str().unwrap())
        .expect("clean should succeed");

    // The hatch must cause the content to be returned VERBATIM.
    assert_eq!(cleaned, secret.as_bytes());
}

#[test]
fn clean_encrypts_normally_without_plaintext_sibling() {
    // Negative test: when the sibling does not exist, the filter still
    // encrypts the file (this proves the hatch is a real opt-in, not a no-op).
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secrets.env");
    let secret = concat!("AGE", "-SECRET", "-KEY-", "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L");

    fs::write(&path, secret).unwrap();
    // No `.plaintext` sibling

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), path.to_str().unwrap())
        .expect("clean should succeed");

    // Without the hatch, the secret content must NOT appear verbatim.
    let cleaned_str = String::from_utf8_lossy(&cleaned);
    assert!(
        !cleaned_str.contains("[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBtc1N1Mm1aZDhEdUVPbUtVRVJadmhoalhvV0hmcjB1L0FtQzMyU2V0Q3hjClUxdWZ4K1dUNFlNcytUZHB0RDh4R1JFNWpiNWttNDEvVjRIK2pRd1dGZXcKLT4gSmF3NUUtZ3JlYXNlCmZlYzVnS21xeFpKS2hnSithdzJTN1BXNkR1aHhWcTVacmNST0Zwc2lsQzkreWhlc2hLSHM5R3BOMDF6djdvYmMKVUVkWWJTNitTaE51T1kvTHpuQQotLS0gNEJwcWtTUHorUEJtR3VPYmJwQTQvWEhQRUFLQ3hDTXdOVnd3K2VDQ2JPTQrQwg3gLl7Y74pib2WgRPbzTP0Y8FoD/6fPt1OFsoAd1NBksnqkm5oRsjibSpGPXWOQlJt/]"),
        "secret leaked through clean filter without hatch: {}",
        cleaned_str
    );
}

#[test]
fn clean_with_plaintext_sibling_does_not_add_env_version_header() {
    // Even for .env files (which normally get a Dracon Warden version
    // header), the hatch must cause pass-through with NO modification.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".env");
    let sibling = dir.path().join(".env.plaintext");
    let secret = concat!("AGE", "-SECRET", "-KEY-", "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L");

    fs::write(&path, secret).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), path.to_str().unwrap())
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
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blob.bin");
    let sibling = dir.path().join("blob.bin.plaintext");
    // Real binary content (PNG header)
    let bytes: Vec<u8> = vec![
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    ];

    fs::write(&path, &bytes).unwrap();
    fs::write(&sibling, "").unwrap();

    let security = WardenSecurity::new(None).unwrap();
    let cleaned = security
        .smart_clean_with_path(&bytes, path.to_str().unwrap())
        .expect("clean should succeed");

    assert_eq!(cleaned, bytes);
}

#[test]
fn clean_with_empty_sibling_path_is_a_noop() {
    // Defensive: empty path_str must NOT match `<empty>.plaintext` at CWD
    // and accidentally skip encryption. The hatch is opt-in: empty path = no
    // hatch decision.
    let security = WardenSecurity::new(None).unwrap();
    let secret = concat!("AGE", "-SECRET", "-KEY-", "1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L");
    let cleaned = security
        .smart_clean_with_path(secret.as_bytes(), "")
        .expect("clean should succeed");
    // The cleaned output should NOT contain the plaintext secret.
    let s = String::from_utf8_lossy(&cleaned);
    assert!(
        !s.contains("[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBwZitKWGRoR1MzOWNVZU83OFhOYk9vanJYdWlHa2d5QkFWc0FyREg5Z0hBCllrUmVuaUkrbkROSE1QUlhydWw1REhHMFBpMnhseVhSNzF6TDIwTXZYWWMKLT4gX3csLWdyZWFzZSAwYSAkNiN8U352VAp3R2oyOVYzdG8xbXhMQTZZS3RTNU80MHBQQ3BtSHFHcCsyUGdmTm4ydGU1OEQ0ZmhGUDJ6RUcwCi0tLSBVTFdrM3h4WURqN0FrMXlXc3hxVXh0a2poa1ZLVEJPTEhHYnYxTkpiTkdNCkjFjE0M9rk1VxZHosxxKGoKbX5eStsE9Gn9h5Dz4wJtd6P2aiSHz43J5culknH8zym9DSE=]"),
        "empty path leaked plaintext: {}",
        s
    );
}

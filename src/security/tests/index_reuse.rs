//! Git representation reuse must not weaken protection or hide actual edits.
use dracon_security::WardenSecurity;

fn security() -> WardenSecurity {
    let mut s = WardenSecurity::new(None).unwrap();
    s.add_memory_identity(age::x25519::Identity::generate());
    s.with_managed_patterns(vec!["keys.json".into()])
}

#[test]
fn unchanged_ciphertext_is_reused_but_edits_and_plaintext_are_not() {
    let s = security();
    let plain = format!(
        "const TOKEN: &str = {:?};\n",
        format!("sk_live_{}", "A".repeat(24))
    );
    let old = s
        .smart_clean_with_path(plain.as_bytes(), "src/a.rs")
        .unwrap();
    assert_ne!(old, plain.as_bytes());
    assert_eq!(
        s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(&old))
            .unwrap(),
        old
    );
    let changed = plain.replace('A', "B");
    let fresh = s
        .clean_reusing_index(changed.as_bytes(), "src/a.rs", Some(&old))
        .unwrap();
    assert_ne!(fresh, old);
    assert_eq!(
        s.smart_smudge(std::str::from_utf8(&fresh).unwrap())
            .unwrap(),
        changed
    );
    assert_ne!(
        s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(plain.as_bytes()))
            .unwrap(),
        plain.as_bytes()
    );
    let corrupted = String::from_utf8(old.clone())
        .unwrap()
        .replace("[DRACON_SECRET:", "[DRACON_SECRET:INVALID");
    assert_ne!(
        s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(corrupted.as_bytes()))
            .unwrap(),
        corrupted.as_bytes()
    );
}

#[test]
fn policy_upgrade_does_not_reuse_partially_protected_index() {
    let s = security();
    let plain = format!(
        "{{\"key\":{:?},\"short\":\"example\"}}",
        format!("sk_live_{}", "A".repeat(24))
    );
    let inline = s
        .smart_clean_with_path(plain.as_bytes(), "src/a.rs")
        .unwrap();
    let whole = s
        .clean_reusing_index(plain.as_bytes(), "keys.json", Some(&inline))
        .unwrap();
    assert_ne!(whole, inline);
    assert!(whole.starts_with(b"[DRACON_SECRET:"));
    assert_eq!(
        s.clean_reusing_index(plain.as_bytes(), "keys.json", Some(&whole))
            .unwrap(),
        whole
    );
}

#[test]
fn newly_detected_secrets_in_index_force_reencryption() {
    let s = security();
    let token = format!("sk_live_{}", "A".repeat(24));
    let first = s.smart_clean_with_path(token.as_bytes(), "a.rs").unwrap();
    let second = format!("AIza{}", "B".repeat(35));
    let partial = [first, format!("\n{second}").into_bytes()].concat();
    let plain = format!("{token}\n{second}");
    let fresh = s
        .clean_reusing_index(plain.as_bytes(), "a.rs", Some(&partial))
        .unwrap();
    assert_ne!(fresh, partial);
    assert!(!String::from_utf8(fresh).unwrap().contains(&second));
}

#[test]
fn inline_key_tag_with_exterior_newline_reuses_only_exact_plaintext_and_layout() {
    let s = security();
    let plain = format!(
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBESVQ4UjBOR0hPYkM1bE8wL2FKVjMzUDVuUnljdFIzbXd3Q3JnY2ZrckN3CnZOSE1nQW9iMVYvRmtzVHNMa3YwL3ROdnRZSm01ZzZqMGhRbW4zRGhlK2cKLT4gWDI1NTE5IGsyTzI0R1ZEYWJVZkpVdWRPVmZ0M0JUeTZqelBaaDlsRlBMSzR5dmZ2RzQKelRUMnI4c3FXbmU0MlBMaGNRM0RWR1NENzY4WHp3dDcrb2FSdytrYnBFWQotPiBYMjU1MTkgVlpuVGp6UkFoZkRNcCtKLzV6ZzRkblVueVczU1ZsTE4zem1tRU0yMjhHYwpaTHhwei9LL0ZtR1dDNmtOSjZoM2VCY1doZkFsWGE1bE94VjJlUi9ZVDVzCi0+IFgyNTUxOSArVlRCSWQ2aUc3cDNyV1ZZODdlVmZxcHJ1Wk5lTWtUNkRtTUp1dW1ab3pNCjUyUzIvZ3A3clVNNXpUZk5LRjZFRDdZeVZOTTlxSGp0UFNDelFpbCtKUVkKLT4gWDI1NTE5IHE1MHpKc1pPUmMrNnJrQ3ZDV1AvU0RtL2FhRWtUSHk4SnJla2lvNzlPRGcKWG1aUURpbGwzcTh6TENVVE9zdktiQ05PRS94eThaUDZ4RlY1Z00rajFuVQotPiByXEstZ3JlYXNlIDFyJXd5RiBKdWtVWXEgYD0KV3ZqYWdqcm5EQXN0S1l1SWVtYURybmF3bElvR3lSYTZGMldTQlZsOUxBT3h4VVRKb3NRTi9NZ0FqSkw3S0hTOQpPSmU0bUEKLS0tIEJUTWdSRnJWeTd5Skg0TUVEa0s2QnU1Z08wN2E4bk1ZaURsM1lpczc2TkUK7aCqCFu7uI/7GQbb44ZS4gSNGjzvWPVVb0saol1dOcng41QJLmHE6TRuCtjJ3wen4L64UiiKXUbNkZiCWVA8NgjMIVbVOgUI77M6qHm4aQTGGMHxmpMpDVDl0Y2GeWkoVrGG5vc0bnbhPw==]\n",
        "QUJD".repeat(60)
    );
    let old = s.smart_clean_with_path(plain.as_bytes(), "secrets/key").unwrap();
    assert!(old.starts_with(b"[DRACON_SECRET:"));
    assert!(old.ends_with(b"]\n"), "scanner keeps the PEM's exterior newline");
    assert_eq!(s.smart_smudge(std::str::from_utf8(&old).unwrap()).unwrap(), plain);
    assert_eq!(s.clean_reusing_index(plain.as_bytes(), "secrets/key", Some(&old)).unwrap(), old);
    for edited in [plain.trim_end().to_string(), format!("{plain}\n"), plain.replace("QUJD", "REVG")] {
        assert_ne!(s.clean_reusing_index(edited.as_bytes(), "secrets/key", Some(&old)).unwrap(), old,
            "real content or exterior whitespace edits must remain visible");
    }
    let upgraded = s.with_managed_patterns(vec!["credentials".into()]);
    assert_ne!(upgraded.clean_reusing_index(plain.as_bytes(), "credentials", Some(&old)).unwrap(), old,
        "whole-file upgrade must move the exterior newline inside the encrypted payload");
}

#[test]
fn generated_env_header_does_not_reencrypt_an_unchanged_headerless_worktree() {
    let s = security().with_managed_patterns(vec![".env.dev".into()]);
    let raw = b"PASSWORD=synthetic-example\n";
    let old = s.smart_clean_with_path(raw, "service/.env.dev").unwrap();
    assert!(old.starts_with(b"[DRACON_SECRET:"));
    assert_eq!(s.clean_reusing_index(raw, "service/.env.dev", Some(&old)).unwrap(), old);
    assert_ne!(s.clean_reusing_index(b"PASSWORD=changed-example\n", "service/.env.dev", Some(&old)).unwrap(), old);
}

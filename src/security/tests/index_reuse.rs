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
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB2Q1hkcnVlSnFKaWhNWHhyNzFSakxsN0dnd3p0VU5BdWpBS2NDcjVtTEhFCjBPQng4T0l6ckJiemxXZG0wZ1FxMHFtTmdqdG5idE5LcWFzYlBsUVVtNE0KLT4gWDI1NTE5IGV3dkhhM0tKd0pMZXhTUWN2Qm5WSzR6QlJGaS90bWZCeUVXbkRJZUFjbFEKVFlPR0FiKyt4eVJFTFhvSXJlRFR3VmxJTlZxa2E2TXNXS25hL2NSb3R4OAotPiBYMjU1MTkgOW1NWjYwSlJsOVFGbzNmaFR4cGFJaXVPeGtoYXhkK1RZSlJSRW04RWdoZwpCY00xN2M3dUtUbEJFMzZJR0oraytsT1cxekJsRGkvWjN3ZFBlNFR0TWNFCi0+IFgyNTUxOSBKODFrSmpaS1BrNXo5SEdqcTNZYVp2SUNUaFBwUnR2VmxUTVlOQWRFekVvClpZWm1TMVhrRGJpV2pYQmVnOXB3a2xyK3ZQNG1RQVNqZksycThGYkZYc0kKLT4gWDI1NTE5IDRoMTNCdm5nWTlMZ0s2YTR4eWdIUGlYYjdZQTVyZlNFdEg5ME9RZDZ5elkKTHFGV3F3YnAwaDZoZTRGeWdCdXQyK214WTZSZWQ1L1YybHA3YmNtdGVHZwotPiBPXVc/SW4/LWdyZWFzZSBQCjJOQQotLS0gVS9tdURxY2I3VFBMSUtVQWFlMmRsUEhxZXl3UkE3ek1KMXJ1UXdpQjZ1OApEfDj3z8PMI1vTu45c1UYnJTFSoaslc2oJEHkaTcQkr7WVI1dg8cT4E661WOXndFZK0nvW9BY9kVbJQ9vQRiNUnKETKW+jzu00I9iQdV0ED9ECI4Ed9z7wmwWHkjskGRhtLsGhTUN5tKtO]\n",
        "QUJD".repeat(60)
    );
    let old = s
        .smart_clean_with_path(plain.as_bytes(), "secrets/key")
        .unwrap();
    assert!(old.starts_with(b"[DRACON_SECRET:"));
    assert!(
        old.ends_with(b"]\n"),
        "scanner keeps the PEM's exterior newline"
    );
    assert_eq!(
        s.smart_smudge(std::str::from_utf8(&old).unwrap()).unwrap(),
        plain
    );
    assert_eq!(
        s.clean_reusing_index(plain.as_bytes(), "secrets/key", Some(&old))
            .unwrap(),
        old
    );
    for edited in [
        plain.trim_end().to_string(),
        format!("{plain}\n"),
        plain.replace("QUJD", "REVG"),
    ] {
        assert_ne!(
            s.clean_reusing_index(edited.as_bytes(), "secrets/key", Some(&old))
                .unwrap(),
            old,
            "real content or exterior whitespace edits must remain visible"
        );
    }
    let upgraded = s.with_managed_patterns(vec!["credentials".into()]);
    assert_ne!(
        upgraded
            .clean_reusing_index(plain.as_bytes(), "credentials", Some(&old))
            .unwrap(),
        old,
        "whole-file upgrade must move the exterior newline inside the encrypted payload"
    );
}

#[test]
fn generated_env_header_does_not_reencrypt_an_unchanged_headerless_worktree() {
    let s = security().with_managed_patterns(vec![".env.dev".into()]);
    let raw = b"PASSWORD=synthetic-example\n";
    let old = s.smart_clean_with_path(raw, "service/.env.dev").unwrap();
    assert!(old.starts_with(b"[DRACON_SECRET:"));
    assert_eq!(
        s.clean_reusing_index(raw, "service/.env.dev", Some(&old))
            .unwrap(),
        old
    );
    assert_ne!(
        s.clean_reusing_index(
            b"PASSWORD=changed-example\n",
            "service/.env.dev",
            Some(&old)
        )
        .unwrap(),
        old
    );
    let managed = s.smart_smudge(std::str::from_utf8(&old).unwrap()).unwrap();
    let bumped = s
        .smart_clean_with_path(managed.as_bytes(), "service/.env.dev")
        .unwrap();
    assert_eq!(
        s.clean_reusing_index(managed.as_bytes(), "service/.env.dev", Some(&bumped))
            .unwrap(),
        bumped
    );
    for changed in [
        managed.replace("synthetic-example", "changed-example"),
        format!("{managed}\n"),
    ] {
        assert_ne!(
            s.clean_reusing_index(changed.as_bytes(), "service/.env.dev", Some(&bumped))
                .unwrap(),
            bumped
        );
    }
}

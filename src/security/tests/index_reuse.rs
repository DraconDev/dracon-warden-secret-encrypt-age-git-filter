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
    let plain = format!("const TOKEN: &str = {:?};\n", format!("sk_live_{}", "A".repeat(24)));
    let old = s.smart_clean_with_path(plain.as_bytes(), "src/a.rs").unwrap();
    assert_ne!(old, plain.as_bytes());
    assert_eq!(s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(&old)).unwrap(), old);
    let changed = plain.replace('A', "B");
    let fresh = s.clean_reusing_index(changed.as_bytes(), "src/a.rs", Some(&old)).unwrap();
    assert_ne!(fresh, old);
    assert_eq!(s.smart_smudge(std::str::from_utf8(&fresh).unwrap()).unwrap(), changed);
    assert_ne!(s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(plain.as_bytes())).unwrap(), plain.as_bytes());
    let corrupted = String::from_utf8(old.clone()).unwrap().replace("[DRACON_SECRET:", "[DRACON_SECRET:INVALID");
    assert_ne!(s.clean_reusing_index(plain.as_bytes(), "src/a.rs", Some(corrupted.as_bytes())).unwrap(), corrupted.as_bytes());
}

#[test]
fn policy_upgrade_does_not_reuse_partially_protected_index() {
    let s = security();
    let plain = format!("{{\"key\":{:?},\"short\":\"example\"}}", format!("sk_live_{}", "A".repeat(24)));
    let inline = s.smart_clean_with_path(plain.as_bytes(), "src/a.rs").unwrap();
    let whole = s.clean_reusing_index(plain.as_bytes(), "keys.json", Some(&inline)).unwrap();
    assert_ne!(whole, inline);
    assert!(whole.starts_with(b"[DRACON_SECRET:"));
    assert_eq!(s.clean_reusing_index(plain.as_bytes(), "keys.json", Some(&whole)).unwrap(), whole);
}

#[test]
fn newly_detected_secrets_in_index_force_reencryption() {
    let s = security();
    let token = format!("sk_live_{}", "A".repeat(24));
    let first = s.smart_clean_with_path(token.as_bytes(), "a.rs").unwrap();
    let second = format!("AIza{}", "B".repeat(35));
    let partial = [first, format!("\n{second}").into_bytes()].concat();
    let plain = format!("{token}\n{second}");
    let fresh = s.clean_reusing_index(plain.as_bytes(), "a.rs", Some(&partial)).unwrap();
    assert_ne!(fresh, partial);
    assert!(!String::from_utf8(fresh).unwrap().contains(&second));
}

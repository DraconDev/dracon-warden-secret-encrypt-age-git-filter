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
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMTEdOekVmRENsRXFsa0JJU2RGT29IYzVFTWwvK0FxbVdUQmF0UUppUmlZCjZSdVJidmpPN3lrQ3ZycFRwSytnYUtLcjg5b1pWRVN5eHI0bzdhUHFyQ3cKLT4gWDI1NTE5IHdyV2JvbVJBeWh1cW85eFNNQ081ZXZ4Q1lMQ1JqclJ4S3pqVjZvSkI4Vm8KbG5IU1lRUDl5SXVhYWhKdU1QRm5FYUZ3SkhSbERyc3RPWG5LcUdEd0lzMAotPiBYMjU1MTkgNm51a2FjaFlHMmdtZEI4Q0tEVG5NOVIwU25EeDdQU002aGtNK1RhSGJsTQpqRlUzQkllK1Q4QWV0UXlLSzVJa2xZQXkzV2Jta0U1VzQ3NjB6QTdTRFVNCi0+IFgyNTUxOSBSajRiUmhzMnFjaEphaWY5YnpScy8vTjZuNEZmRFZiSlo1VUU5c3NtazJZCkU1dXRZN3NHZmNGc1dwRDZ2ZVExR3g1ZE1LdnFaOWNUSkRkYnNWYjV2TmsKLT4gWDI1NTE5IHZMUDNiNTFKTUZCVjZiUXJVWld2RlRSLzVzVkNtU1ZYTnRGWDY3cHk1SFUKUHJuUkowZkdBMWNtRzdvTENVWTNTb0RnNEZBMFA0WGJCUFg5WjNRYVdXcwotPiBeLWdyZWFzZSBpIHFcY0Z5QytsCjV3QVlJdVIwL3ZPZEJjTQotLS0gVWh3UWxpSzIvd0kwMjYwUGRIeGM5dFVtSDdDbW56RkM3a0tHd0l4QnIrOAr/gAOyN9c41/+9deGWJvgKKi9H2kkjEwxyyP0GX+gs7tnrC+GrCzHDN9bswdNnVDF2yj0a4GMTndEbmROmX9XveJHl1QKVP+4VGBCebRCaHxH70sHnC54eTGXX6Dn3zUIhoab4IMjgpRvb]\n",
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

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
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBRTnJEeVpNcTkvVUc1WUFUdEVObFZ5U1FXZ3k3SC9reUdaUlEvUzVKSVdVCkVKTHd2cXFvNTJSazRqKzRCZW1yVDZwR0U4cjZadGdXaHNxYUkza1JmTmcKLT4gWDI1NTE5IHJCQUFrS2ludGRDY0NYQVpmYTN0VDduNDRsNmRhekRneW1WTG9HaVVnQ00KaXlvZDR5Vk0vRE14cnlHc3dyTUlKR0lxbm9Td2paTEtPdmRoUVdMdFJsTQotPiBYMjU1MTkgVTRwbHdLZ01FdnhQY3lNTHdwV1Y5NzZlVE1oWkpmYmVwZWlhV0RvLzhEZwptUmJyTzRYb1hmekR5cWdyWUVNSWd5TUpYTzdlN2pwMGlscysyTGVJdWc4Ci0+IFgyNTUxOSAxakpSTUZ1Q0VNRld2RVRXZHR0MmYvNFV2OXpVcUw2eTJtVndVRnBKU2hvCithTjhIMjN4SkhzVlJMYVJzRlAzMGhyVWYwVmxTbDlxcDRRMTRuWmdmTDAKLT4gWDI1NTE5IE1UYUU1YVRpNXJEeUhJM3pTLzFBMnZ1OUIwaXZ3UzVTR0sreXpBRklhd0kKQUJIUXRaV011ZVpqdjZiM3RTQXBVcWVkblV5RzNXa0ZIeUdxZ3hTbXFwMAotPiBtRS1ncmVhc2UKZFVqMkFPU3JFUUx3c3FiRmNTZzU1WDhZd0hvM29WYytaMWg3ZnZsVlBFbnphVFFMMjBOMnFKYmdReS9xQ3gvSApVNTB1SEEKLS0tIFNCSWNvVXZyM0tmbkhGZGFodDNBWDJ3MXpmcmRTV0pmcUQyT3NSZXdmL2cKDbH9APRnzCY3qnCqAdUpQ82lvMewg7epMiScF59LM4F//b+PSjQ/h9vZuUrRYF8/nULLSCU9+KlDAw5OhDF3M1+t2hbNIrePMiI8ZDutuQK8qNfAZvbZdzrvC/m0Bn4nKzO3qLEecrBvUQ==]\n",
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
    let managed = s.smart_smudge(std::str::from_utf8(&old).unwrap()).unwrap();
    let bumped = s.smart_clean_with_path(managed.as_bytes(), "service/.env.dev").unwrap();
    assert_eq!(s.clean_reusing_index(managed.as_bytes(), "service/.env.dev", Some(&bumped)).unwrap(), bumped);
    for changed in [managed.replace("synthetic-example", "changed-example"), format!("{managed}\n")] {
        assert_ne!(s.clean_reusing_index(changed.as_bytes(), "service/.env.dev", Some(&bumped)).unwrap(), bumped);
    }
}

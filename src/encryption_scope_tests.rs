use super::*;

#[test]
fn encryption_only_scope_never_unignores_credentials() {
    let base: WardenPolicy = toml::from_str("protected_patterns = ['config/services.json']\nhygiene_patterns = ['.env.dev']\n").unwrap();
    let mut scoped = base.clone();
    scoped.encryption_only_patterns = vec![".env.dev".into()];
    assert_eq!(build_gitignore_block(&base).unwrap(), build_gitignore_block(&scoped).unwrap());
    let attrs = build_gitattributes_block(&scoped).unwrap();
    assert!(attrs.contains(".env.dev filter=dracon diff=dracon merge=dracon"));
    assert!(!scoped.effective_protected_patterns().contains(&".env.dev".into()));
    assert!(scoped.effective_encryption_patterns().contains(&".env.dev".into()));
    assert!(!scoped.effective_encryption_patterns().contains(&"*.rs".into()));
    let mut security = dracon_security_kit::WardenSecurity::new(None).unwrap()
        .with_managed_patterns(scoped.effective_encryption_patterns());
    security.add_memory_identity(age::x25519::Identity::generate());
    let raw = b"PASSWORD=synthetic-example\n";
    let encrypted = security.smart_clean_with_path(raw, "apis/services/auth-api/.env.dev").unwrap();
    assert!(encrypted.starts_with(b"[DRACON_SECRET:"));
    let decoded = security.smart_smudge(std::str::from_utf8(&encrypted).unwrap()).unwrap();
    assert!(decoded.ends_with(std::str::from_utf8(raw).unwrap()));
    assert!(decoded.contains("Dracon Warden"));
}

#[test]
fn encryption_only_scope_keeps_legacy_defaults_and_rejects_plaintext_conflicts() {
    let omitted: WardenPolicy = toml::from_str("").unwrap();
    assert!(omitted.encryption_only_patterns.is_empty());
    let legacy: WardenPolicy = toml::from_str("encryption_only_patterns = ['.env.dev']\n").unwrap();
    assert!(legacy.effective_encryption_patterns().is_empty(), "legacy empty protected scope still scans everything");
    let conflict: WardenPolicy = toml::from_str("encryption_only_patterns = ['Cargo.lock']\nplaintext_patterns = ['Cargo.lock']\n").unwrap();
    assert!(conflict.validate().unwrap_err().to_string().contains("both protected and plaintext"));
}

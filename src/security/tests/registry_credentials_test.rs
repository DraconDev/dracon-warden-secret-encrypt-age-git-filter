mod common;

use dracon_security::WardenSecurity;

use common::HomeGuard;

fn init_with_temp_home() -> (WardenSecurity, HomeGuard) {
    let _guard = HomeGuard::new();
    let mut security = WardenSecurity::new(None).expect("init security");
    let identity = age::x25519::Identity::generate();
    security.add_memory_identity(identity);
    (security, _guard)
}

#[test]
fn test_load_registry_credentials_when_none_exist() {
    let (security, _guard) = init_with_temp_home();
    let loaded = security.load_registry_credentials().unwrap_or_default();
    assert!(loaded.is_empty(), "no credentials should exist initially");
}

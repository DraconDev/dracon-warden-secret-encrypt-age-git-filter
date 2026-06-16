mod common;

use age::x25519::Identity;
use dracon_security::WardenSecurity;

use common::HomeGuard;

fn init_with_temp_home() -> (WardenSecurity, HomeGuard) {
    let _guard = HomeGuard::new();
    let mut security = WardenSecurity::new(None).expect("init security");
    let identity = Identity::generate();
    security.add_memory_identity(identity);
    (security, _guard)
}

#[test]
fn test_add_team_member_rejects_invalid_key() {
    let (security, _guard) = init_with_temp_home();
    let result = security.add_team_member("bob", "not-a-valid-key");
    assert!(result.is_err(), "invalid public key should be rejected");
}

#[test]
fn test_create_team_invite_requires_existing_team() {
    let (security, _guard) = init_with_temp_home();

    let user_key = Identity::generate();
    let user_public_str = user_key.to_public().to_string();
    let result = security.create_team_invite("nonexistent-team", &user_public_str);
    assert!(result.is_err(), "invite to nonexistent team should fail");
}

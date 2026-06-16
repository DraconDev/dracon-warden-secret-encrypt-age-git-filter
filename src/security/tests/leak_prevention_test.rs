use dracon_security::WardenSecurity;
use proptest::prelude::*;
use std::sync::OnceLock;

static TEST_SECURITY: OnceLock<WardenSecurity> = OnceLock::new();

fn get_test_security() -> &'static WardenSecurity {
    TEST_SECURITY.get_or_init(|| {
        let mut security = WardenSecurity::new(None).expect("Failed to init security");
        if !security.has_master_identity() {
            let key = age::x25519::Identity::generate();
            security.add_memory_identity(key);
        }
        security
    })
}

// Strategies for generating test data
fn sensitive_paths() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(".ssh/id_rsa".to_string()),
        Just(".ssh/config".to_string()),
        Just(".aws/credentials".to_string()),
        Just(".kube/config".to_string()),
        Just("dracon/keys/master.age".to_string()),
        Just("dummy_repo/.gnupg/trustdb.gpg".to_string()),
    ]
}

fn public_paths() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("src/main.rs".to_string()),
        Just("README.md".to_string()),
        Just("assets/image.png".to_string()),
        Just("docs/notes.txt".to_string()),
        Just("Cargo.toml".to_string()),
    ]
}

fn sensitive_extensions() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("secret.age".to_string()),
        Just("key.p12".to_string()),
        Just("cert.pem".to_string()),
        Just("my.key".to_string()),
    ]
}

fn sensitive_filenames() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("id_rsa".to_string()),
        Just("id_ed25519".to_string()),
        Just("master.age".to_string()),
        Just("dracon-key".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_test_hybrid_security_logic(
        is_binary in any::<bool>(),
        path in prop_oneof![sensitive_paths(), public_paths(), sensitive_extensions(), sensitive_filenames()],
        has_secret in any::<bool>()
    ) {
        let security = get_test_security();

        let mut content = if is_binary {
            vec![0u8, 1, 2, 255, 0, 128]
        } else {
            "Some normal text content\n".as_bytes().to_vec()
        };

        let secret_str = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz123456789012");
        // Header for PEM keys to test content detection
        let pem_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcLiSPlqO2kBz\n-----END RSA PRIVATE KEY-----";

        if has_secret && !is_binary {
            // Test both an API key and a PEM header
            content.extend_from_slice(secret_str.as_bytes());
            content.extend_from_slice(b"\n");
            content.extend_from_slice(pem_content.as_bytes());
        }

        let cleaned = security.smart_clean_with_path(&content, &path).unwrap();

        // 1. Check for Leaks (Total Passthrough of Naked Secrets)
        if !is_binary && has_secret {
            // A text secret should NEVER be committed unencrypted
            prop_assert!(!cleaned.windows(secret_str.len()).any(|w| w == secret_str.as_bytes()),
                "Naked API secret leaked in path: {}", path);
            prop_assert!(!cleaned.windows(pem_content.len()).any(|w| w == pem_content.as_bytes()),
                "Naked PEM content leaked in path: {}", path);
        }

        // 2. Decide Policy: Should it be Nuclear?
        let sensitive_dirs = [".ssh", "dracon/keys", ".aws", ".kube", ".gnupg", ".azure", ".config/gcloud"];
        let sensitive_exts = [".age", ".key", ".p12", ".pfx", ".pem", ".crt", ".der", ".asc"];
        let sensitive_names = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_xmss", "master.age", "identity.age", "owner.age", "dracon-key"];

        let is_sensitive_path = sensitive_dirs.iter().any(|d| path.contains(d));
        let is_sensitive_ext = sensitive_exts.iter().any(|e| path.ends_with(e));
        let filename = std::path::Path::new(&path).file_name().and_then(|s| s.to_str()).unwrap_or("");
        let is_sensitive_name = sensitive_names.contains(&filename);

        let should_be_nuclear = is_binary && (is_sensitive_path || is_sensitive_ext || is_sensitive_name);

        if should_be_nuclear {
            prop_assert!(cleaned.starts_with(b"[DRACON_SECRET:"),
                "Sensitive binary was NOT nuclear encrypted at path: {}", path);
        }

        if !is_binary && !has_secret {
             let filename = std::path::Path::new(&path).file_name().and_then(|s| s.to_str()).unwrap_or("");
             let always_full_encrypt = filename == "credentials"
                 || filename.starts_with(".env")
                 || filename.starts_with(".bash_history")
                 || filename.starts_with(".zsh_history")
                 || filename.starts_with(".sh_history")
                 || filename == "vault.yml";
             if is_sensitive_path && !always_full_encrypt {
                 prop_assert_eq!(&cleaned, &content,
                    "Normal text in sensitive path was incorrectly nuked: {}", path);
             }
        }
    }

    #[test]
    fn prop_test_binary_passthrough_integrity(
        ref data in prop::collection::vec(any::<u8>(), 0..1024),
        ref path in public_paths()
    ) {
        let security = get_test_security();
        let cleaned = security.smart_clean_with_path(data, path).unwrap();

        // If it's a public path and not identifying as sensitive by any other means
        // (public_paths strategy generates non-sensitive paths)
        // it should be bit-for-bit identical.
        assert_eq!(cleaned, *data, "Binary data in public path: {} was modified", path);
    }
}

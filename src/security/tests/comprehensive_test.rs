mod common;

use anyhow::Result;
use dracon_security::WardenSecurity;
use proptest::prelude::*;
use std::fs;
use std::sync::OnceLock;

use common::HomeGuard;

#[allow(dead_code)]
static TEST_SECURITY: OnceLock<WardenSecurity> = OnceLock::new();

#[allow(dead_code)]
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

#[derive(Debug, Clone)]
struct SecretExample {
    name: &'static str,
    #[allow(dead_code)]
    pattern: &'static str,
    raw: &'static str,
}

const CORPUS: &[SecretExample] = &[
    SecretExample {
        name: "Stripe Secret Key",
        pattern: "Stripe Live Secret Key",
        raw: concat!("sk", "_live_51ABCDEF1234567890abcdef1234567890abcdef123"),
    },
    SecretExample {
        name: "GitHub Token",
        pattern: "GitHub Token (ghp)",
        raw: concat!("gh", "p_1234567890abcdef1234567890abcdef1234"),
    },
    SecretExample {
        name: "Slack Token",
        pattern: "Slack Token",
        raw: concat!("xox", "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
    },
    SecretExample {
        name: "Generic API Key (Assignment)",
        pattern: "Generic API Key (Unquoted)",
        raw: "API_KEY=1234567890abcdef1234567890abcdef",
    },
    SecretExample {
        name: "Generic Secret (Assignment)",
        pattern: "Generic Secret (Unquoted)",
        raw: "DB_PASSWORD=super_secret_password_123!",
    },
    SecretExample {
        name: "AWS Access Key",
        pattern: "AWS Access Key ID",
        raw: concat!("AK", "IAIOSFODNN7EXAMPLE"),
    },
    SecretExample {
        name: "AWS Session Token",
        pattern: "AWS Session Token",
        raw: "aws_session_token = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890/+=abcdef",
    },
    SecretExample {
        name: "GCP API Key",
        pattern: "GCP API Key",
        raw: concat!("AI", "zaSyD-1234567890abcdef1234567890abcde"),
    },
    SecretExample {
        name: "GCP OAuth Access Token",
        pattern: "GCP OAuth Access Token",
        raw: concat!("ya", "29.a0AfH6SMC_1234567890abcdef1234567890abcdef1234567890"),
    },
    SecretExample {
        name: "Azure Shared Access Signature",
        pattern: "Azure Shared Access Signature",
        raw: "sv=2019-02-02&sr=b&sig=dD8%2Bfd2%2B1234567890abcdef1234567890abcdef123%3D",
    },
    SecretExample {
        name: "Azure Storage Account Key",
        pattern: "Azure Storage Account Key",
        raw: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuv==",
    },
    SecretExample {
        name: "Alibaba Access Key ID",
        pattern: "Alibaba Access Key ID",
        raw: concat!("LT", "AI1234567890abcdef1234"),
    },
    SecretExample {
        name: "Alibaba Secret Key",
        pattern: "Alibaba Secret Key",
        raw: "aliyun_secret_key = abcdefghijklmnopqrstuvwxyz1234",
    },
    SecretExample {
        name: "IBM Cloud API Key",
        pattern: "IBM Cloud API Key",
        raw: "ibm_cloud_api_key = abcdefghijklmnopqrstuvwxyz1234567890abcdef12",
    },
    SecretExample {
        name: "Oracle Cloud API Key",
        pattern: "Oracle Cloud API Key",
        raw: concat!("oc", "id1.user.oc1.test.abcdef1234567890abcdef1234567890abcdef1234"),
    },
    // SaaS
    SecretExample {
        name: "Stripe Live Secret Key",
        pattern: "Stripe Live Secret Key",
        raw: concat!("sk", "_live_abcdefghijklmnopqrstuvwx123456"),
    },
    SecretExample {
        name: "Stripe Test Secret Key",
        pattern: "Stripe Test Secret Key",
        raw: concat!("sk", "_test_abcdefghijklmnopqrstuvwx123456"),
    },
    SecretExample {
        name: "Slack Token",
        pattern: "Slack Token",
        raw: concat!("xox", "b-123456789012-123456789012-abcdef123456"),
    },
    SecretExample {
        name: "Slack Webhook",
        pattern: "Slack Webhook",
        raw: concat!("https://hooks", ".slack.com/services/T01234567/B01234567/abcdef1234567890abcdef12"),
    },
    SecretExample {
        name: "Discord Token",
        pattern: "Discord Token",
        raw: "Mabcdefghijklmnopqrstuvw.abcdef.abcdefghijklmnopqrstuvw1234", // M + 23, . 6, . 27
    },
    SecretExample {
        name: "Discord Webhook",
        pattern: "Discord Webhook",
        raw: "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef123456",
    },
    SecretExample {
        name: "Telegram Bot Token",
        pattern: "Telegram Bot Token",
        raw: "1234567890:abcdefghijklmnopqrstuvwxyz123456789",
    },
    SecretExample {
        name: "Twilio API Key",
        pattern: "Twilio API Key",
        raw: concat!("SK", "1234567890abcdef1234567890abcdef"),
    },
    SecretExample {
        name: "Twilio Account SID",
        pattern: "Twilio Account SID",
        raw: concat!("AC", "1234567890abcdef1234567890abcdef"),
    },
    SecretExample {
        name: "SendGrid API Key",
        pattern: "SendGrid API Key",
        raw: concat!("SG", ".abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890abcdefg"),
    },
    SecretExample {
        name: "Mailgun API Key",
        pattern: "Mailgun API Key",
        raw: concat!("key", "-1234567890abcdef1234567890abcdef"),
    },
    // Database & Generic
    SecretExample {
        name: "PostgreSQL URL",
        pattern: "PostgreSQL URL",
        raw: "postgres://user:password@localhost:5432/dbname",
    },
    SecretExample {
        name: "MySQL URL",
        pattern: "MySQL URL",
        raw: "mysql://user:password@localhost:3306/dbname",
    },
    SecretExample {
        name: "MongoDB URL",
        pattern: "MongoDB URL",
        raw: "mongodb://user:password@localhost:27017/dbname",
    },
    SecretExample {
        name: "Redis URL",
        pattern: "Redis URL",
        raw: "redis://user:secretpassword@localhost:6379",
    },
];

#[test]
fn test_corpus_roundtrip() {
    let mut security = WardenSecurity::new(None).expect("Security init failed");
    if !security.has_master_identity() {
        let key = age::x25519::Identity::generate();
        security.add_memory_identity(key);
    }

    for example in CORPUS {
        let cleaned = security
            .smart_clean(example.raw)
            .expect("Encryption failed");
        assert_ne!(
            cleaned, example.raw,
            "Content was not modified (not encrypted) for {}",
            example.name
        );
        assert!(cleaned.contains("[DRACON_SECRET:"));
    }
}

// Fuzzing: Generate random strings that look like secrets
proptest! {
    fn prop_fake_secret_roundtrip(s in "[s][k]_live_[0-9a-zA-Z]{24,}") {
        let security = get_test_security();

        let cleaned = security.smart_clean(&s).unwrap();
        // Should be detected and encrypted
        prop_assert!(cleaned.contains("[DRACON_SECRET:"));
    }
    fn prop_arbitrary_roundtrip(s in "\\PC*") {
        let security = get_test_security();

        let cleaned = security.smart_clean(&s).unwrap();
        let smudged = security.smart_smudge(&cleaned).unwrap();
        prop_assert_eq!(smudged, s);
    }

    // Fuzzing: Mixed content with secrets
    fn prop_mixed_content(
        prefix in "[a-zA-Z0-9]{0,20}",
        secret in "[s][k]_live_[0-9a-zA-Z]{24,}",
        suffix in "[a-zA-Z0-9]{0,20}"
    ) {
        let content = format!("{}{}{}", prefix, secret, suffix);
        let security = get_test_security();

        let cleaned = security.smart_clean(&content).unwrap();
        // The secret should be hidden
        prop_assert!(!cleaned.contains(&secret));
        prop_assert!(cleaned.contains("[DRACON_SECRET:"));
    }
}
#[test]
fn test_backup_functionality() -> Result<()> {
    let _guard = HomeGuard::new();

    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);

    let temp_home = std::env::var("HOME").map(std::path::PathBuf::from).unwrap();
    let file_path = temp_home.join("secret.env");
    let content = b"SECRET_API_KEY=12345";

    fs::write(&file_path, content)?;

    let res = security.backup_file(&file_path, content);
    assert!(res.is_ok());

    Ok(())
}

#[test]
fn test_auto_key_generation() -> Result<()> {
    let temp_repo = tempfile::tempdir()?;
    let git_dir = temp_repo.path().join(".git");
    fs::create_dir(&git_dir)?;

    // Pass repo path directly instead of mutating global CWD
    let mut security = WardenSecurity::new(Some(temp_repo.path()))?;
    // Inject a memory identity so we have a current user key to save
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);

    security.ensure_current_user_key()?;

    let keys_dir = temp_repo.path().join(".dracon").join("data").join("keys");
    assert!(keys_dir.exists());

    let mut entries = fs::read_dir(keys_dir)?;
    let entry = entries.next().unwrap()?;
    let path = entry.path();
    assert_eq!(path.extension().unwrap(), "pub");

    Ok(())
}

#[test]
fn test_encrypt_decrypt_multiple_recipients() -> Result<()> {
    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key.clone());

    let plaintext = b"multi-recipient secret data";

    let recipient1 = key.to_public();
    let recipient2 = age::x25519::Identity::generate().to_public();

    let encrypted = security.encrypt_v2(
        plaintext,
        vec![Box::new(recipient1.clone()), Box::new(recipient2.clone())],
    )?;

    let decrypted = security.decrypt_v2(&encrypted)?;
    assert_eq!(
        &decrypted[..],
        plaintext,
        "multi-recipient should roundtrip"
    );

    Ok(())
}

#[test]
fn test_dracon_security_singleton_same_instance() -> Result<()> {
    let s1 = WardenSecurity::get_or_init()?;
    let s2 = WardenSecurity::get_or_init()?;
    assert_eq!(
        s1 as *const _ as usize, s2 as *const _ as usize,
        "get_or_init should return the same instance"
    );
    Ok(())
}

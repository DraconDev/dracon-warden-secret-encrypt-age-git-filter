//! Tier-1 eager source encryption (ADDED 2026-09-16).
//!
//! Tier-1 = structured provider tokens (fixed prefix + rigid body) that run
//! on EVERY non-hatched text file, including unprotected source files.
//! Tier-2 (generic / keyword-anchored / low-floor) stays behind the
//! protected-patterns gate (2026-06 gibuardien false-positive lesson).
//!
//! Fixture hygiene: this file commits NO live-format secret strings —
//! every token below is assembled at runtime (string concat), so neither
//! the warden's own filter nor GitHub secret scanning can match the
//! committed bytes. See README "test fixture convention".

use dracon_security::{SecretScanner, WardenSecurity};

/// Assemble a Stripe live secret key at runtime: `sk_live_` + 24 alnum.
fn stripe_live() -> String {
    format!("{}{}{}", "sk", "_live_", "A1b2C3d4E5f6G7h8I9j0K1L2")
}

/// Assemble a GitHub personal token at runtime: `ghp_` + 30 alnum.
fn github_pat() -> String {
    format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5")
}

/// Assemble an AWS access key ID at runtime: `AKIA` + 16 upper/digit.
fn aws_key() -> String {
    format!("{}{}", "AK", "IA0123456789ABCDEF")
}

/// Assemble an OpenAI-style key at runtime: `sk-` + 24 chars.
fn openai_key() -> String {
    format!("{}{}", "sk-", "a".repeat(24))
}

fn tier1_security() -> WardenSecurity {
    let mut security = WardenSecurity::new(None)
        .unwrap()
        .with_managed_patterns(vec!["*.env".to_string()]);
    security.add_memory_identity(age::x25519::Identity::generate());
    security
}

#[test]
fn tier1_scanner_catches_structured_tokens() {
    let scanner = SecretScanner::new_tier1().unwrap();
    let doc = format!(
        "stripe={} github={} aws={} openai={}",
        stripe_live(),
        github_pat(),
        aws_key(),
        openai_key()
    );
    let findings = scanner.scan(&doc);
    let names: Vec<&str> = findings.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "Stripe Live Secret Key",
        "GitHub Token (ghp)",
        "AWS Access Key ID",
        "OpenAI API Key",
    ] {
        assert!(
            names.contains(&expected),
            "Tier-1 must catch {expected}; got {names:?}"
        );
    }
}

#[test]
fn tier1_ignores_ordinary_code() {
    // June gibuardien pins: none of these may match Tier-1, or innocent
    // source gets encrypted on every commit.
    let scanner = SecretScanner::new_tier1().unwrap();
    let ordinary = [
        // Model IDs / slugs.
        r#"id: "mistralai/mistral-small-3.1-24b-instruct""#.to_string(),
        "model = \"gpt-4o-mini\"".to_string(),
        // Short / malformed near-misses (below floors).
        "sk-abc".to_string(),
        "ghp_short".to_string(),
        "AKIA123".to_string(),
        // Generic assignments are Tier-2, not Tier-1.
        "password = \"hunter2-hunter2\"".to_string(),
        "api_key = \"abcdef0123456789\"".to_string(),
        // Ordinary code shapes.
        "fn fetch_token() { let x = 1; }".to_string(),
        "const UUID = \"123e4567-e89b-12d3-a456-426614174000\";".to_string(),
        "tokenizer.encode(\"hello world\")".to_string(),
    ];
    for content in &ordinary {
        let findings = scanner.scan(content);
        assert!(
            findings.is_empty(),
            "Tier-1 must ignore ordinary code {content:?}; got {:?}",
            findings.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn tier1_is_subset_of_get_patterns() {
    // No-drift pin: every Tier-1 entry must also appear in the full set
    // (Tier-1 first), so Tier-2 behavior is unchanged.
    let full = SecretScanner::get_patterns();
    let tier1 = SecretScanner::tier1_patterns();
    assert!(!tier1.is_empty(), "Tier-1 must not be empty");
    for (i, (name, pattern)) in tier1.iter().enumerate() {
        assert_eq!(
            full[i],
            (*name, *pattern),
            "Tier-1 entry {i} ({name}) must lead get_patterns unchanged"
        );
    }
    assert!(
        full.len() > tier1.len(),
        "Tier-2 must still exist beyond Tier-1"
    );
}

#[test]
fn tier1_source_file_clean_and_roundtrip() {
    // The Sept-15 showcase shape: a Stripe live key sitting in a source
    // file no protected glob covers. Must encrypt + round-trip byte-exact.
    let security = tier1_security();
    for path in [
        "src/routes/play/+page.svelte",
        "src/main.rs",
        "lib/util.ts",
        "notes.txt",
    ] {
        let content = format!("const STRIPE_KEY = \"{}\";\n", stripe_live());
        let cleaned = security
            .smart_clean_with_path(content.as_bytes(), path)
            .unwrap();
        assert_ne!(
            cleaned,
            content.as_bytes(),
            "Tier-1 key must be encrypted in unprotected path: {path}"
        );
        let cleaned_str = String::from_utf8(cleaned).unwrap();
        assert!(
            cleaned_str.contains("DRACON_SECRET"),
            "Tier-1 hit must leave an encrypted marker: {path}"
        );
        assert!(
            !cleaned_str.contains("sk_live_"),
            "no plaintext provider prefix may survive clean: {path}"
        );
        let restored = security.smart_smudge(&cleaned_str).unwrap();
        assert_eq!(restored, content, "round-trip must be byte-exact: {path}");
    }
}

#[test]
fn tier1_openai_boundaries_and_source_roundtrip() {
    let scanner = SecretScanner::new_tier1().unwrap();
    for ordinary in [
        "ta[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBkTWlaZmF0OXJMQnFUOEduRG1DTTA4aE9wblB3cjFuc24xZ3U1V090RTFvCktvZWdxRXhiTW5keW9WQ3hPdUxPY042ZU9Ud2hVZDkwNGlRb2tYSXJCSmMKLT4gWDI1NTE5IDJLQkFzcmxmakZKL21xWHdUNXBkVGd5cDlGNEtuTHZrVEN5bmVpajQvQU0KUnorbThiU0d0amU3Q2pZWTNnSjlrbWdiN3VLdEJ1T0ptZlN5R3d1RlZySQotPiBYMjU1MTkgTVBRL0xKZzRXUUc3N1VvR1FFOUlESE9HcTZSNWViL0JqZEtzMzV4WmJTWQpqbXc5ck82M0RpTGk2VERYeVVST1RXY3lweTY5UHRwdEpXZ1M4VGcvZGtzCi0+IFgyNTUxOSBYNk9CUnlnajRBMERzaU5OOGRMVyt4UGZpM1M2MFNFcVFUV3Qvc2s5YnhnCjNGWVV2S3lFU1hOMENqNXV4RUxVV3lBQ1RFd3ZUaS95TUpvTnpPeThHMzgKLT4gWDI1NTE5IEdqUXpmTm9mOHpVckJUclc1RlBIdGxQNTBXejFDTk1nMHRZQWYzNGVUd1EKa1pBSzZEbVl0TXFIUjJYUzhUWlJlZGR6b04yYndlZFo5c0hndVV6MkR4NAotPiAzYj0hJi1ncmVhc2UgeCNNOkphCnB4Yk82ZThsTnVyQUVtOFFkWTN2NHRpUWZmbWVvUUJFeXk5QmVqVmNYUjBPMmtTMENUblNWMWsKLS0tIGE1dUNxMHhDdmk5RFJJWnk1MTliZlVHblpwNVRjTjcyVE1nUjUzWEp4WWMK9KA5/USoDJP6KEcHg5qjc6KFjFKtp+qdDqQdXeyf9s3XmZ4kh6Q3DdE6w5VbwleR6qC+N+Q4w4Z2LLR2aMX6DA==]",
        "ma[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBNRzQvZjg0VFRrdFVtYStzYk5HVEhFcWxMZ08xbG1TaFE5SUF4MU4xU2dBCitrV3k1M01wazArRXc2emNiN21VMzAyRXllYmp1OVZ3OUFOcVdtRXovV28KLT4gWDI1NTE5IG1GRS9RbTR1L0Ntay9DS0lVbGpRcUNIcXRaOFJrWVpJOVZVdVoxNnp2WGcKdi9pMWI0cmZmZHJrZHpyVUZOT2R5NE5nZ2pCQVVaVW14aDFpTXZqWTIwMAotPiBYMjU1MTkgcmMySHk4ZzhSb2FqbzBvOHoreVlDZ3libVNycng0ZXBURUpDdTdJeUFXQQpIVkJsMFhTQzYxRFoxMnplcWsxV0N0N0d2MWI2dkYxV01PcytOeFc2SldzCi0+IFgyNTUxOSA4ckMwbmRKY2sxbjZ4SS96KzRVWEVsaEpmeHdCV0J5UjZQdktLQVdzeG5JCklkNW96KzFHYU05QTZVUUNTM0ViL1pYdHl2U1Y5VlNEY2FWQzJJUC8relEKLT4gWDI1NTE5IGJ4aDdhMDgrblIyenNiWE5vUStPZEt3YmpNaFJXOVdHQWNqa1hHWEZjblkKMkJhRjMxQXVybkpNazU2czNuTFBZMWpvQjh0ZzI1aXZWeEI2WUw5NzN3dwotPiB3MGE/JCktZ3JlYXNlIEc7SXkieWMgNFV3anZ8Y0ggfkYrK3MnPXwKRVpsYWpHRjJ4YkE1bWRwMQotLS0gcjlQRmtGYUR5NXlVMTg4YzZ3WGwxait5NERESDI2K1RkWmxtSGJUU3FpVQqOMsFG2bUP+xUT85wx8z9aY/OFz6FGWl0A8PiQcrSyGm1hXCjuS3OJxWt1nNlOSl3mARv/XtMc+7mhDYgJPstB]",
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQdHZLa3FSUHc2a2grZjZPMG0yYlJpQkhYSlFoV2NtbUFPMVVxWTZxUGpBCnIxcW9ZOHB6dGRQY1FKTHBmT3FuS0hGSURXY29Za0hoTVAyc3A3TWRabkUKLT4gWDI1NTE5IHNsaWFSQ3NTVFR3cXhvZXdpaGtYYi9sTW9QSVNvVmJmRXN1K3lQcndkWFUKR0FjcEtlYUVrR21wYU5sQm16d1lrQW9NaHpMS1gxMTg0TUlPdXhOTnQ1RQotPiBYMjU1MTkgVE1SSEtTdU9lOVgxTXRGeEdXYXRFTlJBellCd3VqaGZpWU1FWXVTOE5FawovY0JxNEtudkl0MndVNmxPRE5EZytObk8yblJxSk0xVjByekQwdWJ0b0xjCi0+IFgyNTUxOSA0UjVXNmlzM2VFNnQ3dkpQUXZGTnFIMWIwY2J4SUt5UGRWa3RsTnRBZFNnCmxLS01PU3kzaGlEaWM2Q25HUW45UWg1YzQ5M1pMYmo5TGtuN043azhVNk0KLT4gWDI1NTE5IHozZjBxdUFBVjR0ZmcvTnJNSm10UDFxdjhYNzcxTC9DN0dkbU1wZnFFVk0KMFo0bGluUjh3alJ0SkFOd204bDJxZTA4SmpUZ1czK05qNE11d1BsMDZSawotPiBGQXh+PzktZ3JlYXNlICMvK1A9PXcgekM4NXIKS200ZXQ2YVQxTWFvMzV5MW9pOU92MFJQV2N3bDRwa3JiZ2NjaDQyME9uMWplNS9iamJmSTVScEMvdHdYS2NKOQoKLS0tIEIzOGZEOVFMNDIvVkdwRHRSN3pNUEJzNzdxdVV1T2lQOW1SUmgvSjFtVmsKi2xWrrbmwEYAnc0xUDj7GTpNiynR9uZ0I7ggBWPiEetAExB8G80ROXQz8lrXpdpVK44yC2s+5OZcYSUb6Hl6SQ==]",
    ] {
        assert!(scanner.scan(ordinary).is_empty(), "ordinary slug matched");
    }
    let security = tier1_security();
    for prefix in ["sk-", "sk-proj-", "sk-svcacct-"] {
        let token = format!("{prefix}{}", "A1".repeat(24));
        let input = format!("const value = \"{token}\";\r\n");
        let cleaned = security
            .smart_clean_with_path(input.as_bytes(), "src/main.rs")
            .unwrap();
        let text = String::from_utf8(cleaned).unwrap();
        assert!(!text.contains(&token));
        assert!(text.contains("[DRACON_SECRET:"));
        assert_eq!(security.smart_smudge(&text).unwrap(), input);
    }
}

#[test]
fn tier1_pkcs8_and_gcp_source_roundtrip() {
    let security = tier1_security();
    let dashes = "-".repeat(5);
    let mut inputs = Vec::new();
    for label in ["PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
        inputs.push(format!(
            "{dashes}BEGIN {label}{dashes}\nMIIExampleBody\n{dashes}END {label}{dashes}"
        ));
    }
    inputs.push(format!("{}{}{}", "AI", "za", "A1_".repeat(11) + "Z-"));
    for token in inputs {
        let input = format!("/* {token} */\n");
        let cleaned = String::from_utf8(
            security
                .smart_clean_with_path(input.as_bytes(), "src/main.rs")
                .unwrap(),
        )
        .unwrap();
        assert!(!cleaned.contains(&token));
        assert!(cleaned.contains("[DRACON_SECRET:"));
        assert_eq!(security.smart_smudge(&cleaned).unwrap(), input);
    }
}

#[test]
fn tier1_square_requires_exact_body_length() {
    let scanner = SecretScanner::new_tier1().unwrap();
    let prefix = concat!("sq", "0atp-");
    let valid = format!("{prefix}{}", "A".repeat(22));
    let overlong = format!("{prefix}{}", "A".repeat(30));
    let short = format!("{prefix}{}", "A".repeat(21));

    for invalid in [&overlong, &short] {
        assert!(scanner.scan(invalid).is_empty());
        assert_eq!(
            scanner.scan_and_replace(invalid, |_, _| "REPLACED".to_string()),
            *invalid,
            "invalid lengths must not be partially encrypted"
        );
    }
    let findings = scanner.scan(&valid);
    assert!(findings.iter().any(|f| f.name == "Square Access Token"));
    let surrounding = format!("value = \"{valid}\";\n");
    assert_eq!(
        scanner.scan_and_replace(&surrounding, |name, matched| {
            assert_eq!(name, "Square Access Token");
            assert_eq!(matched, valid);
            "REPLACED".to_string()
        }),
        "value = \"REPLACED\";\n"
    );
}

#[test]
fn tier1_binary_passthrough_unprotected() {
    // Non-UTF8 content in a non-protected location is never encrypted.
    let security = tier1_security();
    let binary: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF];
    let cleaned = security
        .smart_clean_with_path(&binary, "assets/logo.png")
        .unwrap();
    assert_eq!(cleaned, binary, "binary must pass through untouched");
}

#[test]
fn tier1_pem_block_in_source_is_caught() {
    // A pasted private key inside a source comment is Tier-1.
    let security = tier1_security();
    let begin = format!("{}BEGIN RSA PRIVATE KEY{}", "-".repeat(5), "-".repeat(5));
    let end = format!("{}END RSA PRIVATE KEY{}", "-".repeat(5), "-".repeat(5));
    let content = format!("// {begin}\n// MIIEpAIBAAKC...\n// {end}\nfn main() {{}}\n");
    let cleaned = security
        .smart_clean_with_path(content.as_bytes(), "src/main.rs")
        .unwrap();
    assert_ne!(
        cleaned,
        content.as_bytes(),
        "PEM block in source must be encrypted"
    );
    let restored = security
        .smart_smudge(&String::from_utf8(cleaned).unwrap())
        .unwrap();
    assert_eq!(restored, content, "PEM round-trip must be byte-exact");
}

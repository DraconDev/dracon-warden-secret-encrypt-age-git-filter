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
    for ordinary in ["ta[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB1eDhjUlNPZUhFL3Y3SjdXR2RUd2EyZmdpWWJUWUZVeDlBc0I2c3VsZkcwClpnaFdsWWpteVBMcFpQbC9id2V6OWM1TVMzWmRUUFpEUzNxNVBaQjRxdHcKLT4gWDI1NTE5IGt3YWRieTZ6QTVNdWZMWDBkdUxNK2E5MGEyU1JzeDY1c05OdlczVEZ4U3cKWEMxTENJRFVCUDB3ZndkT1c2bEJKMXpjY3ZYMGMxYWpOYWI4QjFxdk13ZwotPiBYMjU1MTkgcmVTL3dIYk9xaGIxVGpUSFNsN2tIa3pGUVRLZDVCQmZWZFBUL1BXS05ESQpMUFpQKy9HSW04TjluZlpXUlJ2ZWUzZTJNY2gyVmFUOGxjc0x3Zm8yZlgwCi0+IFgyNTUxOSBDMTBJYTIyNHg1Wms3Tnc5SlFYeG96ajZqb0dMZ1AvOVVSanZYMWpDSkRnCnVxbkNQa3Z4MFo1MW8vbU5qN3JHYUlYYjZMZG1tcjYxZ1dTdlp5Y2lySFEKLT4gWDI1NTE5IHR3SGN6ZFExQ0ZIYXBmQllzVjdtVU85RCtOUW84RXNpMFQvSVNEUFBaR28KZk13SG9QQzI3VG91YXNQblBVaWcxaS8vOXY5M3hOTy9GYnhSenZHREZNOAotPiAsdXAtZ3JlYXNlCmhhTHZJRHlWOHNVaElpb3Z4a3NlZERoQWpnbVE0Y2JiYTcvNzlidU1hdFFoUkJzejd2S1luQlF6ZHprOWhRdzQKCi0tLSBUV1MxODhxemVRUkMvVlFna2R1WnhRN1dDM25mZWJ1QzlpbkZDaXZkNlBBCmc/xPOhBi9nulDl9QejLsWbcj2yxq8u03aZOHTDodxjczzfLNDTHghEcDQiyv3Tv5SjhPcDu28VuHRXo+g9YLI=]", "ma[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBwUHNFaGtqeURsUTNpQlF4L254NUxCUnMxaHFiYTBPL2dnWHZiVldMbENjCk1VMFNHVzRuU1UrY1o0aDJLM0NQSkZNdFE1UzRlRnM0dXRoTUxxZ09URTQKLT4gWDI1NTE5IHluVjV5VkdaUW1HRkJOMmJadEhTTHBCT0NEWjBrZVhiRDkyM0JtZUVJU1kKMzR5RmRLRkV2MkJIMm13RHlxWVdOVkRQQ3hOM2ZjNzV5SVF3QXA0RGo1VQotPiBYMjU1MTkgSE5aSUNXSERTaWd2TWg2SzNWQnRVMFE4KzZuY2JEZzZJaVFQSVQvV2NFRQpHTzY0a3orLzJHeUp0a1M0Qm5KQWEwWGsrZ3FtMERlY0FobXYxeUlUZS9vCi0+IFgyNTUxOSArVi9mL01idTBHT2Q3aWlzb3MrNVkrY044dmlvQkd2TC9NcHBYUVAwRFRjCjFSZDlFaEQvN3hIUGQrckZ2dDc2QmQvM2RyWXBYNUhWaXdMVU5lU1pxYmMKLT4gWDI1NTE5IHY3Q1RodTFleGF4NHNiazVIaERzQjFSTG1ETGw3d1RSOHBzaXlUZnlxeDAKc3hxclZBOUJKcUhVMzl2TTlaamtpc2hwNkc3V1hxM3RORkdkRWhsS3ljSQotPiBrZCstZ3JlYXNlIEVoCkpTbkxjdwotLS0gdkZlTlJWYTlYdUUyaVdQV3FKZmt1WWpBRFplMjRTOXg1aWRvbWtjamQxWQq4jxxH98E8uJNWuYsKwU2ap1CEIkEvatj/EWqAO8eXZSPEzTKCg14CFUxVjOYBf4tsxWfsjZUxJQv6fclfWCXn]", "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBZZGhiY0lWSFFQbkV6b0hXRFBvSFc2bDIwUXlrc3FEZFlLamZCL2lEL21zCm9OdHphcmxzYlhJS2VRYzZJanJXZENPNFl2TGY3Q0tOOFJITHQzVzdOa3cKLT4gWDI1NTE5IHU1SFZwSkJwZUpUTVdhbFdlQmNKV2VLYU1GR0JaUW1QeFFvSTRBTFJ4ekEKZjVqOU5qUzJPNFZEWEhMeGJSNWZnZi9xM21JcytVcEpVOXFFSFdKSGlPYwotPiBYMjU1MTkgSDJEM3BpZitIOWhCeFZ5ODFUdFZraExha3JkT0dXby92MDUveDVhaDRSNApuOTBxMWFiZEg0NEJJYnFDSUhXUDFQakdUbmJhcmwzWU4xaEZtRFp1TUVBCi0+IFgyNTUxOSBwTHNya3M1THl0UjVoK3I4QmNJazRTVFd2UEhxVEV0NzVyUXloYTI4NVdRCk5nRU1LcTJvWlVrSHZydzdxWUpYTGVGOXh2eG5Nd0hyQWptcDBCYmhLa1EKLT4gWDI1NTE5IEtwdkRBdUZzMU1LYm80TWFTK0xIakRZMGhYREMzMnNJRTZMQzlJQTUrQW8KWWR1bTBwZkNhbEtMamlUM0owYTZtOTBBVFRxMi9iM0c5dUd0RGxtMWc4VQotPiAiRnFaKlZ1LWdyZWFzZSAxT2p+WD4KVXNQZStaRlRMWS9GYjVCWEVsMUtqd3ZNNFVIZUVlQWpIOVZSbUZod0YrM1RQTzN2S2xSbG1zdm1zYVlXZTlLRApGbnVQNnhrMnAzWVpHRDMyYWlzNlV3RkoKLS0tIEsrSXU5UVRZc2JBNG10WWFBNHhnMHlNQ3FDTy9mOXNNY1F3ZlZSckRPa2cKI3Ac5Svg9dWkZRZwolZ/DQ9QZo3bRy3C2RV+1/CUt8KDg2vl7UjVxJ57IKh8XtIjk3+zlgJlispJXR0eB/m9Mw==]"] {
        assert!(scanner.scan(ordinary).is_empty(), "ordinary slug matched");
    }
    let security = tier1_security();
    for prefix in ["sk-", "sk-proj-", "sk-svcacct-"] {
        let token = format!("{prefix}{}", "A1".repeat(24));
        let input = format!("const value = \"{token}\";\r\n");
        let cleaned = security.smart_clean_with_path(input.as_bytes(), "src/main.rs").unwrap();
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
        inputs.push(format!("{dashes}BEGIN {label}{dashes}\nMIIExampleBody\n{dashes}END {label}{dashes}"));
    }
    inputs.push(format!("{}{}{}", "AI", "za", "A1_".repeat(11) + "Z-"));
    for token in inputs {
        let input = format!("/* {token} */\n");
        let cleaned = String::from_utf8(security.smart_clean_with_path(input.as_bytes(), "src/main.rs").unwrap()).unwrap();
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

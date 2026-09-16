use dracon_security::SecretScanner;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn inventory_covers_every_builtin_family_and_tier() {
    let doc = include_str!("../token-tier-inventory.md");
    let rows: BTreeMap<&str, &str> = doc
        .lines()
        .filter_map(|line| {
            let cells: Vec<_> = line.split('|').map(str::trim).collect();
            (cells.len() == 5 && matches!(cells[2], "1" | "2")).then(|| (cells[1], cells[2]))
        })
        .collect();
    let full = SecretScanner::get_patterns();
    let all: BTreeSet<_> = full.iter().map(|(n, _)| *n).collect();
    assert_eq!(rows.keys().copied().collect::<BTreeSet<_>>(), all);
    let tier1 = SecretScanner::tier1_patterns();
    let tier1: BTreeSet<_> = tier1.iter().map(|(n, _)| *n).collect();
    for (name, tier) in rows {
        assert_eq!(
            tier == "1",
            tier1.contains(name),
            "wrong inventory tier: {name}"
        );
    }
}

#[test]
fn promoted_provider_tokens_replace_completely() {
    let scanner = SecretScanner::new_tier1().unwrap();
    let cases = [
        (
            "OpenRouter API Key",
            format!("sk-or-v1-{}", "ab".repeat(32)),
        ),
        ("Groq API Key", format!("gsk_{}", "A".repeat(52))),
        (
            "Resend API Key",
            format!("re_{}_{}", "A".repeat(8), "B".repeat(24)),
        ),
        // Overlong bodies must not match (full adjacent boundaries required).
        (
            "OpenRouter Overlong",
            format!("sk-or-v1-{}", "ab".repeat(33)),
        ),
        ("Groq Overlong", format!("gsk_{}", "A".repeat(53))),
        (
            "Resend Overlong",
            format!("re_{}_{}", "A".repeat(9), "B".repeat(24)),
        ),
        (
            "Google Client Secret",
            format!("{}{}", "GOCSPX-", "A1_".repeat(10) + "-"),
        ),
        (
            "DigitalOcean Token",
            format!("{}{}", concat!("dop", "_v1_"), "ab".repeat(32)),
        ),
        (
            "Shopify Token",
            format!("{}{}", concat!("sh", "pat_"), "ab".repeat(16)),
        ),
        ("Shopify Secret", format!("{}{}", "shpss_", "ab".repeat(16))),
        (
            "Square Access Token",
            format!("{}{}-", concat!("sq", "0atp-"), "A".repeat(21)),
        ),
        (
            "Square OAuth Secret",
            format!("{}{}-", concat!("sq", "0csp-"), "A".repeat(42)),
        ),
        (
            "HashiCorp Vault Token",
            format!("{}{}-", "hvs.", "A".repeat(24)),
        ),
        (
            "AWS MWS Key",
            format!("{}{}", "amzn.mws.", "01234567-89ab-cdef-0123-456789abcdef"),
        ),
    ];
    for (name, token) in cases {
        let input = format!("\"{token}\",\"{token}\"");
        if name.ends_with("Overlong") {
            assert!(scanner.scan(&input).is_empty(), "{name} must not match");
            assert_eq!(
                scanner.scan_and_replace(&input, |_, _| "BAD".to_string()),
                input,
                "{name} must not replace"
            );
            continue;
        }
        let replaced = scanner.scan_and_replace(&input, |found_name, found| {
            assert_eq!(found_name, name);
            assert_eq!(found, token);
            "REPLACED".to_string()
        });
        assert_eq!(replaced, "\"REPLACED\",\"REPLACED\"", "{name}");
        let embedded = format!("prefix{token}suffix");
        assert!(scanner.scan(&embedded).is_empty(), "embedded token: {name}");
        assert_eq!(
            scanner.scan_and_replace(&embedded, |_, _| "BAD".to_string()),
            embedded
        );
    }
}

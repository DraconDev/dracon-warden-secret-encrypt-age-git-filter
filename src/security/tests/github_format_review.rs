//! Synthetic vectors derived from GitHub's 2021 format article and the
//! TruffleHog github/v2 detector. These are not issued credentials.
use dracon_security::SecretScanner;

#[test]
fn github_supported_formats_are_replaced_in_full() {
    let scanner = SecretScanner::new_tier1().unwrap();
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
        for size in [36, 41, 76, 82, 255] {
            let token = format!("{prefix}{}", "A".repeat(size));
            let input = format!("\"{token}\",\"{token}\"");
            let replaced = scanner.scan_and_replace(&input, |_, found| {
                assert_eq!(found, token, "must not encrypt just a token prefix");
                "REPLACED".into()
            });
            assert_eq!(replaced, "\"REPLACED\",\"REPLACED\"", "{prefix}/{size}");
        }
    }
}

#[test]
fn github_invalid_boundaries_and_lengths_do_not_match() {
    let scanner = SecretScanner::new_tier1().unwrap();
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
        for size in [0, 29, 35, 256] {
            let input = format!("\"{prefix}{}\"", "A".repeat(size));
            assert!(scanner.scan(&input).is_empty(), "{prefix}/{size}");
            assert_eq!(scanner.scan_and_replace(&input, |_, _| "BAD".into()), input);
        }
        let embedded = format!("prefix{prefix}{}", "A".repeat(36));
        assert!(scanner.scan(&embedded).is_empty());
    }
}

use dracon_security::SecretScanner;
use regex::Regex;

#[test]
fn test_patterns_compile_and_have_reasonable_length() {
    let patterns = SecretScanner::get_patterns();

    for (name, pattern) in patterns {
        assert!(
            Regex::new(pattern).is_ok(),
            "Pattern '{}' failed to compile: {}",
            name,
            pattern
        );
        assert!(
            pattern.len() <= 300,
            "Pattern '{}' is {} chars (limit 300)",
            name,
            pattern.len()
        );
    }
}

#[test]
fn test_no_nested_quantifiers_in_patterns() {
    let patterns = SecretScanner::get_patterns();
    let nested_signatures = ["(a+)+", "(a*)+", "(a+)*", "(a*)*", "{20,}{20,}"];

    for (name, pattern) in patterns {
        for sig in &nested_signatures {
            assert!(
                !pattern.contains(sig),
                "Pattern '{}' contains nested quantifier '{}'",
                name,
                sig
            );
        }
    }
}

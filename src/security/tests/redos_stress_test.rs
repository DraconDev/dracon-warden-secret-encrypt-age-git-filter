use dracon_security::SecretScanner;
use std::time::Duration;

#[test]
fn test_azure_sas_pattern_completes_in_reasonable_time() {
    let scanner = SecretScanner::new().unwrap();
    let input = "sv=2019-02-02&sig=abc123def456".to_string();

    let now = std::time::Instant::now();
    let _result = scanner.scan_and_replace(&input, |_, _| "[REDACTED]".to_string());
    let elapsed = now.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "Azure SAS scan took {:?}, should be < 1s",
        elapsed
    );
}

#[test]
fn test_generic_assignment_pattern_completes_in_reasonable_time() {
    let scanner = SecretScanner::new().unwrap();
    let input = "MY_API_KEY=abcdefghij1234567890abcdef".to_string();

    let now = std::time::Instant::now();
    let _result = scanner.scan_and_replace(&input, |_, _| "[REDACTED]".to_string());
    let elapsed = now.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "assignment scan took {:?}, should be < 1s",
        elapsed
    );
}

#[test]
fn test_scanner_performance_under_large_evil_input() {
    let scanner = SecretScanner::new().unwrap();
    let evil = "x".repeat(10_000);

    let now = std::time::Instant::now();
    let result = scanner.scan_and_replace(&evil, |_, _| "[REDACTED]".to_string());
    let elapsed = now.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "10k-char evil input took {:?}, should be < 5s",
        elapsed
    );
    assert!(
        result.len() == evil.len(),
        "output should not explode on non-matching evil input"
    );
}

#[test]
fn test_scanner_performance_mixed_secret_and_filler() {
    let scanner = SecretScanner::new().unwrap();
    let secret = "API_KEY=super_secret_value_12345";
    let filler = "x".repeat(5_000);
    let input = format!("{}\n{}\n{}", filler, secret, filler);

    let now = std::time::Instant::now();
    let result = scanner.scan_and_replace(&input, |_, _| "[REDACTED]".to_string());
    let elapsed = now.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "mixed secret+filler scan took {:?}, should be < 5s",
        elapsed
    );
    assert!(
        result.contains("[REDACTED]"),
        "secret should still be detected amid filler"
    );
}

#[test]
fn test_nested_quantifier_patterns_do_not_cause_exponential_blowup() {
    let scanner = SecretScanner::new().unwrap();
    let input = "xx".to_string() + &"a".repeat(50);

    let now = std::time::Instant::now();
    let result = scanner.scan_and_replace(&input, |_name, _found| "[REDACTED]".to_string());
    let elapsed = now.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "nested quantifier pattern took {:?}, should be < 2s",
        elapsed
    );
    assert!(result.len() == input.len(), "output should not explode");
}

#[test]
fn test_scanner_detects_known_secret_patterns() {
    let scanner = SecretScanner::new().unwrap();

    let test_cases = vec![
        concat!("gh", "p_1234567890abcdef1234567890abcdef1234"),
        concat!("sk", "_live_51ABCDEF1234567890abcdef1234567890abcdef123"),
        concat!("AK", "IAIOSFODNN7EXAMPLE"),
        concat!("xox", "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
        concat!("AI", "zaSyD-1234567890abcdef1234567890abcde"),
        concat!("ya", "29.a0AfH6SMC_1234567890abcdef1234567890abcdef1234567890"),
        "aws_session_token = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890/+=abcdef",
        concat!("LT", "AI1234567890abcdef1234"),
        concat!("sk", "_test_abcdefghijklmnopqrstuvwx123456"),
        concat!("oc", "id1.user.oc1.test.abcdef1234567890abcdef1234567890abcdef1234"),
    ];

    for secret in test_cases {
        let result =
            scanner.scan_and_replace(secret, |name, found| format!("[{}:{}]", name, found));
        assert!(
            result.contains("["),
            "secret '{}' should be detected, got: {}",
            secret,
            result
        );
    }
}

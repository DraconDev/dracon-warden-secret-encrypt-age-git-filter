use dracon_security::SecretScanner;
use std::time::Duration;

#[test]
fn test_azure_sas_scan() {
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
    let input = "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOR004TVpHanNUVGRuYnN0ZWd1alNsS00zN21QTG1MQTFhaURRdnNGeW0wCmtBMStEOVBzRk9LSnE1WVB0WFJXVkdIZkRmTmRGWXVvZE1xOW5vUFlQc1kKLT4gWDI1NTE5IEVBeTFMU0tTUEVsVHA0VUM3dVpqSncza1ZhdEhNWXhQbzNZakJBWWJkanMKaDFnTksrSUdVWVRGajhCcWtZdXlGTm9wU0w2bkY3c0ZOQVppU1hER3R2awotPiBYMjU1MTkgYjVtUHEra01HelR5Y093MW1YVFhCR3hLc2RjWUZoZ2xsbUVmRG1Sd1dnbwo3OTJwN0VjTmdDUTFXaDd5cTJLY01KcVdWMnduUC92TE9ZNUhuZkRZMTVvCi0+IFgyNTUxOSAxUWV5RmFpSVlKcW9jREZoMEdKcDJCa1FtUE5oMlFSa0V1VCtna3hKODJBCk82STN2eXdnalJBcnpSMTQvWU1JSlJzL0Q0R25LOVlUN3g4T2VZUnNXaTAKLT4gWDI1NTE5IDFyL0svd2dVOUl6d3F1dVhzcldoUEdvTnJ0ampBQzhOZHRJaStnNFB0MXMKTUlVbzc4UnMxM0lROTdrNWtxaTZUcm9TOVBVYStMTC92aHFheGhqUVh6ZwotPiBHYGpGYktYLWdyZWFzZSBOam89IGUgImRMClI3djFzbFBUejFuSjljaURhUStwdVZZCi0tLSBTaEtkQi8wNFByU2Y0RWtmWi9xTUI1R1lQcmNkYWQ5bGtrMlZCT0tleVhNCszf5J1vIcepvlepxmmwclip4fBV9FHvjnb36FDuzuIjLYYbVvO5vwq69KAJh7DZuEEUubWaL1y1OAEG4QAKl4fWxGnEwQ==]".to_string();

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
    let secret = "AKIAIOSFODNN7EXAMPLE".to_string();
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
        "[DRACON_SECRET:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA3anp0cE40ekVudk9SZ3ZINmR1ekVIV1owSC82aDhhL3U0Q2ROeVNVK0dvCjRhR3lMU2pINWpOaVVKdmhrcm5McFNvczBUSlVabUpiZTRIS211MnN4bjAKLT4gWDI1NTE5IDVrdVROQXJPNVhMei9Ka2cvNmdVNkltdFNFV0IrUlptbjdxdFJsZU5KU28KVjRNR1JiK1VyZW5lbGtYZnZqWDdFSlFmODFDRzMyY1VMQTBBYUYrZDJPRQotPiBYMjU1MTkgTkoyQXJhMmlvb0F3WUlPTGU4OTVQenhwR1FKZnM2cy93czFEY0o5U2JpawpncjNMQmRtTVRrdmJjT2JRYXFFUVB4bnIvZmloNTA4TTgyY0xpZ3Q1WW5nCi0+IFgyNTUxOSBVdmhiZXZ4T1hzZ0lRSmZqQVliWkxjZlJVVGdnK1dvcFgvVjduK1JsYlZJCkxETFh0VSsrQlpmSHY0eGM5RitOK1M2cHloYWZ4a2thdTdWQytPcHZOZGMKLT4gWDI1NTE5IEs5dVZGQVVqS2h2ZW40aVZMODNPcWNrYk9HdVhsdkRpUXQzc3ZqaEJHREEKTWFId3doaE1Pcnc0MUxqcGNnamIxcC9IbWEvdTZOZ3VCVTNEZFRmYjB2TQotPiBvcW55YH1ALWdyZWFzZSAnQyBZTmB9XlQ8MCAxT1NTCk9jOHhyWUNCeE1XNlBuQW9DTTBJNmJuRDJ1ZTRoTG1WYmZCN3JSTXZYbzdwT1o1aEs1MEw0MW54bEtNN3hveUoKSklQZEtoaUIyZGRWaHhjQQotLS0gSWVXWlJsMjRVUlNCRlRndHpLYkhQT0xtYXJEcVJFTHhQOVQyVS92eEFtMAoP5QAc5PGSePBcetZlRZbXWqvm/VT8GR8FOGZhQ4vJKV2wNU8aSW1exsguojKXqrN9okbwTpzHpUBxqarlrwkX7g9ItzFwne16ripCWToeTvur+DFwZ0zbn14tT673jXd0Med4WPS1SUgKy5O7EpGizEbPL51+m5WyroA=]",
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

use dracon_security::SecretScanner;

#[test]
fn test_scanner_stress_1000() {
    let scanner = SecretScanner::new().unwrap();
    let clean_content = "fn main() { println!(\"Hello, world!\"); }";
    let secret_content = "let api_key = \"AKIAIOSFODNN7EXAMPLE\";";

    for i in 0..1000 {
        let findings = scanner.scan(clean_content);
        assert!(
            findings.is_empty(),
            "Clean content should have no findings at iteration {}",
            i
        );

        let findings = scanner.scan(secret_content);
        assert!(
            !findings.is_empty(),
            "Secret content should have findings at iteration {}",
            i
        );
    }
}

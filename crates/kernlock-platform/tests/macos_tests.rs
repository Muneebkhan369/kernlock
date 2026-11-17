use kernlock_core::SecurityMode;
use kernlock_platform::{
    macos::{
        EndpointSecurityClient, EsAuthExecEvent, EsProcessInfo, MacOsSecurityProvider,
        ES_AUTH_RESULT_ALLOW, ES_AUTH_RESULT_DENY, ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
    },
    PlatformSecurityProvider,
};

#[test]
fn test_macos_provider_never_claims_kernel_blocking_without_system_extension() {
    let provider = MacOsSecurityProvider::new();

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
        assert!(fallback.contains("Endpoint Security"));
        assert!(fallback.contains("unavailable"));

        // Verify capability statuses
        let esf_cap = caps
            .capabilities
            .iter()
            .find(|c| c.name.contains("Endpoint Security"))
            .expect("Endpoint Security capability must exist");
        assert!(!esf_cap.supported);
        assert!(!esf_cap.enforcement_available);
        assert!(esf_cap.active_mode.contains("Unavailable"));
    }
}

#[test]
fn test_macos_endpoint_security_verdict_evaluation() {
    let client = EndpointSecurityClient::new();

    let event = EsAuthExecEvent {
        message_id: 2002,
        target_executable: "/tmp/suspicious_script.sh".to_string(),
        arguments: vec!["/tmp/suspicious_script.sh".to_string()],
        process: EsProcessInfo {
            pid: 501,
            ppid: 1,
            uid: 501,
            gid: 20,
            executable_path: "/bin/bash".to_string(),
            cdhash: None,
            team_id: None,
            signing_id: None,
            is_platform_binary: false,
        },
        deadline_seconds: 5,
    };

    // Protection mode + threat detected -> Deny execution, do not cache
    let threat_resp = client.evaluate_auth_exec(&event, SecurityMode::Protection, true);
    assert_eq!(threat_resp.message_id, 2002);
    assert_eq!(threat_resp.result, ES_AUTH_RESULT_DENY);
    assert!(!threat_resp.cache);

    // Protection mode + clean file -> Allow execution, cache decision
    let clean_resp = client.evaluate_auth_exec(&event, SecurityMode::Protection, false);
    assert_eq!(clean_resp.message_id, 2002);
    assert_eq!(clean_resp.result, ES_AUTH_RESULT_ALLOW);
    assert!(clean_resp.cache);

    // Audit mode + threat detected -> Allow execution (Audit only), do not cache
    let audit_resp = client.evaluate_auth_exec(&event, SecurityMode::Audit, true);
    assert_eq!(audit_resp.message_id, 2002);
    assert_eq!(audit_resp.result, ES_AUTH_RESULT_ALLOW);
    assert!(!audit_resp.cache);

    // Verify constants
    assert_eq!(ES_EVENT_TYPE_AUTH_EXEC, 0);
    assert_eq!(ES_EVENT_TYPE_AUTH_OPEN, 1);
    assert_eq!(ES_AUTH_RESULT_ALLOW, 0);
    assert_eq!(ES_AUTH_RESULT_DENY, 1);
}

#[test]
fn test_macos_native_client_health_integration() {
    use kernlock_platform::macos::EndpointSecurityStatus;

    let client = EndpointSecurityClient::new();
    assert_eq!(client.probe_status(), EndpointSecurityStatus::NotInstalled);
    assert!(!client.is_active());

    // Native client reports AwaitingApproval
    client.record_native_heartbeat(12345, EndpointSecurityStatus::AwaitingApproval);
    assert_eq!(
        client.probe_status(),
        EndpointSecurityStatus::AwaitingApproval
    );
    assert!(!client.is_active());

    // Native client successfully authorized by user/MDM and actively monitoring
    client.record_native_heartbeat(12345, EndpointSecurityStatus::Active);
    assert_eq!(client.probe_status(), EndpointSecurityStatus::Active);
    assert!(client.is_active());

    // Native client encounters a fatal error or revocation
    client.record_native_heartbeat(12345, EndpointSecurityStatus::Failed);
    assert_eq!(client.probe_status(), EndpointSecurityStatus::Failed);
    assert!(!client.is_active());
}

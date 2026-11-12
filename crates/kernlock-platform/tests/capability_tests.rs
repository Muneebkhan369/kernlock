use kernlock_core::{PolicyConfig, RuleEngine, SecurityMode};
use kernlock_platform::linux::LinuxSecurityProvider;
use kernlock_platform::macos::MacOsSecurityProvider;
use kernlock_platform::windows::WindowsSecurityProvider;
use kernlock_platform::{PlatformError, PlatformSecurityProvider};

#[test]
fn linux_never_claims_kernel_blocking_when_unimplemented() {
    let provider = LinuxSecurityProvider::new();
    for mode in [
        SecurityMode::Audit,
        SecurityMode::Protection,
        SecurityMode::Strict,
    ] {
        let caps = provider.probe_capabilities(mode);
        assert!(
            !caps.kernel_blocking_available,
            "kernel_blocking_available must be false until FAN_OPEN_PERM loop is implemented"
        );
        let fanotify_cap = caps
            .capabilities
            .iter()
            .find(|c| c.name.contains("fanotify"))
            .expect("fanotify capability entry must exist");
        assert!(!fanotify_cap.enforcement_available);
        if mode != SecurityMode::Audit {
            assert!(caps.fallback_reason.is_some());
        }
    }
}

#[test]
fn windows_and_macos_report_unsupported_instead_of_empty_clean() {
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();

    let win = WindowsSecurityProvider::new();
    let win_caps = win.probe_capabilities(SecurityMode::Strict);
    assert!(!win_caps.kernel_blocking_available);
    assert!(!win_caps.auto_quarantine_available);
    assert_eq!(win_caps.active_mode, SecurityMode::Audit);
    assert!(matches!(
        win.list_processes(&rules, &policy),
        Err(PlatformError::Unsupported(_))
    ));
    assert!(matches!(
        win.scan_persistence(&rules),
        Err(PlatformError::Unsupported(_))
    ));

    let mac = MacOsSecurityProvider::new();
    let mac_caps = mac.probe_capabilities(SecurityMode::Protection);
    assert!(!mac_caps.kernel_blocking_available);
    assert!(!mac_caps.auto_quarantine_available);
    assert_eq!(mac_caps.active_mode, SecurityMode::Audit);
    assert!(matches!(
        mac.list_processes(&rules, &policy),
        Err(PlatformError::Unsupported(_))
    ));
    assert!(matches!(
        mac.scan_persistence(&rules),
        Err(PlatformError::Unsupported(_))
    ));
}

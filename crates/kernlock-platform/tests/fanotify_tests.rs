use kernlock_core::SecurityMode;
use kernlock_platform::fanotify::FanotifyPermissionMonitor;
use kernlock_platform::linux::LinuxSecurityProvider;
use kernlock_platform::PlatformSecurityProvider;

#[test]
fn test_fanotify_support_probe_and_capability_consistency() {
    let supported = FanotifyPermissionMonitor::is_supported();
    let provider = LinuxSecurityProvider::new();
    let caps = provider.probe_capabilities(SecurityMode::Protection);

    assert_eq!(
        caps.kernel_blocking_available, supported,
        "kernel_blocking_available must match actual fanotify probe status"
    );

    let fanotify_status = caps
        .capabilities
        .iter()
        .find(|c| c.name.contains("fanotify"))
        .expect("fanotify capability status must exist");

    assert_eq!(fanotify_status.supported, supported);
    assert_eq!(fanotify_status.enforcement_available, supported);

    if !supported {
        assert!(caps.fallback_reason.is_some());
        let init_res = FanotifyPermissionMonitor::init();
        assert!(init_res.is_err());
    }
}

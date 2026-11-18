use kernlock_core::{PolicyConfig, SecurityMode};
use kernlock_daemon::engine::KernLockEngine;
use kernlock_platform::fanotify::{FanotifyMonitorHealth, FanotifyPermissionMonitor};
use tempfile::TempDir;

#[test]
fn test_protection_state_uninitialized_behavior() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    let (protection_state, monitor_health, reason) = engine.get_protection_state();
    // When monitor is uninitialized or absent
    assert!(
        protection_state == "Unavailable" || protection_state == "Degraded",
        "Expected Unavailable or Degraded for uninitialized, got {}",
        protection_state
    );
    assert_ne!(protection_state, "Active");
    assert!(
        monitor_health == "Unavailable"
            || monitor_health == "Uninitialized"
            || monitor_health == "Standby",
        "Got unexpected monitor health: {}",
        monitor_health
    );
    assert!(reason.is_some());
}

#[test]
fn test_protection_state_running_in_protection_and_strict_modes() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    let monitor = FanotifyPermissionMonitor::new_mock(FanotifyMonitorHealth::Running, true);
    engine.inject_fanotify_monitor_for_testing(monitor);

    // 1. Protection mode -> Active
    let policy = PolicyConfig {
        mode: SecurityMode::Protection,
        ..Default::default()
    };
    engine.update_policy(policy).unwrap();

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Active");
        assert_eq!(health, "Running");
        assert!(reason.unwrap().contains("enforcing"));
    }

    // 2. Strict mode -> Active
    let policy_strict = PolicyConfig {
        mode: SecurityMode::Strict,
        ..Default::default()
    };
    engine.update_policy(policy_strict).unwrap();

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Active");
        assert_eq!(health, "Running");
        assert!(reason.unwrap().contains("enforcing"));
    }
}

#[test]
fn test_protection_state_running_in_audit_mode() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    let monitor = FanotifyPermissionMonitor::new_mock(FanotifyMonitorHealth::Running, true);
    engine.inject_fanotify_monitor_for_testing(monitor);

    let policy = PolicyConfig {
        mode: SecurityMode::Audit,
        ..Default::default()
    };
    engine.update_policy(policy).unwrap();

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Degraded");
        assert_eq!(health, "Running");
        assert!(reason.unwrap().contains("Audit Mode active"));
    }
}

#[test]
fn test_protection_state_degraded_queue_overflow_never_shows_active() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    // Simulate kernel event queue overflow: monitor thread is running, but health is Degraded
    let monitor = FanotifyPermissionMonitor::new_mock(FanotifyMonitorHealth::Degraded, true);
    engine.inject_fanotify_monitor_for_testing(monitor);

    // Even in Strict mode, queue overflow must NEVER report Active
    let policy = PolicyConfig {
        mode: SecurityMode::Strict,
        ..Default::default()
    };
    engine.update_policy(policy).unwrap();

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Degraded");
        assert_eq!(health, "Degraded");
        assert_ne!(state, "Active", "Queue overflow must never show Active!");
        assert!(reason.unwrap().contains("overflowed"));
    }
}

#[test]
fn test_protection_state_failed_on_fatal_error() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    let monitor = FanotifyPermissionMonitor::new_mock(FanotifyMonitorHealth::Failed, false);
    engine.inject_fanotify_monitor_for_testing(monitor);

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Failed");
        assert_eq!(health, "Failed");
        assert!(reason.unwrap().contains("fatal runtime error"));
    }
}

#[test]
fn test_protection_state_stopped() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();

    let monitor = FanotifyPermissionMonitor::new_mock(FanotifyMonitorHealth::Stopped, false);
    engine.inject_fanotify_monitor_for_testing(monitor);

    #[cfg(target_os = "linux")]
    {
        let (state, health, reason) = engine.get_protection_state();
        assert_eq!(state, "Degraded");
        assert_eq!(health, "Stopped");
        assert!(reason.unwrap().contains("stopped"));
    }
}

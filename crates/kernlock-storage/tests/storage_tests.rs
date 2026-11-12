use chrono::Utc;
use kernlock_core::{
    AlertStatus, DetectionConfidence, EventCategory, FileScanResult, PolicyConfig,
    QuarantineRecord, QuarantineStatus, ScanJobSummary, ScanMode, ScanStatus, SecurityEvent,
    SecurityMode, Severity, ThreatAlert, ThreatRecord,
};
use kernlock_storage::Storage;
use uuid::Uuid;

#[test]
fn test_events_and_alerts_storage() {
    let storage = Storage::open_in_memory().expect("open memory db");

    let event_id = Uuid::new_v4();
    let event = SecurityEvent {
        id: event_id,
        timestamp: Utc::now(),
        category: EventCategory::Process,
        severity: Severity::High,
        title: "Malicious process execution blocked".to_string(),
        description: "Process attempted to execute suspicious binary".to_string(),
        target: "/tmp/evil.sh".to_string(),
        risk_score: 90,
        action_taken: "Blocked".to_string(),
        rule_ids: vec!["KL-PROC-REV-SHELL".to_string()],
        metadata: serde_json::json!({"pid": 1337}),
    };

    storage.insert_event(&event).expect("insert event");
    let events = storage.list_events(10).expect("list events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, event_id);
    assert_eq!(events[0].target, "/tmp/evil.sh");

    let alert_id = Uuid::new_v4();
    let alert = ThreatAlert {
        id: alert_id,
        event_id,
        timestamp: Utc::now(),
        severity: Severity::High,
        title: "High severity execution alert".to_string(),
        explanation: "Threat reverse shell was detected and blocked".to_string(),
        target: "/tmp/evil.sh".to_string(),
        risk_score: 90,
        status: AlertStatus::Open,
        recommended_action: "Quarantine file and inspect cron".to_string(),
    };

    storage.insert_alert(&alert).expect("insert alert");
    let alerts = storage.list_alerts(10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].id, alert_id);

    storage
        .update_alert_status(alert_id, AlertStatus::Resolved)
        .expect("update alert status");
    let updated_alerts = storage.list_alerts(10).expect("list alerts");
    assert_eq!(updated_alerts[0].status, AlertStatus::Resolved);
}

#[test]
fn test_policy_storage() {
    let storage = Storage::open_in_memory().expect("open memory db");
    let default_policy = storage.get_policy().expect("get default policy");
    assert_eq!(default_policy.mode, SecurityMode::Audit);

    let mut custom_policy = PolicyConfig {
        mode: SecurityMode::Strict,
        auto_quarantine_threshold: 95,
        ..Default::default()
    };
    custom_policy
        .excluded_paths
        .push("/var/log/syslog".to_string());

    storage.save_policy(&custom_policy).expect("save policy");
    let loaded_policy = storage.get_policy().expect("get policy");
    assert_eq!(loaded_policy.mode, SecurityMode::Strict);
    assert_eq!(loaded_policy.auto_quarantine_threshold, 95);
    assert_eq!(loaded_policy.excluded_paths, vec!["/var/log/syslog"]);
}

#[test]
fn test_quarantine_records_storage() {
    let storage = Storage::open_in_memory().expect("open memory db");
    let q_id = Uuid::new_v4();
    let rec = QuarantineRecord {
        id: q_id,
        original_path: "/home/user/malware.bin".to_string(),
        vault_path: "/var/lib/kernlock/vault/abc".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        original_mode: 0o755,
        size_bytes: 4096,
        reason: "EICAR test detection".to_string(),
        quarantined_at: Utc::now(),
        restored_at: None,
        status: QuarantineStatus::Quarantined,
    };

    storage.insert_quarantine(&rec).expect("insert quarantine");
    let fetched = storage.get_quarantine(q_id).expect("get quarantine");
    assert_eq!(fetched.original_path, "/home/user/malware.bin");
    assert_eq!(fetched.status, QuarantineStatus::Quarantined);

    let transitioned = storage
        .transition_quarantine_status(
            q_id,
            QuarantineStatus::Quarantined,
            QuarantineStatus::Restoring,
            None,
        )
        .expect("transition");
    assert!(transitioned);

    let fetched2 = storage.get_quarantine(q_id).expect("get quarantine");
    assert_eq!(fetched2.status, QuarantineStatus::Restoring);
}

#[test]
fn test_scan_jobs_storage() {
    let storage = Storage::open_in_memory().expect("open memory db");
    let job_id = Uuid::new_v4();
    let mut job = ScanJobSummary {
        id: job_id,
        mode: ScanMode::Quick,
        status: ScanStatus::Running,
        started_at: Utc::now(),
        completed_at: None,
        files_scanned: 150,
        files_skipped: 10,
        threats_found: 1,
        errors_count: 0,
        target_paths: vec!["/bin".to_string(), "/usr/bin".to_string()],
        threats: vec![FileScanResult {
            path: "/tmp/eicar.com".to_string(),
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            size_bytes: 68,
            file_type: "text/plain".to_string(),
            entropy: 4.5,
            risk_score: 100,
            severity: Severity::Critical,
            confidence: DetectionConfidence::Certain,
            is_suspicious: true,
            threat_name: Some("EICAR-Standard-AV-Test".to_string()),
            excluded: false,
            matches: vec![],
            summary: "EICAR test string found".to_string(),
            scanned_at: Utc::now(),
        }],
    };

    storage.insert_scan_job(&job).expect("insert scan job");
    let fetched = storage.get_scan_job(job_id).expect("get scan job");
    assert_eq!(fetched.id, job_id);
    assert_eq!(fetched.status, ScanStatus::Running);
    assert_eq!(fetched.files_scanned, 150);
    assert_eq!(fetched.threats.len(), 1);
    assert_eq!(
        fetched.threats[0].threat_name.as_deref(),
        Some("EICAR-Standard-AV-Test")
    );

    job.status = ScanStatus::Completed;
    job.completed_at = Some(Utc::now());
    job.files_scanned = 200;
    storage.update_scan_job(&job).expect("update scan job");

    let updated = storage.get_scan_job(job_id).expect("get updated scan job");
    assert_eq!(updated.status, ScanStatus::Completed);
    assert_eq!(updated.files_scanned, 200);

    let list = storage.list_scan_jobs(10).expect("list scan jobs");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, job_id);
}

#[test]
fn test_threat_history_storage() {
    let storage = Storage::open_in_memory().expect("open memory db");
    let t_id = Uuid::new_v4();
    let q_id = Uuid::new_v4();
    let record = ThreatRecord {
        id: t_id,
        timestamp: Utc::now(),
        threat_name: "ELF.W+X-Segment".to_string(),
        path: "/usr/local/bin/packer_sample".to_string(),
        sha256: "abcdef1234567890".to_string(),
        severity: Severity::High,
        confidence: DetectionConfidence::High,
        risk_score: 85,
        action_taken: "Quarantined".to_string(),
        quarantine_id: Some(q_id),
    };

    storage
        .insert_threat_record(&record)
        .expect("insert threat record");
    let list = storage
        .list_threat_records(10)
        .expect("list threat history");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, t_id);
    assert_eq!(list[0].threat_name, "ELF.W+X-Segment");
    assert_eq!(list[0].action_taken, "Quarantined");
    assert_eq!(list[0].quarantine_id, Some(q_id));
}

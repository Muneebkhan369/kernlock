use kernlock_core::QuarantineStatus;
use kernlock_quarantine::{QuarantineError, QuarantineManager};
use kernlock_storage::Storage;
use std::fs;
use tempfile::TempDir;

#[test]
fn quarantine_and_restore_is_fully_reversible() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let vault_dir = tmp.path().join("vault");
    let sample_file = tmp.path().join("suspicious_fixture.sh");

    let content = b"#!/bin/sh\necho harmless fixture\n";
    fs::write(&sample_file, content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sample_file, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let storage = Storage::open(&db_path).unwrap();
    let qm = QuarantineManager::new(&vault_dir, storage).unwrap();

    // Quarantine
    let rec = qm
        .quarantine_file(&sample_file, "Test fixture quarantine")
        .unwrap();
    assert!(!sample_file.exists(), "Original file must be moved out");
    assert_eq!(rec.status, QuarantineStatus::Quarantined);

    let vault_file = std::path::PathBuf::from(&rec.vault_path);
    assert!(vault_file.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Quarantined file must strip execute bit (0600)");
    }

    // Restore
    let restored = qm.restore_file(rec.id).unwrap();
    assert_eq!(restored.status, QuarantineStatus::Restored);
    assert!(sample_file.exists(), "Restored file must exist at original path");
    assert!(!vault_file.exists(), "Vault copy must be removed after restore");
    assert_eq!(fs::read(&sample_file).unwrap(), content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&sample_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "Original permissions must be restored");
    }
}

#[test]
fn quarantine_refuses_restore_if_destination_already_exists() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let qm = QuarantineManager::new(tmp.path().join("vault"), storage).unwrap();

    let target = tmp.path().join("fixture.txt");
    fs::write(&target, b"original").unwrap();
    let rec = qm.quarantine_file(&target, "test").unwrap();

    // Create conflicting file at original path
    fs::write(&target, b"conflict").unwrap();
    let err = qm.restore_file(rec.id).unwrap_err();
    assert!(matches!(err, QuarantineError::DestinationExists(_)));
}

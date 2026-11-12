use kernlock_core::QuarantineStatus;
use kernlock_quarantine::{FailureInjection, QuarantineError, QuarantineManager};
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
        assert_eq!(
            mode, 0o600,
            "Quarantined file must strip execute bit (0600)"
        );
    }

    let restored = qm.restore_file(rec.id).unwrap();
    assert_eq!(restored.status, QuarantineStatus::Restored);
    assert!(
        sample_file.exists(),
        "Restored file must exist at original path"
    );
    assert!(
        !vault_file.exists(),
        "Vault copy must be removed after restore"
    );
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

    fs::write(&target, b"conflict").unwrap();
    let err = qm.restore_file(rec.id).unwrap_err();
    assert!(matches!(err, QuarantineError::DestinationExists(_)));
}

#[test]
fn quarantine_rolls_back_on_permission_and_db_failures() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("important_user_file.sh");
    let content = b"#!/bin/sh\necho keep me safe\n";
    fs::write(&target, content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o750)).unwrap();
    }

    // 1. Failure at chmod stage
    let err = qm
        .quarantine_file_with_injection(&target, "test", FailureInjection::PermissionChange)
        .unwrap_err();
    assert!(matches!(
        err,
        QuarantineError::RolledBack {
            stage: "vault_chmod",
            ..
        }
    ));
    assert!(target.exists(), "Original file must be rolled back");
    assert_eq!(fs::read(&target).unwrap(), content);
    assert!(qm.list().unwrap().is_empty());

    // 2. Failure at DB insert stage
    let err = qm
        .quarantine_file_with_injection(&target, "test", FailureInjection::DatabaseWrite)
        .unwrap_err();
    assert!(matches!(
        err,
        QuarantineError::RolledBack {
            stage: "database_insert",
            ..
        }
    ));
    assert!(
        target.exists(),
        "Original file must be rolled back on DB failure"
    );
    assert_eq!(fs::read(&target).unwrap(), content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o750,
            "Original permissions must be preserved after rollback"
        );
    }

    // 3. Quarantine succeeds, then restore fails at chmod and DB stages
    let rec = qm.quarantine_file(&target, "legit quarantine").unwrap();
    assert!(!target.exists());

    let err = qm
        .restore_file_with_injection(rec.id, FailureInjection::PermissionChange)
        .unwrap_err();
    assert!(matches!(
        err,
        QuarantineError::RolledBack {
            stage: "restore_chmod",
            ..
        }
    ));
    assert!(!target.exists());
    assert!(std::path::Path::new(&rec.vault_path).exists());

    let err = qm
        .restore_file_with_injection(rec.id, FailureInjection::DatabaseWrite)
        .unwrap_err();
    assert!(matches!(
        err,
        QuarantineError::RolledBack {
            stage: "restore_db_update",
            ..
        }
    ));
    assert!(!target.exists());
    assert!(std::path::Path::new(&rec.vault_path).exists());
}

#[cfg(unix)]
#[test]
fn quarantine_rejects_symlinks_and_files_inside_vault() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage).unwrap();

    let real_file = tmp.path().join("real.txt");
    fs::write(&real_file, b"real").unwrap();
    let link_path = tmp.path().join("link.txt");
    std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

    let err = qm.quarantine_file(&link_path, "symlink").unwrap_err();
    assert!(matches!(err, QuarantineError::SymlinkRejected(_)));
    assert!(real_file.exists());

    let vault_file = vault_dir.join("inside.txt");
    fs::write(&vault_file, b"inside").unwrap();
    let err = qm.quarantine_file(&vault_file, "inside").unwrap_err();
    assert!(matches!(err, QuarantineError::InsideVault(_)));
}

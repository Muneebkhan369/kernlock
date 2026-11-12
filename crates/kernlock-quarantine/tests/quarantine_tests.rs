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

#[test]
fn quarantine_returns_rollback_failed_with_recovery_info() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage).unwrap();

    // 1. Rollback failure during quarantine vault_chmod
    let target1 = tmp.path().join("stranded_chmod.bin");
    fs::write(&target1, b"precious payload").unwrap();
    let err1 = qm
        .quarantine_file_with_injection(
            &target1,
            "test",
            FailureInjection::PermissionChangeAndRollbackMove,
        )
        .unwrap_err();
    match err1 {
        QuarantineError::RollbackFailed(info) => {
            assert_eq!(info.stage, "vault_chmod");
            assert!(info.cause.contains("injected permission failure"));
            assert!(info
                .rollback_error
                .contains("injected rollback move failure"));
            assert_eq!(info.stranded_path, info.vault_path);
            assert!(std::path::Path::new(&info.stranded_path).exists());
            assert!(!info.sha256.is_empty());
            assert!(info.original_path.ends_with("stranded_chmod.bin"));
        }
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }

    // 2. Rollback failure during quarantine database_insert
    let target2 = tmp.path().join("stranded_db.bin");
    fs::write(&target2, b"precious payload 2").unwrap();
    let err2 = qm
        .quarantine_file_with_injection(
            &target2,
            "test",
            FailureInjection::DatabaseWriteAndRollbackMove,
        )
        .unwrap_err();
    match err2 {
        QuarantineError::RollbackFailed(info) => assert_eq!(info.stage, "database_insert"),
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }

    // 3. Rollback failure during restore_chmod
    let target3 = tmp.path().join("stranded_restore.bin");
    fs::write(&target3, b"precious payload 3").unwrap();
    let rec = qm.quarantine_file(&target3, "test").unwrap();
    let err3 = qm
        .restore_file_with_injection(rec.id, FailureInjection::PermissionChangeAndRollbackMove)
        .unwrap_err();
    match err3 {
        QuarantineError::RollbackFailed(info) => assert_eq!(info.stage, "restore_chmod"),
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }
}

#[test]
fn restore_prevents_destination_overwrite_on_toctou_race() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let qm = QuarantineManager::new(tmp.path().join("vault"), storage).unwrap();

    let target = tmp.path().join("raced_file.txt");
    fs::write(&target, b"quarantined original").unwrap();
    let rec = qm.quarantine_file(&target, "test").unwrap();

    let err = qm
        .restore_file_with_injection(rec.id, FailureInjection::DestinationRaceCreated)
        .unwrap_err();
    assert!(
        matches!(err, QuarantineError::DestinationExists(_)),
        "Expected DestinationExists on race, got {err:?}"
    );
    assert_eq!(
        fs::read(&target).unwrap(),
        b"user file created during race window",
        "Existing user file must never be overwritten"
    );
    assert!(
        std::path::Path::new(&rec.vault_path).exists(),
        "Vault copy must remain intact when restore is aborted"
    );
}

#[test]
fn cross_fs_copy_cleans_up_partial_staging_and_never_clobbers() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src.bin");
    let dst = tmp.path().join("dst.bin");
    fs::write(&src, b"source bytes").unwrap();

    // 1. Injected copy failure must clean up any `.kernlock_staging_*` file and leave `src` intact
    let err = kernlock_quarantine::cross_fs_copy_no_clobber(&src, &dst, true).unwrap_err();
    assert!(err
        .to_string()
        .contains("injected cross-filesystem copy failure"));
    assert!(src.exists());
    assert!(!dst.exists());
    let leftover: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".kernlock_staging_")
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "Staging file must be cleaned up on error"
    );

    // 2. Existing destination must never be overwritten
    fs::write(&dst, b"do not overwrite").unwrap();
    let err = kernlock_quarantine::cross_fs_copy_no_clobber(&src, &dst, false).unwrap_err();
    match err {
        kernlock_quarantine::MoveError::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::AlreadyExists);
        }
        other => panic!("Expected MoveError::Io(AlreadyExists), got {other:?}"),
    }
    assert_eq!(fs::read(&dst).unwrap(), b"do not overwrite");
    assert!(src.exists());
}

#[test]
fn hard_link_move_cleans_up_destination_on_source_unlink_failure() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("hl_src.bin");
    let dst = tmp.path().join("hl_dst.bin");
    fs::write(&src, b"hardlink bytes").unwrap();

    let err = kernlock_quarantine::hard_link_or_cross_fs(&src, &dst, true).unwrap_err();
    assert!(err
        .to_string()
        .contains("injected hard-link source removal failure"));
    assert!(src.exists(), "Source must remain intact");
    assert!(
        !dst.exists(),
        "Destination hard-link must be cleaned up when source removal fails"
    );
}

#[test]
fn delete_permanently_uses_recoverable_deleting_state_and_rolls_back() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let qm = QuarantineManager::new(tmp.path().join("vault"), storage.clone()).unwrap();

    let target = tmp.path().join("to_delete.bin");
    fs::write(&target, b"malware fixture bytes").unwrap();
    let rec = qm.quarantine_file(&target, "test delete").unwrap();
    let vault_file = std::path::PathBuf::from(&rec.vault_path);

    // 1. Failure marking Deleting leaves file & DB Quarantined
    let err = qm
        .delete_permanently_with_injection(rec.id, FailureInjection::DeleteMarkDeleting)
        .unwrap_err();
    assert!(matches!(err, QuarantineError::Storage(_)));
    assert!(vault_file.exists());
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Quarantined
    );

    // 2. Failure finalizing Deleted in DB rolls back staging file & DB status to Quarantined
    let err = qm
        .delete_permanently_with_injection(rec.id, FailureInjection::DeleteFinalizeDb)
        .unwrap_err();
    assert!(matches!(
        err,
        QuarantineError::RolledBack {
            stage: "delete_finalize_db",
            ..
        }
    ));
    assert!(vault_file.exists());
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Quarantined
    );

    // 3. Rollback failure during delete finalization returns RollbackFailed with recovery info
    let err = qm
        .delete_permanently_with_injection(
            rec.id,
            FailureInjection::DeleteFinalizeDbAndRollbackMove,
        )
        .unwrap_err();
    match err {
        QuarantineError::RollbackFailed(info) => {
            assert_eq!(info.stage, "delete_finalize_db");
            assert!(std::path::Path::new(&info.stranded_path).exists());
        }
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }
    // Record is in Deleting state with staged file on disk — verify delete_permanently recovers & completes
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleting
    );
    qm.delete_permanently(rec.id).unwrap();
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleted
    );
    assert!(!vault_file.exists());

    // 4. Unlink cleanup failure after DB Deleted returns CleanupFailed with stranded file path
    let target2 = tmp.path().join("to_delete_2.bin");
    fs::write(&target2, b"second fixture").unwrap();
    let rec2 = qm.quarantine_file(&target2, "test delete 2").unwrap();
    let err = qm
        .delete_permanently_with_injection(rec2.id, FailureInjection::DeleteUnlinkCleanup)
        .unwrap_err();
    match err {
        QuarantineError::CleanupFailed(info) => {
            assert_eq!(info.operation, "delete_unlink_staging");
            assert_eq!(info.stranded_files.len(), 1);
            assert!(std::path::Path::new(&info.stranded_files[0]).exists());
        }
        other => panic!("Expected CleanupFailed, got {other:?}"),
    }
}

#[test]
fn startup_recovery_audits_and_recovers_crashes_at_every_deletion_stage() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    // --- Scenario 1: Crash at Step 1 (DB set to Deleting, file still at vault_path) ---
    let t1 = tmp.path().join("file1.bin");
    fs::write(&t1, b"payload one").unwrap();
    let rec1 = qm.quarantine_file(&t1, "s1").unwrap();
    storage
        .update_quarantine_status(rec1.id, QuarantineStatus::Deleting, None)
        .unwrap();

    // --- Scenario 2: Crash at Step 2 (file moved to .deleting_<id>.locked, DB still Deleting) ---
    let t2 = tmp.path().join("file2.bin");
    fs::write(&t2, b"payload two").unwrap();
    let rec2 = qm.quarantine_file(&t2, "s2").unwrap();
    storage
        .update_quarantine_status(rec2.id, QuarantineStatus::Deleting, None)
        .unwrap();
    let vault_path2 = std::path::PathBuf::from(&rec2.vault_path);
    let staged_path2 = vault_dir.join(format!(".deleting_{}.locked", rec2.id));
    fs::rename(&vault_path2, &staged_path2).unwrap();

    // --- Scenario 3: Crash at Step 3 (DB set to Deleted, .deleting_<id>.locked not unlinked) ---
    let t3 = tmp.path().join("file3.bin");
    fs::write(&t3, b"payload three").unwrap();
    let rec3 = qm.quarantine_file(&t3, "s3").unwrap();
    let vault_path3 = std::path::PathBuf::from(&rec3.vault_path);
    let staged_path3 = vault_dir.join(format!(".deleting_{}.locked", rec3.id));
    fs::rename(&vault_path3, &staged_path3).unwrap();
    storage
        .update_quarantine_status(rec3.id, QuarantineStatus::Deleted, None)
        .unwrap();

    // --- Scenario 4: Corrupted / Tampered staging file (SHA-256 mismatch) ---
    let t4 = tmp.path().join("file4.bin");
    fs::write(&t4, b"payload four original").unwrap();
    let rec4 = qm.quarantine_file(&t4, "s4").unwrap();
    let vault_path4 = std::path::PathBuf::from(&rec4.vault_path);
    let staged_path4 = vault_dir.join(format!(".deleting_{}.locked", rec4.id));
    fs::remove_file(&vault_path4).unwrap();
    fs::write(&staged_path4, b"TAMPERED BYTES!").unwrap(); // Mismatched SHA-256!

    // --- Scenario 5: Orphaned cross-fs staging file with verified existing duplicate ---
    let staged_dup = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_dup, b"payload one").unwrap(); // matches rec1

    // --- Scenario 6: Unknown stranded staging file (no matching DB record) ---
    let staged_unknown = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_unknown, b"mystery bytes from interrupted operation").unwrap();

    // Run startup recovery!
    let report = qm.recover_on_startup().unwrap();

    // Assertions for Scenario 1:
    assert!(report.recovered_to_quarantine.contains(&rec1.id));
    assert_eq!(
        storage.get_quarantine(rec1.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    assert!(std::path::Path::new(&rec1.vault_path).is_file());

    // Assertions for Scenario 2:
    assert!(report.recovered_to_quarantine.contains(&rec2.id));
    assert_eq!(
        storage.get_quarantine(rec2.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    assert!(vault_path2.is_file());
    assert!(!staged_path2.exists());

    // Assertions for Scenario 3:
    assert!(report.finalized_deletions.contains(&rec3.id));
    assert_eq!(
        storage.get_quarantine(rec3.id).unwrap().status,
        QuarantineStatus::Deleted
    );
    assert!(!staged_path3.exists());

    // Assertions for Scenario 4: Tampered file must NEVER be deleted!
    assert!(
        staged_path4.exists(),
        "Unverified / corrupted file must NEVER be deleted automatically"
    );
    assert!(report
        .unverified_stranded_files
        .contains(&staged_path4.display().to_string()));

    // Assertions for Scenario 5: Verified duplicate staging file was safely cleaned up
    assert!(
        !staged_dup.exists(),
        "Verified duplicate staging file should be cleaned up"
    );

    // Assertions for Scenario 6: Unknown staging file must NEVER be deleted!
    assert!(
        staged_unknown.exists(),
        "Unknown staging file must NOT be deleted without verification"
    );
    assert!(report
        .unverified_stranded_files
        .contains(&staged_unknown.display().to_string()));
}

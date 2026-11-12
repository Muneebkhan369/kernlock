use kernlock_core::QuarantineStatus;
use kernlock_quarantine::{
    read_regular_nofollow, FailureInjection, QuarantineError, QuarantineManager,
};
use kernlock_storage::Storage;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
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
    // Record is in Deleting state with staged file on disk
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleting
    );
    // Direct call to delete_permanently fails closed with InvalidState
    assert!(matches!(
        qm.delete_permanently(rec.id).unwrap_err(),
        QuarantineError::InvalidState(_)
    ));
    // Dedicated startup recovery inspects and restores to Quarantined
    let report = qm.recover_on_startup().unwrap();
    assert!(report.recovered_to_quarantine.contains(&rec.id));
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    // Now delete_permanently completes cleanly
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
    assert!(report.contains_unverified_path(&staged_path4.display().to_string()));

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
    assert!(report.contains_unverified_path(&staged_unknown.display().to_string()));
}

#[test]
fn staging_cleanup_requires_independently_verified_copy() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    // Case A: Staging file valid, but vault copy is corrupted -> staging file preserved
    let t_a = tmp.path().join("case_a.bin");
    fs::write(&t_a, b"valid payload A").unwrap();
    let rec_a = qm.quarantine_file(&t_a, "case A").unwrap();
    let staged_a = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_a, b"valid payload A").unwrap();
    // Corrupt vault file
    fs::write(&rec_a.vault_path, b"corrupted vault payload A").unwrap();

    // Case B: Staging file valid, but original copy is corrupted (and vault missing) -> staging file preserved
    let t_b = tmp.path().join("case_b.bin");
    fs::write(&t_b, b"valid payload B").unwrap();
    let rec_b = qm.quarantine_file(&t_b, "case B").unwrap();
    let staged_b = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_b, b"valid payload B").unwrap();
    // Remove vault file, put corrupted file at original path
    fs::remove_file(&rec_b.vault_path).unwrap();
    fs::write(&rec_b.original_path, b"corrupted original payload B").unwrap();

    // Case C: Staging file valid, but both vault and original are missing -> staging file preserved
    let t_c = tmp.path().join("case_c.bin");
    fs::write(&t_c, b"valid payload C").unwrap();
    let rec_c = qm.quarantine_file(&t_c, "case C").unwrap();
    let staged_c = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_c, b"valid payload C").unwrap();
    fs::remove_file(&rec_c.vault_path).unwrap();
    if Path::new(&rec_c.original_path).exists() {
        fs::remove_file(&rec_c.original_path).unwrap();
    }

    // Case D: Staging file valid, and vault copy is intact and verified -> staging file safely deleted
    let t_d = tmp.path().join("case_d.bin");
    fs::write(&t_d, b"valid payload D").unwrap();
    let _rec_d = qm.quarantine_file(&t_d, "case D").unwrap();
    let staged_d = vault_dir.join(format!(".kernlock_staging_{}", uuid::Uuid::new_v4()));
    fs::write(&staged_d, b"valid payload D").unwrap();

    let report = qm.recover_on_startup().unwrap();

    assert!(
        staged_a.exists(),
        "Staging copy A must be preserved because vault copy is corrupted"
    );
    assert!(report.contains_unverified_path(&staged_a.display().to_string()));

    assert!(
        staged_b.exists(),
        "Staging copy B must be preserved because original copy is corrupted"
    );
    assert!(report.contains_unverified_path(&staged_b.display().to_string()));

    assert!(
        staged_c.exists(),
        "Staging copy C must be preserved because both copies are missing"
    );
    assert!(report.contains_unverified_path(&staged_c.display().to_string()));

    assert!(
        !staged_d.exists(),
        "Staging copy D must be cleaned up because vault copy is independently verified"
    );
}

#[test]
fn deleting_recovery_reports_unresolved_when_files_missing_or_tampered() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    // 1. Missing payload in Deleting state: must NOT mark Deleted! Must preserve Deleting and report unresolved.
    let t1 = tmp.path().join("missing_deleting.bin");
    fs::write(&t1, b"payload one").unwrap();
    let rec1 = qm.quarantine_file(&t1, "missing deleting").unwrap();
    fs::remove_file(&rec1.vault_path).unwrap();
    storage
        .update_quarantine_status(rec1.id, QuarantineStatus::Deleting, None)
        .unwrap();

    // 2. Tampered payload in Deleting state: vault file has wrong hash
    let t2 = tmp.path().join("tampered_deleting.bin");
    fs::write(&t2, b"payload two").unwrap();
    let rec2 = qm.quarantine_file(&t2, "tampered deleting").unwrap();
    fs::write(&rec2.vault_path, b"TAMPERED CONTENT IN VAULT").unwrap();
    storage
        .update_quarantine_status(rec2.id, QuarantineStatus::Deleting, None)
        .unwrap();

    let report = qm.recover_on_startup().unwrap();

    // rec1 must remain in Deleting status
    let rec1_after = storage.get_quarantine(rec1.id).unwrap();
    assert_eq!(
        rec1_after.status,
        QuarantineStatus::Deleting,
        "Record with missing files must NEVER be marked Deleted automatically"
    );
    assert!(
        report
            .unresolved_states
            .iter()
            .any(|u| u.id == rec1.id && u.status == QuarantineStatus::Deleting),
        "Unresolved state must be recorded for missing payload in Deleting"
    );

    // rec2 must also remain in Deleting status with unverified stranded file recorded
    let rec2_after = storage.get_quarantine(rec2.id).unwrap();
    assert_eq!(rec2_after.status, QuarantineStatus::Deleting);
    assert!(report.contains_unverified_path(&rec2.vault_path));
    assert!(report.unresolved_states.iter().any(|u| u.id == rec2.id));
}

#[test]
fn concurrent_restore_and_delete_operations_are_race_safe() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let qm = Arc::new(QuarantineManager::new(tmp.path().join("vault"), storage.clone()).unwrap());

    let target = tmp.path().join("race_target.bin");
    fs::write(&target, b"important user document").unwrap();
    let rec = qm.quarantine_file(&target, "race test").unwrap();
    let rec_id = rec.id;

    let barrier = Arc::new(Barrier::new(2));

    let qm_restore = Arc::clone(&qm);
    let barrier_restore = Arc::clone(&barrier);
    let h_restore = thread::spawn(move || {
        barrier_restore.wait();
        qm_restore.restore_file(rec_id)
    });

    let qm_delete = Arc::clone(&qm);
    let barrier_delete = Arc::clone(&barrier);
    let h_delete = thread::spawn(move || {
        barrier_delete.wait();
        qm_delete.delete_permanently(rec_id)
    });

    let res_restore = h_restore.join().unwrap();
    let res_delete = h_delete.join().unwrap();

    // Exactly one must succeed and the other must fail with InvalidState
    let final_record = storage.get_quarantine(rec_id).unwrap();
    match (res_restore, res_delete) {
        (Ok(_), Err(QuarantineError::InvalidState(_))) => {
            // Restore won the race
            assert_eq!(final_record.status, QuarantineStatus::Restored);
            assert!(
                target.exists(),
                "Restored file must exist at original target"
            );
            assert_eq!(fs::read(&target).unwrap(), b"important user document");
        }
        (Err(QuarantineError::InvalidState(_)), Ok(())) => {
            // Delete won the race
            assert_eq!(final_record.status, QuarantineStatus::Deleted);
            assert!(!target.exists(), "Target must not exist");
            assert!(
                !Path::new(&rec.vault_path).exists(),
                "Vault file must not exist"
            );
        }
        (r, d) => {
            panic!("Expected one success and one InvalidState, got restore={r:?}, delete={d:?}")
        }
    }
}

#[test]
fn startup_recovery_handles_interrupted_restore() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    // Scenario 1: Interrupted restore AFTER file was moved to destination
    // File at original_path is valid, vault file is gone, DB is Restoring -> recovers to Restored
    let t1 = tmp.path().join("restore_after_move.bin");
    fs::write(&t1, b"restore payload 1").unwrap();
    let rec1 = qm.quarantine_file(&t1, "restore 1").unwrap();
    // Simulate crash after move
    fs::rename(&rec1.vault_path, &rec1.original_path).unwrap();
    storage
        .update_quarantine_status(rec1.id, QuarantineStatus::Restoring, None)
        .unwrap();

    // Scenario 2: Interrupted restore BEFORE file was moved
    // Vault file is valid, original_path does not exist, DB is Restoring -> reverts to Quarantined
    let t2 = tmp.path().join("restore_before_move.bin");
    fs::write(&t2, b"restore payload 2").unwrap();
    let rec2 = qm.quarantine_file(&t2, "restore 2").unwrap();
    storage
        .update_quarantine_status(rec2.id, QuarantineStatus::Restoring, None)
        .unwrap();

    // Scenario 3: Interrupted restore where BOTH exist -> leave in Restoring, report unresolved
    let t3 = tmp.path().join("restore_both_exist.bin");
    fs::write(&t3, b"restore payload 3").unwrap();
    let rec3 = qm.quarantine_file(&t3, "restore 3").unwrap();
    fs::write(&rec3.original_path, b"restore payload 3").unwrap();
    storage
        .update_quarantine_status(rec3.id, QuarantineStatus::Restoring, None)
        .unwrap();

    // Run recovery
    let report = qm.recover_on_startup().unwrap();

    // Scenario 1: Finalized to Restored
    assert!(report.finalized_restores.contains(&rec1.id));
    assert_eq!(
        storage.get_quarantine(rec1.id).unwrap().status,
        QuarantineStatus::Restored
    );
    assert!(Path::new(&rec1.original_path).is_file());

    // Scenario 2: Reverted to Quarantined
    assert!(report.recovered_to_quarantine.contains(&rec2.id));
    assert_eq!(
        storage.get_quarantine(rec2.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    assert!(Path::new(&rec2.vault_path).is_file());

    // Scenario 3: Left in Restoring, reported in unresolved_states
    assert_eq!(
        storage.get_quarantine(rec3.id).unwrap().status,
        QuarantineStatus::Restoring
    );
    assert!(report.unresolved_states.iter().any(|u| u.id == rec3.id));

    // Verify idempotency: running recovery a second time produces no new finalized actions or failures
    let second_report = qm.recover_on_startup().unwrap();
    assert!(second_report.finalized_restores.is_empty());
    assert!(second_report.recovered_to_quarantine.is_empty());
    assert!(second_report.recovery_failures.is_empty());
}

#[test]
fn concurrent_two_delete_requests_only_one_succeeds() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = Arc::new(QuarantineManager::new(&vault_dir, storage.clone()).unwrap());

    let target = tmp.path().join("concurrent_del.bin");
    fs::write(&target, b"delete concurrency test").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let qm1 = Arc::clone(&qm);
    let barrier1 = Arc::clone(&barrier);
    let id = rec.id;
    let handle1 = thread::spawn(move || {
        barrier1.wait();
        qm1.delete_permanently(id)
    });

    let qm2 = Arc::clone(&qm);
    let barrier2 = Arc::clone(&barrier);
    let handle2 = thread::spawn(move || {
        barrier2.wait();
        qm2.delete_permanently(id)
    });

    let res1 = handle1.join().unwrap();
    let res2 = handle2.join().unwrap();

    let (ok_count, invalid_count) = match (&res1, &res2) {
        (Ok(()), Err(QuarantineError::InvalidState(_))) => (1, 1),
        (Err(QuarantineError::InvalidState(_)), Ok(())) => (1, 1),
        _ => panic!(
            "Expected exactly one Ok and one InvalidState, got res1: {res1:?}, res2: {res2:?}"
        ),
    };
    assert_eq!(ok_count, 1);
    assert_eq!(invalid_count, 1);
    assert_eq!(
        storage.get_quarantine(id).unwrap().status,
        QuarantineStatus::Deleted
    );
    assert!(!Path::new(&rec.vault_path).exists());
}

#[test]
fn concurrent_two_restore_requests_only_one_succeeds() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = Arc::new(QuarantineManager::new(&vault_dir, storage.clone()).unwrap());

    let target = tmp.path().join("concurrent_restore.bin");
    fs::write(&target, b"restore concurrency test").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let qm1 = Arc::clone(&qm);
    let barrier1 = Arc::clone(&barrier);
    let id = rec.id;
    let handle1 = thread::spawn(move || {
        barrier1.wait();
        qm1.restore_file(id)
    });

    let qm2 = Arc::clone(&qm);
    let barrier2 = Arc::clone(&barrier);
    let handle2 = thread::spawn(move || {
        barrier2.wait();
        qm2.restore_file(id)
    });

    let res1 = handle1.join().unwrap();
    let res2 = handle2.join().unwrap();

    let (ok_count, invalid_count) = match (&res1, &res2) {
        (Ok(_), Err(QuarantineError::InvalidState(_))) => (1, 1),
        (Err(QuarantineError::InvalidState(_)), Ok(_)) => (1, 1),
        _ => panic!(
            "Expected exactly one Ok and one InvalidState, got res1: {res1:?}, res2: {res2:?}"
        ),
    };
    assert_eq!(ok_count, 1);
    assert_eq!(invalid_count, 1);
    assert_eq!(
        storage.get_quarantine(id).unwrap().status,
        QuarantineStatus::Restored
    );
    assert!(target.exists());
    assert!(!Path::new(&rec.vault_path).exists());
}

#[test]
fn second_delete_request_after_deleting_acquired_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("deleting_acquired.bin");
    fs::write(&target, b"fail closed test").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    // Mark record as Deleting in storage (simulating first worker having acquired the lock)
    storage
        .update_quarantine_status(rec.id, QuarantineStatus::Deleting, None)
        .unwrap();

    // Second delete request arrives while record is in Deleting
    let err = qm.delete_permanently(rec.id).unwrap_err();
    match err {
        QuarantineError::InvalidState(msg) => {
            assert!(msg.contains(&rec.id.to_string()));
        }
        other => panic!("Expected InvalidState, got {other:?}"),
    }

    // Vault payload MUST remain intact and untouched
    let vault_file = Path::new(&rec.vault_path);
    assert!(vault_file.exists());
    assert_eq!(fs::read(vault_file).unwrap(), b"fail closed test");
}

#[test]
fn restore_database_rollback_failure_returns_structured_recovery_info() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("restore_rollback_db_fail.bin");
    fs::write(&target, b"restore rollback test").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    // Recreate destination so restore fails pre-move check, and inject RestorePreMoveRollbackDb
    fs::write(&rec.original_path, b"conflicting destination").unwrap();

    let err = qm
        .restore_file_with_injection(rec.id, FailureInjection::RestorePreMoveRollbackDb)
        .unwrap_err();

    match err {
        QuarantineError::RollbackFailed(info) => {
            assert_eq!(info.stage, "check_destination");
            assert!(info.cause.contains("destination already exists"));
            assert!(info
                .rollback_error
                .contains("injected restore pre-move rollback db failure"));
            assert_eq!(info.stranded_path, rec.vault_path);
            assert_eq!(info.original_path, rec.original_path);
            assert_eq!(info.sha256, rec.sha256);
        }
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }
}

#[test]
fn test_1_vault_metadata_permission_denied_during_deletion() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("file1.bin");
    fs::write(&target, b"content 1").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let err = qm
        .delete_permanently_with_injection(rec.id, FailureInjection::DeleteVaultMetadataPermission)
        .unwrap_err();

    match err {
        QuarantineError::Io(e) => {
            assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        }
        other => panic!("Expected QuarantineError::Io(PermissionDenied), got {other:?}"),
    }

    // Verify SQLite: record was safely rolled back to Quarantined
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    // Verify Filesystem: vault file is intact
    let vault_path = Path::new(&rec.vault_path);
    assert!(vault_path.exists());
    assert_eq!(fs::read(vault_path).unwrap(), b"content 1");
}

#[test]
fn test_2_vault_file_unexpectedly_missing_before_deletion() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("file2.bin");
    fs::write(&target, b"content 2").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    // Manually delete vault file before deletion attempt
    fs::remove_file(&rec.vault_path).unwrap();

    let err = qm.delete_permanently(rec.id).unwrap_err();
    match err {
        QuarantineError::Io(e) => {
            assert_eq!(e.kind(), ErrorKind::NotFound);
        }
        other => panic!("Expected QuarantineError::Io(NotFound), got {other:?}"),
    }

    // Verify SQLite: preserved unresolved Deleting state; NOT marked Deleted!
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleting
    );

    // Startup recovery flags the unresolved state
    let report = qm.recover_on_startup().unwrap();
    assert!(report.unresolved_states.iter().any(|u| u.id == rec.id));
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleting
    );
}

#[test]
fn test_3_staging_metadata_permission_denied_during_rollback() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("file3.bin");
    fs::write(&target, b"content 3").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let err = qm
        .delete_permanently_with_injection(
            rec.id,
            FailureInjection::DeleteRollbackStagingMetadataPermission,
        )
        .unwrap_err();

    match err {
        QuarantineError::RollbackFailed(info) => {
            assert_eq!(info.stage, "delete_finalize_db");
            assert!(info
                .rollback_error
                .contains("staging metadata permission denied"));
        }
        other => panic!("Expected RollbackFailed, got {other:?}"),
    }

    // Verify SQLite: preserved Deleting state because rollback failed
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleting
    );
    // Verify Filesystem: staging file remains stranded on disk
    let deleting_path = vault_dir.join(format!(".deleting_{}.locked", rec.id));
    assert!(deleting_path.exists());
}

#[test]
fn test_4_staging_metadata_permission_denied_during_final_cleanup() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("file4.bin");
    fs::write(&target, b"content 4").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let err = qm
        .delete_permanently_with_injection(
            rec.id,
            FailureInjection::DeleteCleanupStagingMetadataPermission,
        )
        .unwrap_err();

    match err {
        QuarantineError::CleanupFailed(info) => {
            assert_eq!(info.operation, "delete_inspect_staging_metadata");
            assert!(info
                .cleanup_error
                .contains("staging metadata permission denied"));
            assert_eq!(info.stranded_files.len(), 1);
        }
        other => panic!("Expected CleanupFailed, got {other:?}"),
    }

    // Verify SQLite: DB committed Deleted before final cleanup stage
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Deleted
    );
    let deleting_path = vault_dir.join(format!(".deleting_{}.locked", rec.id));
    assert!(deleting_path.exists());

    // Startup recovery cleans up stranded verified file
    let report = qm.recover_on_startup().unwrap();
    assert!(report.finalized_deletions.contains(&rec.id));
    assert!(!deleting_path.exists());
}

#[test]
fn test_5_sha256_mismatch_between_vault_and_staging() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("file5.bin");
    fs::write(&target, b"content 5").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    let err = qm
        .delete_permanently_with_injection(rec.id, FailureInjection::DeleteStagingHashMismatch)
        .unwrap_err();

    match err {
        QuarantineError::IntegrityMismatch(msg) => {
            assert!(msg.contains(&rec.id.to_string()));
        }
        other => panic!("Expected IntegrityMismatch, got {other:?}"),
    }

    // Verify SQLite: rolled back to Quarantined!
    assert_eq!(
        storage.get_quarantine(rec.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    // Verify Filesystem: restored to vault, staging gone
    let vault_path = Path::new(&rec.vault_path);
    assert!(vault_path.exists());
    assert_eq!(fs::read(vault_path).unwrap(), b"content 5");
    let deleting_path = vault_dir.join(format!(".deleting_{}.locked", rec.id));
    assert!(!deleting_path.exists());
}

#[test]
fn test_6_fifo_rejection_by_regular_file_reader() {
    let tmp = TempDir::new().unwrap();
    let fifo_path = tmp.path().join("test_fifo.pipe");

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(res, 0, "mkfifo must succeed");

        // Calling read_regular_nofollow on FIFO must immediately fail with InvalidInput, not block indefinitely
        let err = read_regular_nofollow(&fifo_path).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not a regular file"));

        let _ = fs::remove_file(&fifo_path);
    }
}

#[test]
fn test_7_symlink_rejection() {
    let tmp = TempDir::new().unwrap();
    let real_file = tmp.path().join("real.txt");
    fs::write(&real_file, b"real file content").unwrap();

    let symlink_path = tmp.path().join("link.txt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&real_file, &symlink_path).unwrap();

        // 1. read_regular_nofollow rejects symlinks
        let err = read_regular_nofollow(&symlink_path).unwrap_err();
        assert!(err.raw_os_error() == Some(libc::ELOOP) || err.kind() == ErrorKind::InvalidInput);

        // 2. quarantine_file rejects symlinks
        let storage = Storage::open_in_memory().unwrap();
        let vault_dir = tmp.path().join("vault");
        let qm = QuarantineManager::new(&vault_dir, storage).unwrap();

        let qerr = qm.quarantine_file(&symlink_path, "threat").unwrap_err();
        match qerr {
            QuarantineError::SymlinkRejected(p) => {
                assert!(p.contains("link.txt"));
            }
            other => panic!("Expected SymlinkRejected, got {other:?}"),
        }
    }
}

#[test]
fn test_8_recovery_with_unreadable_original_copy_and_unreadable_vault_copy() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    let target = tmp.path().join("unreadable_file.bin");
    fs::write(&target, b"secret payload").unwrap();
    let rec = qm.quarantine_file(&target, "threat").unwrap();

    // Recreate original file so both original and vault copies exist
    fs::write(&rec.original_path, b"secret payload").unwrap();

    // Set status to Restoring
    storage
        .update_quarantine_status(rec.id, QuarantineStatus::Restoring, None)
        .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Make both copies unreadable (mode 0000)
        fs::set_permissions(&rec.original_path, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&rec.vault_path, fs::Permissions::from_mode(0o000)).unwrap();

        let report = qm.recover_on_startup().unwrap();

        let status = storage.get_quarantine(rec.id).unwrap().status;
        assert_eq!(status, QuarantineStatus::Restoring);
        assert!(report.unresolved_states.iter().any(|u| u.id == rec.id));

        // Restore permissions for clean tempdir teardown
        let _ = fs::set_permissions(&rec.original_path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(&rec.vault_path, fs::Permissions::from_mode(0o600));
    }
}

#[test]
fn test_9_repeated_startup_recovery_after_each_interrupted_deletion_stage() {
    let tmp = TempDir::new().unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let vault_dir = tmp.path().join("vault");
    let qm = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();

    // Stage 1 interruption: record in Deleting, file still at vault_path
    let f1 = tmp.path().join("stage1.bin");
    fs::write(&f1, b"stage 1 payload").unwrap();
    let rec1 = qm.quarantine_file(&f1, "threat 1").unwrap();
    storage
        .update_quarantine_status(rec1.id, QuarantineStatus::Deleting, None)
        .unwrap();

    // Stage 2 interruption: record in Deleting, file moved to .deleting_<id>.locked
    let f2 = tmp.path().join("stage2.bin");
    fs::write(&f2, b"stage 2 payload").unwrap();
    let rec2 = qm.quarantine_file(&f2, "threat 2").unwrap();
    let del2_path = vault_dir.join(format!(".deleting_{}.locked", rec2.id));
    fs::rename(&rec2.vault_path, &del2_path).unwrap();
    storage
        .update_quarantine_status(rec2.id, QuarantineStatus::Deleting, None)
        .unwrap();

    // Stage 3 interruption: record in Deleted, file still at .deleting_<id>.locked
    let f3 = tmp.path().join("stage3.bin");
    fs::write(&f3, b"stage 3 payload").unwrap();
    let rec3 = qm.quarantine_file(&f3, "threat 3").unwrap();
    let del3_path = vault_dir.join(format!(".deleting_{}.locked", rec3.id));
    fs::rename(&rec3.vault_path, &del3_path).unwrap();
    storage
        .update_quarantine_status(rec3.id, QuarantineStatus::Deleted, None)
        .unwrap();

    // 1st recovery run:
    let r1 = qm.recover_on_startup().unwrap();
    assert!(r1.recovered_to_quarantine.contains(&rec1.id));
    assert!(r1.recovered_to_quarantine.contains(&rec2.id));
    assert!(r1.finalized_deletions.contains(&rec3.id));

    // Verify SQLite states
    assert_eq!(
        storage.get_quarantine(rec1.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    assert_eq!(
        storage.get_quarantine(rec2.id).unwrap().status,
        QuarantineStatus::Quarantined
    );
    assert_eq!(
        storage.get_quarantine(rec3.id).unwrap().status,
        QuarantineStatus::Deleted
    );

    // Verify Filesystem
    assert!(Path::new(&rec1.vault_path).exists());
    assert!(Path::new(&rec2.vault_path).exists());
    assert!(!del2_path.exists());
    assert!(!del3_path.exists());

    // 2nd recovery run (idempotency):
    let r2 = qm.recover_on_startup().unwrap();
    assert!(r2.recovered_to_quarantine.is_empty());
    assert!(r2.finalized_deletions.is_empty());
    assert!(r2.recovery_failures.is_empty());

    // 3rd recovery run (repeated idempotency):
    let r3 = qm.recover_on_startup().unwrap();
    assert!(r3.recovered_to_quarantine.is_empty());
    assert!(r3.finalized_deletions.is_empty());
    assert!(r3.recovery_failures.is_empty());
}

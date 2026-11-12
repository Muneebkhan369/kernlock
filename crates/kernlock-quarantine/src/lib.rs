use chrono::Utc;
use kernlock_core::{sha256_hex, QuarantineRecord, QuarantineStatus};
use kernlock_storage::{Storage, StorageError};
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug)]
pub struct RollbackFailureInfo {
    pub stage: &'static str,
    pub cause: String,
    pub rollback_error: String,
    pub stranded_path: String,
    pub original_path: String,
    pub vault_path: String,
    pub sha256: String,
    pub original_mode: u32,
}

impl std::fmt::Display for RollbackFailureInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Operation failed at stage '{}' ({}) AND rollback failed ({}); \
             stranded file may remain at '{}'. Recovery info: original='{}', \
             vault='{}', sha256={}, original_mode={:#o}",
            self.stage,
            self.cause,
            self.rollback_error,
            self.stranded_path,
            self.original_path,
            self.vault_path,
            self.sha256,
            self.original_mode
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedStrandedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFailure {
    pub id: Option<Uuid>,
    pub path: Option<String>,
    pub stage: &'static str,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRecoveryState {
    pub id: Uuid,
    pub status: QuarantineStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryAuditReport {
    /// Records that were interrupted in `Deleting` or `Restoring` whose state was safely rolled back to `Quarantined`.
    pub recovered_to_quarantine: Vec<Uuid>,
    /// Records that were committed `Deleted` in the DB whose verified `.deleting_<id>.locked`
    /// file was safely unlinked after SHA-256 verification.
    pub finalized_deletions: Vec<Uuid>,
    /// Records in `Restoring` state whose destination was verified and marked `Restored`.
    pub finalized_restores: Vec<Uuid>,
    /// Stranded staging files found on disk that could NOT be verified (SHA-256 mismatch or unknown)
    /// or whose existing copies could not be independently verified. These files are NEVER automatically deleted.
    pub unverified_stranded_files: Vec<UnverifiedStrandedFile>,
    /// Explicit I/O or DB failures encountered during recovery steps (no ignored errors).
    pub recovery_failures: Vec<RecoveryFailure>,
    /// Records in transitional states (`Deleting`, `Restoring`) that could not be cleanly resolved.
    pub unresolved_states: Vec<UnresolvedRecoveryState>,
}

impl RecoveryAuditReport {
    pub fn is_empty(&self) -> bool {
        self.recovered_to_quarantine.is_empty()
            && self.finalized_deletions.is_empty()
            && self.finalized_restores.is_empty()
            && self.unverified_stranded_files.is_empty()
            && self.recovery_failures.is_empty()
            && self.unresolved_states.is_empty()
    }

    pub fn contains_unverified_path(&self, path: &str) -> bool {
        self.unverified_stranded_files
            .iter()
            .any(|u| u.path == path)
    }
}

#[derive(Debug)]
pub struct CleanupFailureInfo {
    pub operation: &'static str,
    pub cause: String,
    pub cleanup_error: String,
    pub stranded_files: Vec<String>,
    pub recovery_hint: String,
}

impl std::fmt::Display for CleanupFailureInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cleanup failed during '{}' (cause: {}; cleanup_error: {}); \
             stranded files: [{}]. Hint: {}",
            self.operation,
            self.cause,
            self.cleanup_error,
            self.stranded_files.join(", "),
            self.recovery_hint
        )
    }
}

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Refusing to quarantine symbolic link: {0}")]
    SymlinkRejected(String),
    #[error("Refusing to quarantine file inside quarantine vault: {0}")]
    InsideVault(String),
    #[error("Target is not a regular file: {0}")]
    NotAFile(String),
    #[error("Cannot restore: destination already exists at {0}")]
    DestinationExists(String),
    #[error("Record {0} is not currently in quarantined state")]
    InvalidState(String),
    #[error("Integrity mismatch for quarantined file {0}")]
    IntegrityMismatch(String),
    #[error("Operation failed at stage '{stage}' and was safely rolled back: {cause}")]
    RolledBack { stage: &'static str, cause: String },
    #[error("{0}")]
    RollbackFailed(Box<RollbackFailureInfo>),
    #[error("{0}")]
    CleanupFailed(Box<CleanupFailureInfo>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInjection {
    None,
    PermissionChange,
    DatabaseWrite,
    PermissionChangeAndRollbackMove,
    DatabaseWriteAndRollbackMove,
    DestinationRaceCreated,
    RestorePreMoveRollbackDb,
    DeleteMarkDeleting,
    DeleteFinalizeDb,
    DeleteFinalizeDbAndRollbackMove,
    DeleteUnlinkCleanup,
}

#[derive(Clone)]
pub struct QuarantineManager {
    vault_dir: PathBuf,
    storage: Storage,
}

impl QuarantineManager {
    pub fn new<P: AsRef<Path>>(vault_dir: P, storage: Storage) -> Result<Self, QuarantineError> {
        let vault = vault_dir.as_ref().to_path_buf();
        fs::create_dir_all(&vault)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&vault, fs::Permissions::from_mode(0o700))?;
        }
        let canonical_vault = fs::canonicalize(&vault)?;
        Ok(Self {
            vault_dir: canonical_vault,
            storage,
        })
    }

    pub fn quarantine_file<P: AsRef<Path>>(
        &self,
        path: P,
        reason: &str,
    ) -> Result<QuarantineRecord, QuarantineError> {
        self.quarantine_file_with_injection(path, reason, FailureInjection::None)
    }

    pub fn quarantine_file_with_injection<P: AsRef<Path>>(
        &self,
        path: P,
        reason: &str,
        inject: FailureInjection,
    ) -> Result<QuarantineRecord, QuarantineError> {
        let orig_path = path.as_ref();
        let metadata = fs::symlink_metadata(orig_path)?;
        if metadata.file_type().is_symlink() {
            return Err(QuarantineError::SymlinkRejected(
                orig_path.display().to_string(),
            ));
        }
        if !metadata.is_file() {
            return Err(QuarantineError::NotAFile(orig_path.display().to_string()));
        }

        let canonical_orig = fs::canonicalize(orig_path)?;
        if canonical_orig.starts_with(&self.vault_dir) {
            return Err(QuarantineError::InsideVault(
                canonical_orig.display().to_string(),
            ));
        }

        let bytes = read_regular_nofollow(&canonical_orig)?;
        let sha256 = sha256_hex(&bytes);
        let size_bytes = bytes.len() as u64;

        #[cfg(unix)]
        let original_mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o7777
        };
        #[cfg(not(unix))]
        let original_mode = 0o644u32;

        let id = Uuid::new_v4();
        let vault_path = self.vault_dir.join(format!("{}.locked", id));

        move_file_no_clobber(&canonical_orig, &vault_path)
            .map_err(|e| e.into_quarantine_error())?;

        // Stage 2: Set restrictive 0600 permissions inside vault; roll back move on failure.
        let perm_res: Result<(), io::Error> = matches!(
            inject,
            FailureInjection::PermissionChange | FailureInjection::PermissionChangeAndRollbackMove
        )
        .then(|| {
            Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "injected permission failure",
            ))
        })
        .unwrap_or_else(|| set_mode(&vault_path, 0o600));

        if let Err(e) = perm_res {
            let rollback_move = if inject == FailureInjection::PermissionChangeAndRollbackMove {
                Err("injected rollback move failure".to_string())
            } else {
                move_file_no_clobber(&vault_path, &canonical_orig).map_err(|err| err.to_string())
            };

            if let Err(rb_err) = rollback_move {
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "vault_chmod",
                        cause: e.to_string(),
                        rollback_error: rb_err,
                        stranded_path: vault_path.display().to_string(),
                        original_path: canonical_orig.display().to_string(),
                        vault_path: vault_path.display().to_string(),
                        sha256,
                        original_mode,
                    },
                )));
            }

            if let Err(mode_err) = set_mode(&canonical_orig, original_mode) {
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "vault_chmod",
                        cause: e.to_string(),
                        rollback_error: format!("failed to restore original mode: {mode_err}"),
                        stranded_path: canonical_orig.display().to_string(),
                        original_path: canonical_orig.display().to_string(),
                        vault_path: vault_path.display().to_string(),
                        sha256,
                        original_mode,
                    },
                )));
            }

            return Err(QuarantineError::RolledBack {
                stage: "vault_chmod",
                cause: e.to_string(),
            });
        }

        let record = QuarantineRecord {
            id,
            original_path: canonical_orig.display().to_string(),
            vault_path: vault_path.display().to_string(),
            sha256: sha256.clone(),
            original_mode,
            size_bytes,
            reason: reason.to_string(),
            quarantined_at: Utc::now(),
            restored_at: None,
            status: QuarantineStatus::Quarantined,
        };

        // Stage 3: Persist metadata in SQLite; roll back move and restore permissions on failure.
        let db_res = if matches!(
            inject,
            FailureInjection::DatabaseWrite | FailureInjection::DatabaseWriteAndRollbackMove
        ) {
            Err(StorageError::NotFound(
                "injected database write failure".to_string(),
            ))
        } else {
            self.storage.insert_quarantine(&record)
        };

        if let Err(e) = db_res {
            let rollback_res: Result<(), String> = (|| {
                if inject == FailureInjection::DatabaseWriteAndRollbackMove {
                    return Err("injected rollback move failure".to_string());
                }
                move_file_no_clobber(&vault_path, &canonical_orig)
                    .map_err(|err| format!("move back failed: {err}"))?;
                set_mode(&canonical_orig, original_mode)
                    .map_err(|err| format!("restore mode failed: {err}"))?;
                Ok(())
            })();

            if let Err(rb_err) = rollback_res {
                let stranded = if vault_path.exists() {
                    &vault_path
                } else {
                    &canonical_orig
                };
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "database_insert",
                        cause: e.to_string(),
                        rollback_error: rb_err,
                        stranded_path: stranded.display().to_string(),
                        original_path: canonical_orig.display().to_string(),
                        vault_path: vault_path.display().to_string(),
                        sha256,
                        original_mode,
                    },
                )));
            }

            return Err(QuarantineError::RolledBack {
                stage: "database_insert",
                cause: e.to_string(),
            });
        }

        Ok(record)
    }

    fn rollback_restoring_to_quarantined(
        &self,
        record: &QuarantineRecord,
        stage: &'static str,
        cause: String,
        stranded_path: &Path,
        inject: FailureInjection,
    ) -> Result<(), QuarantineError> {
        let db_res = if inject == FailureInjection::RestorePreMoveRollbackDb {
            Err(StorageError::NotFound(
                "injected restore pre-move rollback db failure".to_string(),
            ))
        } else {
            self.storage.transition_quarantine_status(
                record.id,
                QuarantineStatus::Restoring,
                QuarantineStatus::Quarantined,
                None,
            )
        };

        match db_res {
            Ok(true) => Ok(()),
            Ok(false) => Err(QuarantineError::RollbackFailed(Box::new(
                RollbackFailureInfo {
                    stage,
                    cause,
                    rollback_error:
                        "CAS transition Restoring -> Quarantined failed (0 rows updated)"
                            .to_string(),
                    stranded_path: stranded_path.display().to_string(),
                    original_path: record.original_path.clone(),
                    vault_path: record.vault_path.clone(),
                    sha256: record.sha256.clone(),
                    original_mode: record.original_mode,
                },
            ))),
            Err(e) => Err(QuarantineError::RollbackFailed(Box::new(
                RollbackFailureInfo {
                    stage,
                    cause,
                    rollback_error: format!(
                        "Database transition Restoring -> Quarantined failed: {e}"
                    ),
                    stranded_path: stranded_path.display().to_string(),
                    original_path: record.original_path.clone(),
                    vault_path: record.vault_path.clone(),
                    sha256: record.sha256.clone(),
                    original_mode: record.original_mode,
                },
            ))),
        }
    }

    pub fn restore_file(&self, id: Uuid) -> Result<QuarantineRecord, QuarantineError> {
        self.restore_file_with_injection(id, FailureInjection::None)
    }

    pub fn restore_file_with_injection(
        &self,
        id: Uuid,
        inject: FailureInjection,
    ) -> Result<QuarantineRecord, QuarantineError> {
        let ok = self.storage.transition_quarantine_status(
            id,
            QuarantineStatus::Quarantined,
            QuarantineStatus::Restoring,
            None,
        )?;
        if !ok {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }

        let mut record = self.storage.get_quarantine(id)?;
        let vault_path = PathBuf::from(&record.vault_path);
        let orig_path = PathBuf::from(&record.original_path);

        if fs::symlink_metadata(&orig_path).is_ok() {
            let cause = format!("destination already exists at {}", record.original_path);
            self.rollback_restoring_to_quarantined(
                &record,
                "check_destination",
                cause,
                &vault_path,
                inject,
            )?;
            return Err(QuarantineError::DestinationExists(
                record.original_path.clone(),
            ));
        }

        let vault_meta = match fs::symlink_metadata(&vault_path) {
            Ok(m) => m,
            Err(e) => {
                let cause = format!("failed reading vault metadata: {e}");
                self.rollback_restoring_to_quarantined(
                    &record,
                    "check_vault_metadata",
                    cause,
                    &vault_path,
                    inject,
                )?;
                return Err(QuarantineError::Io(e));
            }
        };

        if vault_meta.file_type().is_symlink() {
            let cause = format!("vault file is a symlink at {}", vault_path.display());
            self.rollback_restoring_to_quarantined(
                &record,
                "check_vault_symlink",
                cause,
                &vault_path,
                inject,
            )?;
            return Err(QuarantineError::SymlinkRejected(
                vault_path.display().to_string(),
            ));
        }

        let bytes = match read_regular_nofollow(&vault_path) {
            Ok(b) => b,
            Err(e) => {
                let cause = format!("failed reading vault file with no-follow: {e}");
                self.rollback_restoring_to_quarantined(
                    &record,
                    "read_vault_payload",
                    cause,
                    &vault_path,
                    inject,
                )?;
                return Err(QuarantineError::Io(e));
            }
        };

        let current_sha = sha256_hex(&bytes);
        if current_sha != record.sha256 {
            let cause = format!(
                "integrity mismatch for quarantined file {}: expected {}, found {}",
                id, record.sha256, current_sha
            );
            self.rollback_restoring_to_quarantined(
                &record,
                "verify_vault_integrity",
                cause,
                &vault_path,
                inject,
            )?;
            return Err(QuarantineError::IntegrityMismatch(id.to_string()));
        }

        if let Some(parent) = orig_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                let cause = format!(
                    "failed creating parent directory for destination {}: {e}",
                    orig_path.display()
                );
                self.rollback_restoring_to_quarantined(
                    &record,
                    "create_destination_parent",
                    cause,
                    &vault_path,
                    inject,
                )?;
                return Err(QuarantineError::Io(e));
            }
        }

        // Simulate a TOCTOU race where a user file is created at `orig_path`
        // after our initial `symlink_metadata` check and before the atomic move.
        if inject == FailureInjection::DestinationRaceCreated {
            fs::write(&orig_path, b"user file created during race window")?;
        }

        match move_file_no_clobber(&vault_path, &orig_path) {
            Ok(()) => {}
            Err(MoveError::Io(e)) if e.kind() == ErrorKind::AlreadyExists => {
                let cause = format!("destination already exists at {}", record.original_path);
                self.rollback_restoring_to_quarantined(
                    &record,
                    "restore_move_no_clobber",
                    cause,
                    &vault_path,
                    inject,
                )?;
                return Err(QuarantineError::DestinationExists(
                    record.original_path.clone(),
                ));
            }
            Err(e) => {
                let cause = format!("move file to destination failed: {e}");
                self.rollback_restoring_to_quarantined(
                    &record,
                    "restore_move_no_clobber",
                    cause,
                    &vault_path,
                    inject,
                )?;
                return Err(e.into_quarantine_error());
            }
        }

        let perm_res: Result<(), io::Error> = matches!(
            inject,
            FailureInjection::PermissionChange | FailureInjection::PermissionChangeAndRollbackMove
        )
        .then(|| {
            Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "injected restore permission failure",
            ))
        })
        .unwrap_or_else(|| set_mode(&orig_path, record.original_mode));

        if let Err(e) = perm_res {
            let rollback_res: Result<(), String> = (|| {
                if inject == FailureInjection::PermissionChangeAndRollbackMove {
                    return Err("injected restore rollback move failure".to_string());
                }
                move_file_no_clobber(&orig_path, &vault_path)
                    .map_err(|err| format!("move back to vault failed: {err}"))?;
                set_mode(&vault_path, 0o600)
                    .map_err(|err| format!("re-lock vault mode failed: {err}"))?;
                match self.storage.transition_quarantine_status(
                    id,
                    QuarantineStatus::Restoring,
                    QuarantineStatus::Quarantined,
                    None,
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(
                        "CAS transition Restoring -> Quarantined failed (0 rows updated)"
                            .to_string(),
                    ),
                    Err(err) => Err(format!("revert DB status to quarantined failed: {err}")),
                }
            })();

            if let Err(rb_err) = rollback_res {
                let stranded = if orig_path.exists() {
                    &orig_path
                } else {
                    &vault_path
                };
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "restore_chmod",
                        cause: e.to_string(),
                        rollback_error: rb_err,
                        stranded_path: stranded.display().to_string(),
                        original_path: record.original_path.clone(),
                        vault_path: record.vault_path.clone(),
                        sha256: record.sha256.clone(),
                        original_mode: record.original_mode,
                    },
                )));
            }

            return Err(QuarantineError::RolledBack {
                stage: "restore_chmod",
                cause: e.to_string(),
            });
        }

        let now = Utc::now();
        let db_res = if matches!(
            inject,
            FailureInjection::DatabaseWrite | FailureInjection::DatabaseWriteAndRollbackMove
        ) {
            Err(StorageError::NotFound(
                "injected restore db failure".to_string(),
            ))
        } else {
            let ok = self.storage.transition_quarantine_status(
                id,
                QuarantineStatus::Restoring,
                QuarantineStatus::Restored,
                Some(now),
            )?;
            if !ok {
                Err(StorageError::NotFound(
                    "CAS Restoring->Restored failed".to_string(),
                ))
            } else {
                Ok(())
            }
        };

        if let Err(e) = db_res {
            let rollback_res: Result<(), String> = (|| {
                if inject == FailureInjection::DatabaseWriteAndRollbackMove {
                    return Err("injected restore db rollback move failure".to_string());
                }
                set_mode(&orig_path, 0o600).map_err(|err| format!("re-lock mode failed: {err}"))?;
                move_file_no_clobber(&orig_path, &vault_path)
                    .map_err(|err| format!("move back to vault failed: {err}"))?;
                match self.storage.transition_quarantine_status(
                    id,
                    QuarantineStatus::Restoring,
                    QuarantineStatus::Quarantined,
                    None,
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(
                        "CAS transition Restoring -> Quarantined failed (0 rows updated)"
                            .to_string(),
                    ),
                    Err(err) => Err(format!("revert DB status to quarantined failed: {err}")),
                }
            })();

            if let Err(rb_err) = rollback_res {
                let stranded = if orig_path.exists() {
                    &orig_path
                } else {
                    &vault_path
                };
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "restore_db_update",
                        cause: e.to_string(),
                        rollback_error: rb_err,
                        stranded_path: stranded.display().to_string(),
                        original_path: record.original_path.clone(),
                        vault_path: record.vault_path.clone(),
                        sha256: record.sha256.clone(),
                        original_mode: record.original_mode,
                    },
                )));
            }

            return Err(QuarantineError::RolledBack {
                stage: "restore_db_update",
                cause: e.to_string(),
            });
        }

        record.status = QuarantineStatus::Restored;
        record.restored_at = Some(now);
        Ok(record)
    }

    pub fn delete_permanently(&self, id: Uuid) -> Result<(), QuarantineError> {
        self.delete_permanently_with_injection(id, FailureInjection::None)
    }

    /// Database-safe permanent deletion using strict atomic CAS from Quarantined to Deleting.
    ///
    /// Competing delete requests arriving while Deleting fail closed immediately with InvalidState.
    /// Interrupted deletions are recovered solely through startup recovery.
    pub fn delete_permanently_with_injection(
        &self,
        id: Uuid,
        inject: FailureInjection,
    ) -> Result<(), QuarantineError> {
        let record = self.storage.get_quarantine(id)?;
        if record.status != QuarantineStatus::Quarantined {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }

        let vault_path = PathBuf::from(&record.vault_path);
        let deleting_path = self.vault_dir.join(format!(".deleting_{}.locked", id));

        // Step 1: Mark record as `Deleting` using strict atomic CAS from Quarantined.
        // A record already in Deleting cannot be entered by another delete operation.
        if inject == FailureInjection::DeleteMarkDeleting {
            return Err(QuarantineError::Storage(StorageError::NotFound(
                "injected delete mark-deleting DB failure".to_string(),
            )));
        }
        let ok = self.storage.transition_quarantine_status(
            id,
            QuarantineStatus::Quarantined,
            QuarantineStatus::Deleting,
            None,
        )?;
        if !ok {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }

        // Step 2: Stage the vault file to `.deleting_<id>.locked` so DB finalization failure is recoverable.
        if fs::symlink_metadata(&vault_path).is_ok() {
            if let Err(e) = move_file_no_clobber(&vault_path, &deleting_path) {
                let rb_res = match self.storage.transition_quarantine_status(
                    id,
                    QuarantineStatus::Deleting,
                    QuarantineStatus::Quarantined,
                    None,
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(
                        "CAS transition Deleting -> Quarantined failed (0 rows updated)"
                            .to_string(),
                    ),
                    Err(err) => Err(err.to_string()),
                };
                if let Err(rb_err) = rb_res {
                    return Err(QuarantineError::RollbackFailed(Box::new(
                        RollbackFailureInfo {
                            stage: "delete_stage_move",
                            cause: e.to_string(),
                            rollback_error: rb_err,
                            stranded_path: vault_path.display().to_string(),
                            original_path: record.original_path,
                            vault_path: record.vault_path,
                            sha256: record.sha256,
                            original_mode: record.original_mode,
                        },
                    )));
                }
                return Err(e.into_quarantine_error());
            }
        }

        // Step 3: Finalize DB status to `Deleted` using CAS.
        let finalize_res = if matches!(
            inject,
            FailureInjection::DeleteFinalizeDb | FailureInjection::DeleteFinalizeDbAndRollbackMove
        ) {
            Err(StorageError::NotFound(
                "injected delete finalize DB failure".to_string(),
            ))
        } else {
            let ok = self.storage.transition_quarantine_status(
                id,
                QuarantineStatus::Deleting,
                QuarantineStatus::Deleted,
                None,
            )?;
            if !ok {
                Err(StorageError::NotFound(
                    "CAS Deleting->Deleted failed (0 rows updated)".to_string(),
                ))
            } else {
                Ok(())
            }
        };

        if let Err(e) = finalize_res {
            let rollback_res: Result<(), String> = (|| {
                if inject == FailureInjection::DeleteFinalizeDbAndRollbackMove {
                    return Err("injected delete rollback move failure".to_string());
                }
                if fs::symlink_metadata(&deleting_path).is_ok() {
                    move_file_no_clobber(&deleting_path, &vault_path)
                        .map_err(|err| format!("move staging file back to vault failed: {err}"))?;
                }
                match self.storage.transition_quarantine_status(
                    id,
                    QuarantineStatus::Deleting,
                    QuarantineStatus::Quarantined,
                    None,
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(
                        "CAS transition Deleting -> Quarantined failed (0 rows updated)"
                            .to_string(),
                    ),
                    Err(err) => Err(format!("revert DB status to quarantined failed: {err}")),
                }
            })();

            if let Err(rb_err) = rollback_res {
                let stranded = if deleting_path.exists() {
                    &deleting_path
                } else {
                    &vault_path
                };
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "delete_finalize_db",
                        cause: e.to_string(),
                        rollback_error: rb_err,
                        stranded_path: stranded.display().to_string(),
                        original_path: record.original_path,
                        vault_path: record.vault_path,
                        sha256: record.sha256,
                        original_mode: record.original_mode,
                    },
                )));
            }

            return Err(QuarantineError::RolledBack {
                stage: "delete_finalize_db",
                cause: e.to_string(),
            });
        }

        // Step 4: Remove staged file now that DB has committed `Deleted`.
        if fs::symlink_metadata(&deleting_path).is_ok() {
            let unlink_res = if inject == FailureInjection::DeleteUnlinkCleanup {
                Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "injected delete unlink cleanup failure",
                ))
            } else {
                fs::remove_file(&deleting_path)
            };

            if let Err(e) = unlink_res {
                return Err(QuarantineError::CleanupFailed(Box::new(
                    CleanupFailureInfo {
                        operation: "delete_unlink_staging",
                        cause: "DB marked record Deleted, but staging file removal failed"
                            .to_string(),
                        cleanup_error: e.to_string(),
                        stranded_files: vec![deleting_path.display().to_string()],
                        recovery_hint: format!(
                            "Record {} is Deleted in DB; safely remove stranded staging file '{}'",
                            id,
                            deleting_path.display()
                        ),
                    },
                )));
            }
        }

        Ok(())
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>, QuarantineError> {
        Ok(self.storage.list_quarantine()?)
    }

    /// Startup recovery inspection for stranded staging files and interrupted operations.
    pub fn recover_on_startup(&self) -> Result<RecoveryAuditReport, QuarantineError> {
        let mut report = RecoveryAuditReport::default();

        // 1. Inspect vault directory for stranded staging files
        match fs::read_dir(&self.vault_dir) {
            Ok(entries) => {
                for entry_res in entries {
                    let entry = match entry_res {
                        Ok(ent) => ent,
                        Err(e) => {
                            report.recovery_failures.push(RecoveryFailure {
                                id: None,
                                path: Some(self.vault_dir.display().to_string()),
                                stage: "read_vault_dir_entry",
                                error: e.to_string(),
                            });
                            continue;
                        }
                    };
                    let path = entry.path();
                    let file_name = entry.file_name().to_string_lossy().to_string();

                    if file_name.starts_with(".deleting_") && file_name.ends_with(".locked") {
                        let id_str = file_name
                            .trim_start_matches(".deleting_")
                            .trim_end_matches(".locked");
                        let id = match Uuid::parse_str(id_str) {
                            Ok(parsed) => parsed,
                            Err(_) => {
                                report
                                    .unverified_stranded_files
                                    .push(UnverifiedStrandedFile {
                                        path: path.display().to_string(),
                                        reason:
                                            "Cannot parse UUID from .deleting_<id>.locked filename"
                                                .to_string(),
                                    });
                                continue;
                            }
                        };

                        match self.storage.get_quarantine(id) {
                            Ok(record) => {
                                let bytes = match read_regular_nofollow(&path) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        report.unverified_stranded_files.push(
                                            UnverifiedStrandedFile {
                                                path: path.display().to_string(),
                                                reason: format!(
                                                "Failed reading staging file with no-follow: {e}"
                                            ),
                                            },
                                        );
                                        continue;
                                    }
                                };
                                let actual_sha = sha256_hex(&bytes);

                                if actual_sha != record.sha256 {
                                    // SHA-256 mismatch: NEVER automatically delete unverified files!
                                    report
                                        .unverified_stranded_files
                                        .push(UnverifiedStrandedFile {
                                            path: path.display().to_string(),
                                            reason: format!(
                                                "SHA-256 mismatch: file has {}, expected {}",
                                                actual_sha, record.sha256
                                            ),
                                        });
                                    continue;
                                }

                                match record.status {
                                    QuarantineStatus::Deleted => {
                                        // DB committed Deleted, SHA-256 verified -> safe to unlink.
                                        match fs::remove_file(&path) {
                                            Ok(()) => {
                                                report.finalized_deletions.push(id);
                                            }
                                            Err(e) => {
                                                report.recovery_failures.push(RecoveryFailure {
                                                    id: Some(id),
                                                    path: Some(path.display().to_string()),
                                                    stage: "unlink_deleted_staging",
                                                    error: e.to_string(),
                                                });
                                            }
                                        }
                                    }
                                    QuarantineStatus::Deleting | QuarantineStatus::Quarantined => {
                                        let vault_target = PathBuf::from(&record.vault_path);
                                        if !vault_target.exists() {
                                            match move_file_no_clobber(&path, &vault_target) {
                                                Ok(()) => {
                                                    if let Err(e) = set_mode(&vault_target, 0o600) {
                                                        report.recovery_failures.push(
                                                            RecoveryFailure {
                                                                id: Some(id),
                                                                path: Some(
                                                                    vault_target
                                                                        .display()
                                                                        .to_string(),
                                                                ),
                                                                stage: "set_mode_vault",
                                                                error: e.to_string(),
                                                            },
                                                        );
                                                        report.unresolved_states.push(
                                                            UnresolvedRecoveryState {
                                                                id,
                                                                status: record.status,
                                                                reason: format!(
                                                                    "Failed setting permissions (0600) on recovered vault file: {e}"
                                                                ),
                                                            },
                                                        );
                                                        continue;
                                                    }
                                                    match self
                                                        .storage
                                                        .transition_quarantine_status_from_any(
                                                            id,
                                                            &[
                                                                QuarantineStatus::Deleting,
                                                                QuarantineStatus::Quarantined,
                                                            ],
                                                            QuarantineStatus::Quarantined,
                                                            None,
                                                        ) {
                                                        Ok(true) => {
                                                            report.recovered_to_quarantine.push(id);
                                                        }
                                                        Ok(false) => {
                                                            report.unresolved_states.push(
                                                                UnresolvedRecoveryState {
                                                                    id,
                                                                    status: record.status,
                                                                    reason: "CAS Deleting->Quarantined returned false (0 rows updated)".to_string(),
                                                                },
                                                            );
                                                        }
                                                        Err(e) => {
                                                            report.recovery_failures.push(
                                                                RecoveryFailure {
                                                                    id: Some(id),
                                                                    path: Some(
                                                                        vault_target
                                                                            .display()
                                                                            .to_string(),
                                                                    ),
                                                                    stage:
                                                                        "db_transition_quarantined",
                                                                    error: e.to_string(),
                                                                },
                                                            );
                                                            report.unresolved_states.push(
                                                                UnresolvedRecoveryState {
                                                                    id,
                                                                    status: record.status,
                                                                    reason: format!("Database transition Deleting->Quarantined failed: {e}"),
                                                                },
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    report.recovery_failures.push(
                                                        RecoveryFailure {
                                                            id: Some(id),
                                                            path: Some(path.display().to_string()),
                                                            stage: "move_deleting_to_vault",
                                                            error: e.to_string(),
                                                        },
                                                    );
                                                }
                                            }
                                        } else if let Ok(vault_bytes) =
                                            read_regular_nofollow(&vault_target)
                                        {
                                            if sha256_hex(&vault_bytes) == record.sha256 {
                                                // Verified copy already in vault! Safe to remove deleting staging file.
                                                match fs::remove_file(&path) {
                                                    Ok(()) => {
                                                        match self
                                                            .storage
                                                            .transition_quarantine_status_from_any(
                                                                id,
                                                                &[
                                                                    QuarantineStatus::Deleting,
                                                                    QuarantineStatus::Quarantined,
                                                                ],
                                                                QuarantineStatus::Quarantined,
                                                                None,
                                                            ) {
                                                            Ok(true) => {
                                                                report
                                                                    .recovered_to_quarantine
                                                                    .push(id);
                                                            }
                                                            Ok(false) => {
                                                                report.unresolved_states.push(
                                                                    UnresolvedRecoveryState {
                                                                        id,
                                                                        status: record.status,
                                                                        reason: "CAS Deleting->Quarantined returned false (0 rows updated)".to_string(),
                                                                    },
                                                                );
                                                            }
                                                            Err(e) => {
                                                                report
                                                                    .recovery_failures
                                                                    .push(RecoveryFailure {
                                                                    id: Some(id),
                                                                    path: Some(
                                                                        vault_target
                                                                            .display()
                                                                            .to_string(),
                                                                    ),
                                                                    stage:
                                                                        "db_transition_quarantined",
                                                                    error: e.to_string(),
                                                                });
                                                                report.unresolved_states.push(
                                                                    UnresolvedRecoveryState {
                                                                        id,
                                                                        status: record.status,
                                                                        reason: format!("Database transition Deleting->Quarantined failed: {e}"),
                                                                    },
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        report
                                                            .recovery_failures
                                                            .push(RecoveryFailure {
                                                            id: Some(id),
                                                            path: Some(path.display().to_string()),
                                                            stage:
                                                                "unlink_staging_after_vault_verified",
                                                            error: e.to_string(),
                                                        });
                                                    }
                                                }
                                            } else {
                                                report
                                                    .unverified_stranded_files
                                                    .push(UnverifiedStrandedFile {
                                                    path: vault_target.display().to_string(),
                                                    reason:
                                                        "Vault target exists but has SHA-256 mismatch"
                                                            .to_string(),
                                                });
                                                report.unresolved_states.push(
                                                    UnresolvedRecoveryState {
                                                        id,
                                                        status: record.status,
                                                        reason:
                                                            "Both deleting staging file and corrupted vault copy exist"
                                                                .to_string(),
                                                    },
                                                );
                                            }
                                        } else {
                                            report.unverified_stranded_files.push(
                                                UnverifiedStrandedFile {
                                                    path: vault_target.display().to_string(),
                                                    reason:
                                                        "Vault target exists but could not be read with no-follow"
                                                            .to_string(),
                                                },
                                            );
                                            report.unresolved_states.push(UnresolvedRecoveryState {
                                                id,
                                                status: record.status,
                                                reason:
                                                    "Vault target unreadable while deleting staging file exists"
                                                        .to_string(),
                                            });
                                        }
                                    }
                                    QuarantineStatus::Restoring => {
                                        report.unverified_stranded_files.push(
                                            UnverifiedStrandedFile {
                                                path: path.display().to_string(),
                                                reason:
                                                    "Unexpected .deleting_<id>.locked file while record is in Restoring status"
                                                        .to_string(),
                                            },
                                        );
                                        report.unresolved_states.push(UnresolvedRecoveryState {
                                            id,
                                            status: QuarantineStatus::Restoring,
                                            reason:
                                                "Record is Restoring but .deleting_<id>.locked exists"
                                                    .to_string(),
                                        });
                                    }
                                    QuarantineStatus::Restored => {
                                        report.unverified_stranded_files.push(
                                            UnverifiedStrandedFile {
                                                path: path.display().to_string(),
                                                reason:
                                                    "Unexpected .deleting_<id>.locked file while record is in Restored status"
                                                        .to_string(),
                                            },
                                        );
                                        report.unresolved_states.push(UnresolvedRecoveryState {
                                            id,
                                            status: QuarantineStatus::Restored,
                                            reason:
                                                "Record is Restored but .deleting_<id>.locked exists"
                                                    .to_string(),
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                // No DB record found for this UUID: NEVER automatically delete!
                                report
                                    .unverified_stranded_files
                                    .push(UnverifiedStrandedFile {
                                        path: path.display().to_string(),
                                        reason: format!("No database record found for UUID {}", id),
                                    });
                            }
                        }
                    } else if file_name.starts_with(".kernlock_staging_") {
                        let bytes = match read_regular_nofollow(&path) {
                            Ok(b) => b,
                            Err(e) => {
                                report
                                    .unverified_stranded_files
                                    .push(UnverifiedStrandedFile {
                                        path: path.display().to_string(),
                                        reason: format!(
                                            "Cannot read staging file with no-follow: {e}"
                                        ),
                                    });
                                continue;
                            }
                        };
                        let actual_sha = sha256_hex(&bytes);
                        let all_records = match self.storage.list_quarantine() {
                            Ok(recs) => recs,
                            Err(e) => {
                                report.recovery_failures.push(RecoveryFailure {
                                    id: None,
                                    path: Some(path.display().to_string()),
                                    stage: "list_quarantine_for_staging",
                                    error: e.to_string(),
                                });
                                report
                                    .unverified_stranded_files
                                    .push(UnverifiedStrandedFile {
                                        path: path.display().to_string(),
                                        reason: format!(
                                            "Cannot query database to verify staging file: {e}"
                                        ),
                                    });
                                continue;
                            }
                        };
                        let matching_record =
                            all_records.into_iter().find(|r| r.sha256 == actual_sha);

                        if let Some(rec) = matching_record {
                            // Check if an independently verified good copy exists at vault_path or original_path
                            let mut verified_copy_exists = false;

                            if let Ok(v_bytes) = read_regular_nofollow(Path::new(&rec.vault_path)) {
                                if sha256_hex(&v_bytes) == rec.sha256 {
                                    verified_copy_exists = true;
                                }
                            }

                            if !verified_copy_exists {
                                if let Ok(o_bytes) =
                                    read_regular_nofollow(Path::new(&rec.original_path))
                                {
                                    if sha256_hex(&o_bytes) == rec.sha256 {
                                        verified_copy_exists = true;
                                    }
                                }
                            }

                            if verified_copy_exists {
                                // Independently verified good copy exists! Safe to clean up staging file.
                                if let Err(e) = fs::remove_file(&path) {
                                    report.recovery_failures.push(RecoveryFailure {
                                        id: Some(rec.id),
                                        path: Some(path.display().to_string()),
                                        stage: "remove_verified_staging_file",
                                        error: e.to_string(),
                                    });
                                }
                            } else {
                                // Neither vault nor original copy is independently verified!
                                // NEVER delete staging copy!
                                report.unverified_stranded_files.push(UnverifiedStrandedFile {
                                    path: path.display().to_string(),
                                    reason: "Neither vault nor original location has an independently verified copy".to_string(),
                                });
                            }
                        } else {
                            // No DB record with matching SHA-256!
                            report
                                .unverified_stranded_files
                                .push(UnverifiedStrandedFile {
                                    path: path.display().to_string(),
                                    reason:
                                        "No database record matches this staging file's SHA-256"
                                            .to_string(),
                                });
                        }
                    }
                }
            }
            Err(e) => {
                report.recovery_failures.push(RecoveryFailure {
                    id: None,
                    path: Some(self.vault_dir.display().to_string()),
                    stage: "read_vault_dir",
                    error: e.to_string(),
                });
            }
        }

        // 2. Audit DB records stuck in `Deleting`
        let deleting_records = self
            .storage
            .list_quarantine_by_status(QuarantineStatus::Deleting)?;
        for record in deleting_records {
            if report.recovered_to_quarantine.contains(&record.id)
                || report.finalized_deletions.contains(&record.id)
            {
                continue;
            }

            let vault_path = PathBuf::from(&record.vault_path);
            let deleting_path = self
                .vault_dir
                .join(format!(".deleting_{}.locked", record.id));

            if vault_path.is_file() {
                match read_regular_nofollow(&vault_path) {
                    Ok(bytes) => {
                        if sha256_hex(&bytes) == record.sha256 {
                            if let Err(e) = set_mode(&vault_path, 0o600) {
                                report.recovery_failures.push(RecoveryFailure {
                                    id: Some(record.id),
                                    path: Some(vault_path.display().to_string()),
                                    stage: "revert_vault_mode_deleting",
                                    error: e.to_string(),
                                });
                                report.unresolved_states.push(UnresolvedRecoveryState {
                                    id: record.id,
                                    status: QuarantineStatus::Deleting,
                                    reason: format!("Failed setting vault permissions (0600) during Deleting recovery: {e}"),
                                });
                                continue;
                            }
                            match self.storage.transition_quarantine_status(
                                record.id,
                                QuarantineStatus::Deleting,
                                QuarantineStatus::Quarantined,
                                None,
                            ) {
                                Ok(true) => {
                                    report.recovered_to_quarantine.push(record.id);
                                }
                                Ok(false) => {
                                    report.unresolved_states.push(UnresolvedRecoveryState {
                                        id: record.id,
                                        status: QuarantineStatus::Deleting,
                                        reason: "CAS Deleting->Quarantined returned false (0 rows updated)"
                                            .to_string(),
                                    });
                                }
                                Err(e) => {
                                    report.recovery_failures.push(RecoveryFailure {
                                        id: Some(record.id),
                                        path: Some(vault_path.display().to_string()),
                                        stage: "revert_deleting_to_quarantined_db",
                                        error: e.to_string(),
                                    });
                                    report.unresolved_states.push(UnresolvedRecoveryState {
                                        id: record.id,
                                        status: QuarantineStatus::Deleting,
                                        reason: format!(
                                            "Database transition Deleting->Quarantined failed: {e}"
                                        ),
                                    });
                                }
                            }
                        } else {
                            report
                                .unverified_stranded_files
                                .push(UnverifiedStrandedFile {
                                    path: vault_path.display().to_string(),
                                    reason: "Vault file SHA-256 mismatch during Deleting recovery"
                                        .to_string(),
                                });
                            report.unresolved_states.push(UnresolvedRecoveryState {
                                id: record.id,
                                status: QuarantineStatus::Deleting,
                                reason: "Vault file corrupted".to_string(),
                            });
                        }
                    }
                    Err(e) => {
                        report.recovery_failures.push(RecoveryFailure {
                            id: Some(record.id),
                            path: Some(vault_path.display().to_string()),
                            stage: "read_vault_file_deleting_recovery",
                            error: e.to_string(),
                        });
                        report.unresolved_states.push(UnresolvedRecoveryState {
                            id: record.id,
                            status: QuarantineStatus::Deleting,
                            reason: format!("Vault file unreadable: {e}"),
                        });
                    }
                }
            } else if !deleting_path.is_file() {
                // NEITHER vault_path nor deleting_path exists!
                // Do NOT mark Deleted! Preserve DB state and report unresolved condition.
                report.unresolved_states.push(UnresolvedRecoveryState {
                    id: record.id,
                    status: QuarantineStatus::Deleting,
                    reason: "Neither vault copy nor deleting staging copy exists on disk; cannot positively establish deletion".to_string(),
                });
            }
        }

        // 3. Audit DB records stuck in `Restoring`
        let restoring_records = self
            .storage
            .list_quarantine_by_status(QuarantineStatus::Restoring)?;
        for record in restoring_records {
            let orig_path = PathBuf::from(&record.original_path);
            let vault_path = PathBuf::from(&record.vault_path);

            let orig_valid = match read_regular_nofollow(&orig_path) {
                Ok(b) => sha256_hex(&b) == record.sha256,
                Err(_) => false,
            };

            let vault_valid = match read_regular_nofollow(&vault_path) {
                Ok(b) => sha256_hex(&b) == record.sha256,
                Err(_) => false,
            };

            if orig_valid && !vault_path.exists() {
                // Crash happened after move to destination was completed!
                if let Err(e) = set_mode(&orig_path, record.original_mode) {
                    report.recovery_failures.push(RecoveryFailure {
                        id: Some(record.id),
                        path: Some(orig_path.display().to_string()),
                        stage: "restore_set_mode_orig",
                        error: e.to_string(),
                    });
                    report.unresolved_states.push(UnresolvedRecoveryState {
                        id: record.id,
                        status: QuarantineStatus::Restoring,
                        reason: format!(
                            "Failed setting original permissions on restored destination: {e}"
                        ),
                    });
                    continue;
                }
                match self.storage.transition_quarantine_status(
                    record.id,
                    QuarantineStatus::Restoring,
                    QuarantineStatus::Restored,
                    Some(Utc::now()),
                ) {
                    Ok(true) => {
                        report.finalized_restores.push(record.id);
                    }
                    Ok(false) => {
                        report.unresolved_states.push(UnresolvedRecoveryState {
                            id: record.id,
                            status: QuarantineStatus::Restoring,
                            reason: "CAS Restoring->Restored returned false (0 rows updated)"
                                .to_string(),
                        });
                    }
                    Err(e) => {
                        report.recovery_failures.push(RecoveryFailure {
                            id: Some(record.id),
                            path: Some(orig_path.display().to_string()),
                            stage: "finalize_restored_db",
                            error: e.to_string(),
                        });
                        report.unresolved_states.push(UnresolvedRecoveryState {
                            id: record.id,
                            status: QuarantineStatus::Restoring,
                            reason: format!("Database transition Restoring->Restored failed: {e}"),
                        });
                    }
                }
            } else if vault_valid && !orig_path.exists() {
                // Crash happened before move to destination! File is safe in vault.
                if let Err(e) = set_mode(&vault_path, 0o600) {
                    report.recovery_failures.push(RecoveryFailure {
                        id: Some(record.id),
                        path: Some(vault_path.display().to_string()),
                        stage: "revert_vault_mode",
                        error: e.to_string(),
                    });
                    report.unresolved_states.push(UnresolvedRecoveryState {
                        id: record.id,
                        status: QuarantineStatus::Restoring,
                        reason: format!(
                            "Failed setting vault permissions (0600) on vault file: {e}"
                        ),
                    });
                    continue;
                }
                match self.storage.transition_quarantine_status(
                    record.id,
                    QuarantineStatus::Restoring,
                    QuarantineStatus::Quarantined,
                    None,
                ) {
                    Ok(true) => {
                        report.recovered_to_quarantine.push(record.id);
                    }
                    Ok(false) => {
                        report.unresolved_states.push(UnresolvedRecoveryState {
                            id: record.id,
                            status: QuarantineStatus::Restoring,
                            reason: "CAS Restoring->Quarantined returned false (0 rows updated)"
                                .to_string(),
                        });
                    }
                    Err(e) => {
                        report.recovery_failures.push(RecoveryFailure {
                            id: Some(record.id),
                            path: Some(vault_path.display().to_string()),
                            stage: "revert_restoring_to_quarantined_db",
                            error: e.to_string(),
                        });
                        report.unresolved_states.push(UnresolvedRecoveryState {
                            id: record.id,
                            status: QuarantineStatus::Restoring,
                            reason: format!(
                                "Database transition Restoring->Quarantined failed: {e}"
                            ),
                        });
                    }
                }
            } else {
                // Both exist or neither exists or corrupted: leave record in Restoring and report unresolved!
                let reason = if orig_valid && vault_valid {
                    "Both destination and vault files exist with valid SHA-256; will not overwrite"
                        .to_string()
                } else if orig_path.exists() && vault_path.exists() {
                    "Both destination and vault files exist, but at least one is corrupted"
                        .to_string()
                } else {
                    "Neither destination nor vault file has verified SHA-256".to_string()
                };
                report.unresolved_states.push(UnresolvedRecoveryState {
                    id: record.id,
                    status: QuarantineStatus::Restoring,
                    reason,
                });
            }
        }

        Ok(report)
    }
}

#[derive(Debug)]
pub enum MoveError {
    Io(io::Error),
    Cleanup(Box<CleanupFailureInfo>),
}

impl MoveError {
    fn into_quarantine_error(self) -> QuarantineError {
        match self {
            MoveError::Io(e) => QuarantineError::Io(e),
            MoveError::Cleanup(info) => QuarantineError::CleanupFailed(info),
        }
    }
}

impl std::fmt::Display for MoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoveError::Io(e) => write!(f, "{e}"),
            MoveError::Cleanup(info) => write!(f, "{info}"),
        }
    }
}

impl From<io::Error> for MoveError {
    fn from(e: io::Error) -> Self {
        MoveError::Io(e)
    }
}

fn read_regular_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Atomically move `src` to `dst` without ever overwriting an existing `dst`.
pub fn move_file_no_clobber(src: &Path, dst: &Path) -> Result<(), MoveError> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "NUL byte in source path"))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "NUL byte in destination path"))?;
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                c_src.as_ptr(),
                libc::AT_FDCWD,
                c_dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EEXIST) => Err(MoveError::Io(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("Destination already exists: {}", dst.display()),
            ))),
            Some(libc::EXDEV) => cross_fs_copy_no_clobber(src, dst, false),
            Some(libc::ENOSYS) | Some(libc::EINVAL) => hard_link_or_cross_fs(src, dst, false),
            _ => Err(MoveError::Io(err)),
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "NUL byte in source path"))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "NUL byte in destination path"))?;
        let rc = unsafe { libc::renamex_np(c_src.as_ptr(), c_dst.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EEXIST) => Err(MoveError::Io(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("Destination already exists: {}", dst.display()),
            ))),
            Some(libc::EXDEV) => cross_fs_copy_no_clobber(src, dst, false),
            Some(libc::ENOTSUP) => hard_link_or_cross_fs(src, dst, false),
            _ => Err(MoveError::Io(err)),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        hard_link_or_cross_fs(src, dst, false)
    }
}

pub fn hard_link_or_cross_fs(
    src: &Path,
    dst: &Path,
    inject_unlink_failure: bool,
) -> Result<(), MoveError> {
    match fs::hard_link(src, dst) {
        Ok(()) => {
            let remove_res = if inject_unlink_failure {
                Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "injected hard-link source removal failure",
                ))
            } else {
                fs::remove_file(src)
            };
            if let Err(e) = remove_res {
                if let Err(cleanup_err) = fs::remove_file(dst) {
                    return Err(MoveError::Cleanup(Box::new(CleanupFailureInfo {
                        operation: "hard_link_move",
                        cause: e.to_string(),
                        cleanup_error: cleanup_err.to_string(),
                        stranded_files: vec![src.display().to_string(), dst.display().to_string()],
                        recovery_hint: "Both source and destination links remain; remove the unintended duplicate link after verifying integrity.".to_string(),
                    })));
                }
                return Err(MoveError::Io(e));
            }
            Ok(())
        }
        Err(e) if is_cross_device_error(&e) => cross_fs_copy_no_clobber(src, dst, false),
        Err(e) => Err(MoveError::Io(e)),
    }
}

fn is_cross_device_error(err: &io::Error) -> bool {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::EXDEV) {
        return true;
    }
    #[cfg(windows)]
    if err.raw_os_error() == Some(17) {
        // ERROR_NOT_SAME_DEVICE
        return true;
    }
    err.kind() == ErrorKind::CrossesDevices
}

/// Perform a staged cross-filesystem copy to `dst` without overwriting an existing `dst`.
///
/// Surfaces any staging or rollback cleanup failure via `MoveError::Cleanup`.
pub fn cross_fs_copy_no_clobber(
    src: &Path,
    dst: &Path,
    inject_copy_failure: bool,
) -> Result<(), MoveError> {
    let parent = dst.parent().ok_or_else(|| {
        MoveError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Destination has no parent directory: {}", dst.display()),
        ))
    })?;
    let tmp_path = parent.join(format!(".kernlock_staging_{}", Uuid::new_v4()));

    let copy_res = (|| -> io::Result<()> {
        let mut src_opts = OpenOptions::new();
        src_opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            src_opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut src_file = src_opts.open(src)?;

        let mut dst_opts = OpenOptions::new();
        dst_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            dst_opts.mode(0o600);
        }
        let mut tmp_file = dst_opts.open(&tmp_path)?;

        if inject_copy_failure {
            use std::io::Write;
            tmp_file.write_all(b"partial")?;
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "injected cross-filesystem copy failure",
            ));
        }

        io::copy(&mut src_file, &mut tmp_file)?;
        tmp_file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = copy_res {
        if tmp_path.exists() {
            if let Err(cleanup_err) = fs::remove_file(&tmp_path) {
                return Err(MoveError::Cleanup(Box::new(CleanupFailureInfo {
                    operation: "cross_fs_copy",
                    cause: e.to_string(),
                    cleanup_error: cleanup_err.to_string(),
                    stranded_files: vec![tmp_path.display().to_string()],
                    recovery_hint:
                        "Remove partial staging file after verifying source remains intact."
                            .to_string(),
                })));
            }
        }
        return Err(MoveError::Io(e));
    }

    // Atomically publish staging file to `dst` without clobbering any existing file.
    if let Err(e) = fs::hard_link(&tmp_path, dst) {
        if let Err(cleanup_err) = fs::remove_file(&tmp_path) {
            return Err(MoveError::Cleanup(Box::new(CleanupFailureInfo {
                operation: "cross_fs_publish",
                cause: e.to_string(),
                cleanup_error: cleanup_err.to_string(),
                stranded_files: vec![tmp_path.display().to_string()],
                recovery_hint: "Remove staging file; destination was not modified.".to_string(),
            })));
        }
        return Err(MoveError::Io(e));
    }

    if let Err(cleanup_err) = fs::remove_file(&tmp_path) {
        return Err(MoveError::Cleanup(Box::new(CleanupFailureInfo {
            operation: "cross_fs_staging_unlink",
            cause: "Published destination successfully, but failed to remove staging file"
                .to_string(),
            cleanup_error: cleanup_err.to_string(),
            stranded_files: vec![tmp_path.display().to_string(), src.display().to_string()],
            recovery_hint:
                "Remove temporary staging file and verify whether source file should be removed."
                    .to_string(),
        })));
    }

    if let Err(e) = fs::remove_file(src) {
        if let Err(cleanup_err) = fs::remove_file(dst) {
            return Err(MoveError::Cleanup(Box::new(CleanupFailureInfo {
                operation: "cross_fs_source_unlink",
                cause: e.to_string(),
                cleanup_error: cleanup_err.to_string(),
                stranded_files: vec![src.display().to_string(), dst.display().to_string()],
                recovery_hint: "Both source and destination files exist; remove the duplicate after verifying SHA-256.".to_string(),
            })));
        }
        return Err(MoveError::Io(e));
    }

    Ok(())
}

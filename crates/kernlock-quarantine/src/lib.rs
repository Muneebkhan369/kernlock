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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInjection {
    None,
    PermissionChange,
    DatabaseWrite,
    PermissionChangeAndRollbackMove,
    DatabaseWriteAndRollbackMove,
    DestinationRaceCreated,
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

        move_file_no_clobber(&canonical_orig, &vault_path)?;

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
                Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "injected rollback move failure",
                ))
            } else {
                move_file_no_clobber(&vault_path, &canonical_orig)
            };

            if let Err(rb_err) = rollback_move {
                return Err(QuarantineError::RollbackFailed(Box::new(
                    RollbackFailureInfo {
                        stage: "vault_chmod",
                        cause: e.to_string(),
                        rollback_error: rb_err.to_string(),
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

    pub fn restore_file(&self, id: Uuid) -> Result<QuarantineRecord, QuarantineError> {
        self.restore_file_with_injection(id, FailureInjection::None)
    }

    pub fn restore_file_with_injection(
        &self,
        id: Uuid,
        inject: FailureInjection,
    ) -> Result<QuarantineRecord, QuarantineError> {
        let mut record = self.storage.get_quarantine(id)?;
        if record.status != QuarantineStatus::Quarantined {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }

        let vault_path = PathBuf::from(&record.vault_path);
        let orig_path = PathBuf::from(&record.original_path);

        if fs::symlink_metadata(&orig_path).is_ok() {
            return Err(QuarantineError::DestinationExists(
                record.original_path.clone(),
            ));
        }

        let vault_meta = fs::symlink_metadata(&vault_path)?;
        if vault_meta.file_type().is_symlink() {
            return Err(QuarantineError::SymlinkRejected(
                vault_path.display().to_string(),
            ));
        }

        let bytes = read_regular_nofollow(&vault_path)?;
        let current_sha = sha256_hex(&bytes);
        if current_sha != record.sha256 {
            return Err(QuarantineError::IntegrityMismatch(id.to_string()));
        }

        if let Some(parent) = orig_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Simulate a TOCTOU race where a user file is created at `orig_path`
        // after our initial `symlink_metadata` check and before the atomic move.
        if inject == FailureInjection::DestinationRaceCreated {
            fs::write(&orig_path, b"user file created during race window")?;
        }

        match move_file_no_clobber(&vault_path, &orig_path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(QuarantineError::DestinationExists(
                    record.original_path.clone(),
                ));
            }
            Err(e) => return Err(e.into()),
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
                Ok(())
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
            self.storage
                .update_quarantine_status(id, QuarantineStatus::Restored, Some(now))
        };

        if let Err(e) = db_res {
            let rollback_res: Result<(), String> = (|| {
                if inject == FailureInjection::DatabaseWriteAndRollbackMove {
                    return Err("injected restore db rollback move failure".to_string());
                }
                set_mode(&orig_path, 0o600).map_err(|err| format!("re-lock mode failed: {err}"))?;
                move_file_no_clobber(&orig_path, &vault_path)
                    .map_err(|err| format!("move back to vault failed: {err}"))?;
                Ok(())
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
        let record = self.storage.get_quarantine(id)?;
        if record.status != QuarantineStatus::Quarantined {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }
        let vault_path = PathBuf::from(&record.vault_path);
        if vault_path.exists() {
            fs::remove_file(&vault_path)?;
        }
        self.storage
            .update_quarantine_status(id, QuarantineStatus::Deleted, None)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>, QuarantineError> {
        Ok(self.storage.list_quarantine()?)
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
///
/// Uses kernel-level `RENAME_NOREPLACE` (Linux) / `RENAME_EXCL` (macOS) when
/// supported, falls back to atomic `hard_link` + `remove_file` when needed,
/// and performs a staged no-clobber copy with cleanup on cross-device moves (`EXDEV`).
pub fn move_file_no_clobber(src: &Path, dst: &Path) -> io::Result<()> {
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
            Some(libc::EEXIST) => Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("Destination already exists: {}", dst.display()),
            )),
            Some(libc::EXDEV) => cross_fs_copy_no_clobber(src, dst, false),
            Some(libc::ENOSYS) | Some(libc::EINVAL) => hard_link_or_cross_fs(src, dst),
            _ => Err(err),
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
            Some(libc::EEXIST) => Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("Destination already exists: {}", dst.display()),
            )),
            Some(libc::EXDEV) => cross_fs_copy_no_clobber(src, dst, false),
            Some(libc::ENOTSUP) => hard_link_or_cross_fs(src, dst),
            _ => Err(err),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        hard_link_or_cross_fs(src, dst)
    }
}

fn hard_link_or_cross_fs(src: &Path, dst: &Path) -> io::Result<()> {
    match fs::hard_link(src, dst) {
        Ok(()) => {
            if let Err(e) = fs::remove_file(src) {
                let _ = fs::remove_file(dst);
                return Err(e);
            }
            Ok(())
        }
        Err(e) if is_cross_device_error(&e) => cross_fs_copy_no_clobber(src, dst, false),
        Err(e) => Err(e),
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
/// Always cleans up the temporary staging file on any error (including injected copy failure).
pub fn cross_fs_copy_no_clobber(
    src: &Path,
    dst: &Path,
    inject_copy_failure: bool,
) -> io::Result<()> {
    let parent = dst.parent().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("Destination has no parent directory: {}", dst.display()),
        )
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
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomically publish staging file to `dst` without clobbering any existing file.
    if let Err(e) = fs::hard_link(&tmp_path, dst) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    let _ = fs::remove_file(&tmp_path);

    if let Err(e) = fs::remove_file(src) {
        let _ = fs::remove_file(dst);
        return Err(e);
    }

    Ok(())
}

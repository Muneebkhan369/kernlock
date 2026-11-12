use chrono::Utc;
use kernlock_core::{sha256_hex, QuarantineRecord, QuarantineStatus};
use kernlock_storage::{Storage, StorageError};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInjection {
    None,
    PermissionChange,
    DatabaseWrite,
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
            let _ = fs::set_permissions(&vault, fs::Permissions::from_mode(0o700));
        }
        let canonical_vault = fs::canonicalize(&vault).unwrap_or(vault);
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
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let original_mode = 0o644u32;

        let id = Uuid::new_v4();
        let vault_path = self.vault_dir.join(format!("{}.locked", id));

        move_file_safely(&canonical_orig, &vault_path)?;

        // Stage 2: Set restrictive 0600 permissions inside vault; roll back move on failure.
        let perm_res: Result<(), std::io::Error> = if inject == FailureInjection::PermissionChange {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected permission failure",
            ))
        } else {
            set_mode(&vault_path, 0o600)
        };

        if let Err(e) = perm_res {
            let _ = move_file_safely(&vault_path, &canonical_orig);
            let _ = set_mode(&canonical_orig, original_mode);
            return Err(QuarantineError::RolledBack {
                stage: "vault_chmod",
                cause: e.to_string(),
            });
        }

        let record = QuarantineRecord {
            id,
            original_path: canonical_orig.display().to_string(),
            vault_path: vault_path.display().to_string(),
            sha256,
            original_mode,
            size_bytes,
            reason: reason.to_string(),
            quarantined_at: Utc::now(),
            restored_at: None,
            status: QuarantineStatus::Quarantined,
        };

        // Stage 3: Persist metadata in SQLite; roll back move and restore permissions on failure.
        let db_res = if inject == FailureInjection::DatabaseWrite {
            Err(StorageError::NotFound(
                "injected database write failure".to_string(),
            ))
        } else {
            self.storage.insert_quarantine(&record)
        };

        if let Err(e) = db_res {
            let _ = set_mode(&vault_path, original_mode);
            let _ = move_file_safely(&vault_path, &canonical_orig);
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

        move_file_safely(&vault_path, &orig_path)?;

        let perm_res: Result<(), std::io::Error> = if inject == FailureInjection::PermissionChange {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected restore permission failure",
            ))
        } else {
            set_mode(&orig_path, record.original_mode)
        };

        if let Err(e) = perm_res {
            let _ = move_file_safely(&orig_path, &vault_path);
            let _ = set_mode(&vault_path, 0o600);
            return Err(QuarantineError::RolledBack {
                stage: "restore_chmod",
                cause: e.to_string(),
            });
        }

        let now = Utc::now();
        let db_res = if inject == FailureInjection::DatabaseWrite {
            Err(StorageError::NotFound(
                "injected restore db failure".to_string(),
            ))
        } else {
            self.storage
                .update_quarantine_status(id, QuarantineStatus::Restored, Some(now))
        };

        if let Err(e) = db_res {
            let _ = set_mode(&orig_path, 0o600);
            let _ = move_file_safely(&orig_path, &vault_path);
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

fn read_regular_nofollow(path: &Path) -> Result<Vec<u8>, std::io::Error> {
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
fn set_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), std::io::Error> {
    Ok(())
}

fn move_file_safely(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Cross-filesystem fallback: copy, fsync, then remove source
            fs::copy(src, dst)?;
            let file = fs::File::open(dst)?;
            file.sync_all()?;
            fs::remove_file(src)?;
            Ok(())
        }
    }
}

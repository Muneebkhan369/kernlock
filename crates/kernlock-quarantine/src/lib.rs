use chrono::Utc;
use kernlock_core::{sha256_hex, QuarantineRecord, QuarantineStatus};
use kernlock_storage::{Storage, StorageError};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Target is not a regular file: {0}")]
    NotAFile(String),
    #[error("Cannot restore: destination already exists at {0}")]
    DestinationExists(String),
    #[error("Record {0} is not currently in quarantined state")]
    InvalidState(String),
    #[error("Integrity mismatch for quarantined file {0}")]
    IntegrityMismatch(String),
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
        Ok(Self {
            vault_dir: vault,
            storage,
        })
    }

    pub fn quarantine_file<P: AsRef<Path>>(
        &self,
        path: P,
        reason: &str,
    ) -> Result<QuarantineRecord, QuarantineError> {
        let orig_path = path.as_ref();
        let metadata = fs::symlink_metadata(orig_path)?;
        if !metadata.is_file() {
            return Err(QuarantineError::NotAFile(orig_path.display().to_string()));
        }

        let bytes = fs::read(orig_path)?;
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

        move_file_safely(orig_path, &vault_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Remove execute permissions inside the vault
            fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o600))?;
        }

        let record = QuarantineRecord {
            id,
            original_path: orig_path.display().to_string(),
            vault_path: vault_path.display().to_string(),
            sha256,
            original_mode,
            size_bytes,
            reason: reason.to_string(),
            quarantined_at: Utc::now(),
            restored_at: None,
            status: QuarantineStatus::Quarantined,
        };

        self.storage.insert_quarantine(&record)?;
        Ok(record)
    }

    pub fn restore_file(&self, id: Uuid) -> Result<QuarantineRecord, QuarantineError> {
        let mut record = self.storage.get_quarantine(id)?;
        if record.status != QuarantineStatus::Quarantined {
            return Err(QuarantineError::InvalidState(id.to_string()));
        }

        let vault_path = PathBuf::from(&record.vault_path);
        let orig_path = PathBuf::from(&record.original_path);

        if orig_path.exists() {
            return Err(QuarantineError::DestinationExists(
                record.original_path.clone(),
            ));
        }

        let bytes = fs::read(&vault_path)?;
        let current_sha = sha256_hex(&bytes);
        if current_sha != record.sha256 {
            return Err(QuarantineError::IntegrityMismatch(id.to_string()));
        }

        if let Some(parent) = orig_path.parent() {
            fs::create_dir_all(parent)?;
        }

        move_file_safely(&vault_path, &orig_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&orig_path, fs::Permissions::from_mode(record.original_mode))?;
        }

        let now = Utc::now();
        self.storage
            .update_quarantine_status(id, QuarantineStatus::Restored, Some(now))?;
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

fn move_file_safely(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Cross-filesystem fallback
            fs::copy(src, dst)?;
            let file = fs::File::open(dst)?;
            file.sync_all()?;
            fs::remove_file(src)?;
            Ok(())
        }
    }
}

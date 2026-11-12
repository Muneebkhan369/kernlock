use chrono::{DateTime, Utc};
use kernlock_core::{
    AlertStatus, EventCategory, FileScanResult, PolicyConfig, QuarantineRecord, QuarantineStatus,
    ScanJobSummary, ScanMode, ScanStatus, SecurityEvent, Severity, ThreatAlert, ThreatRecord,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Lock poisoned")]
    Lock,
    #[error("Record not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        if let Some(parent) = path.as_ref().parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                action_taken TEXT NOT NULL,
                rule_ids TEXT NOT NULL,
                metadata TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp DESC);

            CREATE TABLE IF NOT EXISTS threat_alerts (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                recommended_action TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON threat_alerts(timestamp DESC);

            CREATE TABLE IF NOT EXISTS quarantine_records (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                vault_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                original_mode INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                restored_at TEXT,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                files_scanned INTEGER NOT NULL,
                files_skipped INTEGER NOT NULL,
                threats_found INTEGER NOT NULL,
                errors_count INTEGER NOT NULL,
                target_paths TEXT NOT NULL,
                threats_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_jobs_ts ON scan_jobs(started_at DESC);

            CREATE TABLE IF NOT EXISTS threat_history (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                action_taken TEXT NOT NULL,
                quarantine_id TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_threat_history_ts ON threat_history(timestamp DESC);
            ",
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &SecurityEvent) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute(
            "INSERT INTO security_events
             (id, timestamp, category, severity, title, description, target, risk_score, action_taken, rule_ids, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.id.to_string(),
                event.timestamp.to_rfc3339(),
                serde_json::to_string(&event.category)?,
                serde_json::to_string(&event.severity)?,
                event.title,
                event.description,
                event.target,
                event.risk_score as i64,
                event.action_taken,
                serde_json::to_string(&event.rule_ids)?,
                serde_json::to_string(&event.metadata)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<SecurityEvent>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, category, severity, title, description, target, risk_score, action_taken, rule_ids, metadata
             FROM security_events ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let id_str: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let cat_str: String = row.get(2)?;
            let sev_str: String = row.get(3)?;
            let title: String = row.get(4)?;
            let description: String = row.get(5)?;
            let target: String = row.get(6)?;
            let risk_score: i64 = row.get(7)?;
            let action_taken: String = row.get(8)?;
            let rule_ids_str: String = row.get(9)?;
            let metadata_str: String = row.get(10)?;

            Ok((
                id_str,
                ts_str,
                cat_str,
                sev_str,
                title,
                description,
                target,
                risk_score,
                action_taken,
                rule_ids_str,
                metadata_str,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (
                id_str,
                ts_str,
                cat_str,
                sev_str,
                title,
                description,
                target,
                risk_score,
                action_taken,
                rule_ids_str,
                metadata_str,
            ) = r?;
            let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());
            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let category: EventCategory = serde_json::from_str(&cat_str)?;
            let severity: Severity = serde_json::from_str(&sev_str)?;
            let rule_ids: Vec<String> = serde_json::from_str(&rule_ids_str)?;
            let metadata: serde_json::Value = serde_json::from_str(&metadata_str)?;
            out.push(SecurityEvent {
                id,
                timestamp,
                category,
                severity,
                title,
                description,
                target,
                risk_score: risk_score as u32,
                action_taken,
                rule_ids,
                metadata,
            });
        }
        Ok(out)
    }

    pub fn insert_alert(&self, alert: &ThreatAlert) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute(
            "INSERT INTO threat_alerts
             (id, event_id, timestamp, severity, title, explanation, target, risk_score, status, recommended_action)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                alert.id.to_string(),
                alert.event_id.to_string(),
                alert.timestamp.to_rfc3339(),
                serde_json::to_string(&alert.severity)?,
                alert.title,
                alert.explanation,
                alert.target,
                alert.risk_score as i64,
                serde_json::to_string(&alert.status)?,
                alert.recommended_action,
            ],
        )?;
        Ok(())
    }

    pub fn list_alerts(&self, limit: usize) -> Result<Vec<ThreatAlert>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let mut stmt = conn.prepare(
            "SELECT id, event_id, timestamp, severity, title, explanation, target, risk_score, status, recommended_action
             FROM threat_alerts ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id_s, ev_s, ts_s, sev_s, title, explanation, target, score, status_s, rec) = r?;
            out.push(ThreatAlert {
                id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                event_id: Uuid::parse_str(&ev_s).unwrap_or_else(|_| Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&ts_s)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                severity: serde_json::from_str(&sev_s)?,
                title,
                explanation,
                target,
                risk_score: score as u32,
                status: serde_json::from_str(&status_s)?,
                recommended_action: rec,
            });
        }
        Ok(out)
    }

    pub fn update_alert_status(&self, id: Uuid, status: AlertStatus) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let updated = conn.execute(
            "UPDATE threat_alerts SET status = ?1 WHERE id = ?2",
            params![serde_json::to_string(&status)?, id.to_string()],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound(format!("alert {}", id)));
        }
        Ok(())
    }

    pub fn insert_quarantine(&self, rec: &QuarantineRecord) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute(
            "INSERT INTO quarantine_records
             (id, original_path, vault_path, sha256, original_mode, size_bytes, reason, quarantined_at, restored_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rec.id.to_string(),
                rec.original_path,
                rec.vault_path,
                rec.sha256,
                rec.original_mode as i64,
                rec.size_bytes as i64,
                rec.reason,
                rec.quarantined_at.to_rfc3339(),
                rec.restored_at.map(|d| d.to_rfc3339()),
                serde_json::to_string(&rec.status)?,
            ],
        )?;
        Ok(())
    }

    pub fn get_quarantine(&self, id: Uuid) -> Result<QuarantineRecord, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let row = conn
            .query_row(
                "SELECT id, original_path, vault_path, sha256, original_mode, size_bytes, reason, quarantined_at, restored_at, status
                 FROM quarantine_records WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()?;

        match row {
            Some((id_s, orig, vault, sha, mode, size, reason, q_at, r_at, status_s)) => {
                Ok(QuarantineRecord {
                    id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                    original_path: orig,
                    vault_path: vault,
                    sha256: sha,
                    original_mode: mode as u32,
                    size_bytes: size as u64,
                    reason,
                    quarantined_at: DateTime::parse_from_rfc3339(&q_at)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    restored_at: r_at.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                    status: serde_json::from_str(&status_s)?,
                })
            }
            None => Err(StorageError::NotFound(format!("quarantine {}", id))),
        }
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let mut stmt = conn.prepare(
            "SELECT id, original_path, vault_path, sha256, original_mode, size_bytes, reason, quarantined_at, restored_at, status
             FROM quarantine_records ORDER BY quarantined_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id_s, orig, vault, sha, mode, size, reason, q_at, r_at, status_s) = r?;
            out.push(QuarantineRecord {
                id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                original_path: orig,
                vault_path: vault,
                sha256: sha,
                original_mode: mode as u32,
                size_bytes: size as u64,
                reason,
                quarantined_at: DateTime::parse_from_rfc3339(&q_at)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restored_at: r_at.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                status: serde_json::from_str(&status_s)?,
            });
        }
        Ok(out)
    }

    pub fn list_quarantine_by_status(
        &self,
        status: QuarantineStatus,
    ) -> Result<Vec<QuarantineRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let status_json = serde_json::to_string(&status)?;
        let mut stmt = conn.prepare(
            "SELECT id, original_path, vault_path, sha256, original_mode, size_bytes, reason, quarantined_at, restored_at, status
             FROM quarantine_records WHERE status = ?1 ORDER BY quarantined_at DESC",
        )?;
        let rows = stmt.query_map(params![status_json], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id_s, orig, vault, sha, mode, size, reason, q_at, r_at, status_s) = r?;
            out.push(QuarantineRecord {
                id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                original_path: orig,
                vault_path: vault,
                sha256: sha,
                original_mode: mode as u32,
                size_bytes: size as u64,
                reason,
                quarantined_at: DateTime::parse_from_rfc3339(&q_at)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restored_at: r_at.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                status: serde_json::from_str(&status_s)?,
            });
        }
        Ok(out)
    }

    pub fn transition_quarantine_status(
        &self,
        id: Uuid,
        expected: QuarantineStatus,
        target: QuarantineStatus,
        restored_at: Option<DateTime<Utc>>,
    ) -> Result<bool, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let updated = conn.execute(
            "UPDATE quarantine_records SET status = ?1, restored_at = ?2 WHERE id = ?3 AND status = ?4",
            params![
                serde_json::to_string(&target)?,
                restored_at.map(|d| d.to_rfc3339()),
                id.to_string(),
                serde_json::to_string(&expected)?
            ],
        )?;
        Ok(updated > 0)
    }

    pub fn transition_quarantine_status_from_any(
        &self,
        id: Uuid,
        expected_any: &[QuarantineStatus],
        target: QuarantineStatus,
        restored_at: Option<DateTime<Utc>>,
    ) -> Result<bool, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        if expected_any.is_empty() {
            return Ok(false);
        }
        let placeholders: Vec<String> = (4..4 + expected_any.len())
            .map(|i| format!("?{}", i))
            .collect();
        let query = format!(
            "UPDATE quarantine_records SET status = ?1, restored_at = ?2 WHERE id = ?3 AND status IN ({})",
            placeholders.join(", ")
        );
        let target_json = serde_json::to_string(&target)?;
        let restored_rfc = restored_at.map(|d| d.to_rfc3339());
        let id_str = id.to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(target_json),
            Box::new(restored_rfc),
            Box::new(id_str),
        ];
        for st in expected_any {
            params_vec.push(Box::new(serde_json::to_string(st)?));
        }
        let params_slice: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let updated = conn.execute(&query, rusqlite::params_from_iter(params_slice))?;
        Ok(updated > 0)
    }

    pub fn update_quarantine_status(
        &self,
        id: Uuid,
        status: QuarantineStatus,
        restored_at: Option<DateTime<Utc>>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let updated = conn.execute(
            "UPDATE quarantine_records SET status = ?1, restored_at = ?2 WHERE id = ?3",
            params![
                serde_json::to_string(&status)?,
                restored_at.map(|d| d.to_rfc3339()),
                id.to_string()
            ],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound(format!("quarantine {}", id)));
        }
        Ok(())
    }

    pub fn get_policy(&self) -> Result<PolicyConfig, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let json: Option<String> = conn
            .query_row(
                "SELECT config_json FROM policy_config WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match json {
            Some(s) => Ok(serde_json::from_str(&s)?),
            None => Ok(PolicyConfig::default()),
        }
    }

    pub fn save_policy(&self, policy: &PolicyConfig) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let json = serde_json::to_string(policy)?;
        conn.execute(
            "INSERT INTO policy_config (id, config_json, updated_at) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at",
            params![json, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn insert_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute(
            "INSERT INTO scan_jobs
             (id, mode, status, started_at, completed_at, files_scanned, files_skipped, threats_found, errors_count, target_paths, threats_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                job.id.to_string(),
                serde_json::to_string(&job.mode)?,
                serde_json::to_string(&job.status)?,
                job.started_at.to_rfc3339(),
                job.completed_at.map(|d| d.to_rfc3339()),
                job.files_scanned as i64,
                job.files_skipped as i64,
                job.threats_found as i64,
                job.errors_count as i64,
                serde_json::to_string(&job.target_paths)?,
                serde_json::to_string(&job.threats)?,
            ],
        )?;
        Ok(())
    }

    pub fn update_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let updated = conn.execute(
            "UPDATE scan_jobs SET
             mode = ?1, status = ?2, completed_at = ?3, files_scanned = ?4, files_skipped = ?5,
             threats_found = ?6, errors_count = ?7, target_paths = ?8, threats_json = ?9
             WHERE id = ?10",
            params![
                serde_json::to_string(&job.mode)?,
                serde_json::to_string(&job.status)?,
                job.completed_at.map(|d| d.to_rfc3339()),
                job.files_scanned as i64,
                job.files_skipped as i64,
                job.threats_found as i64,
                job.errors_count as i64,
                serde_json::to_string(&job.target_paths)?,
                serde_json::to_string(&job.threats)?,
                job.id.to_string(),
            ],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound(format!("scan job {}", job.id)));
        }
        Ok(())
    }

    pub fn get_scan_job(&self, id: Uuid) -> Result<ScanJobSummary, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let row = conn
            .query_row(
                "SELECT id, mode, status, started_at, completed_at, files_scanned, files_skipped, threats_found, errors_count, target_paths, threats_json
                 FROM scan_jobs WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .optional()?;

        match row {
            Some((
                id_s,
                mode_s,
                status_s,
                start_s,
                end_s,
                scanned,
                skipped,
                threats,
                errors,
                targets_s,
                threats_s,
            )) => {
                let id = Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4());
                let mode: ScanMode = serde_json::from_str(&mode_s)?;
                let status: ScanStatus = serde_json::from_str(&status_s)?;
                let started_at = DateTime::parse_from_rfc3339(&start_s)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let completed_at = end_s.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                });
                let target_paths: Vec<String> = serde_json::from_str(&targets_s)?;
                let threats_list: Vec<FileScanResult> = serde_json::from_str(&threats_s)?;

                Ok(ScanJobSummary {
                    id,
                    mode,
                    status,
                    started_at,
                    completed_at,
                    files_scanned: scanned as usize,
                    files_skipped: skipped as usize,
                    threats_found: threats as usize,
                    errors_count: errors as usize,
                    target_paths,
                    threats: threats_list,
                })
            }
            None => Err(StorageError::NotFound(format!("scan job {}", id))),
        }
    }

    pub fn list_scan_jobs(&self, limit: usize) -> Result<Vec<ScanJobSummary>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let mut stmt = conn.prepare(
            "SELECT id, mode, status, started_at, completed_at, files_scanned, files_skipped, threats_found, errors_count, target_paths, threats_json
             FROM scan_jobs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (
                id_s,
                mode_s,
                status_s,
                start_s,
                end_s,
                scanned,
                skipped,
                threats,
                errors,
                targets_s,
                threats_s,
            ) = r?;
            out.push(ScanJobSummary {
                id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                mode: serde_json::from_str(&mode_s)?,
                status: serde_json::from_str(&status_s)?,
                started_at: DateTime::parse_from_rfc3339(&start_s)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                completed_at: end_s.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                files_scanned: scanned as usize,
                files_skipped: skipped as usize,
                threats_found: threats as usize,
                errors_count: errors as usize,
                target_paths: serde_json::from_str(&targets_s)?,
                threats: serde_json::from_str(&threats_s)?,
            });
        }
        Ok(out)
    }

    pub fn insert_threat_record(&self, record: &ThreatRecord) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        conn.execute(
            "INSERT INTO threat_history
             (id, timestamp, threat_name, path, sha256, severity, confidence, risk_score, action_taken, quarantine_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.id.to_string(),
                record.timestamp.to_rfc3339(),
                record.threat_name,
                record.path,
                record.sha256,
                serde_json::to_string(&record.severity)?,
                serde_json::to_string(&record.confidence)?,
                record.risk_score as i64,
                record.action_taken,
                record.quarantine_id.map(|u| u.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn list_threat_records(&self, limit: usize) -> Result<Vec<ThreatRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Lock)?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, threat_name, path, sha256, severity, confidence, risk_score, action_taken, quarantine_id
             FROM threat_history ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })?;

        let mut out = Vec::new();
        for r in rows {
            let (id_s, ts_s, threat_name, path, sha256, sev_s, conf_s, score, action, q_id_s) = r?;
            out.push(ThreatRecord {
                id: Uuid::parse_str(&id_s).unwrap_or_else(|_| Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&ts_s)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                threat_name,
                path,
                sha256,
                severity: serde_json::from_str(&sev_s)?,
                confidence: serde_json::from_str(&conf_s)?,
                risk_score: score as u32,
                action_taken: action,
                quarantine_id: q_id_s.and_then(|s| Uuid::parse_str(&s).ok()),
            });
        }
        Ok(out)
    }
}

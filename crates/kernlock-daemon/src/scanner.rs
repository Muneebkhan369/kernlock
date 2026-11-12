use chrono::Utc;
use kernlock_core::{
    scan_file_streaming, AlertStatus, EventCategory, RuleEngine, ScanJobSummary, ScanMode,
    ScanProgress, ScanStatus, SecurityEvent, SecurityMode, ThreatAlert, ThreatRecord,
};
use kernlock_platform::PlatformSecurityProvider;
use kernlock_quarantine::QuarantineManager;
use kernlock_storage::Storage;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug)]
pub enum ScanError {
    AlreadyRunning,
    #[allow(dead_code)]
    StartFailed(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::AlreadyRunning => write!(f, "A scan is already in progress"),
            ScanError::StartFailed(msg) => write!(f, "Failed to start scan: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {}

#[derive(Clone)]
pub struct ScanManager {
    rules: Arc<RuleEngine>,
    storage: Storage,
    quarantine: QuarantineManager,
    provider: Arc<Box<dyn PlatformSecurityProvider>>,
    current_scan: Arc<Mutex<Option<ScanProgress>>>,
    cancel_flag: Arc<AtomicBool>,
    is_scanning: Arc<AtomicBool>,
}

impl ScanManager {
    pub fn new(
        rules: Arc<RuleEngine>,
        storage: Storage,
        quarantine: QuarantineManager,
        provider: Arc<Box<dyn PlatformSecurityProvider>>,
    ) -> Self {
        Self {
            rules,
            storage,
            quarantine,
            provider,
            current_scan: Arc::new(Mutex::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            is_scanning: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn current_progress(&self) -> Option<ScanProgress> {
        let guard = self.current_scan.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|p| {
            let mut prog = p.clone();
            if !prog.is_complete && !prog.is_cancelled {
                let now = Utc::now();
                prog.elapsed_seconds = (now - prog.started_at).num_milliseconds() as f64 / 1000.0;
            }
            prog
        })
    }

    pub fn is_running(&self) -> bool {
        self.is_scanning.load(Ordering::SeqCst)
    }

    pub fn cancel_current_scan(&self) -> bool {
        if self.is_running() {
            self.cancel_flag.store(true, Ordering::SeqCst);
            if let Ok(mut guard) = self.current_scan.lock() {
                if let Some(ref mut prog) = *guard {
                    prog.is_cancelled = true;
                    prog.status = ScanStatus::Cancelled;
                }
            }
            true
        } else {
            false
        }
    }

    pub async fn start_scan(
        &self,
        mode: ScanMode,
        custom_paths: Option<Vec<String>>,
    ) -> Result<Uuid, ScanError> {
        if self
            .is_scanning
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ScanError::AlreadyRunning);
        }

        let scan_id = Uuid::new_v4();
        let started_at = Utc::now();
        self.cancel_flag.store(false, Ordering::SeqCst);

        let initial_progress = ScanProgress {
            scan_id,
            mode,
            status: ScanStatus::Running,
            current_path: "Initializing scan target paths...".to_string(),
            files_scanned: 0,
            files_skipped: 0,
            threats_found: 0,
            errors_count: 0,
            is_complete: false,
            is_cancelled: false,
            started_at,
            elapsed_seconds: 0.0,
        };

        {
            let mut guard = self.current_scan.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(initial_progress);
        }

        let self_clone = self.clone();
        let is_scanning_flag = self.is_scanning.clone();

        tokio::spawn(async move {
            struct ScanGuard(Arc<AtomicBool>);
            impl Drop for ScanGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::SeqCst);
                }
            }
            let _guard = ScanGuard(is_scanning_flag);
            self_clone.execute_scan(scan_id, mode, custom_paths).await;
        });

        Ok(scan_id)
    }

    async fn execute_scan(&self, scan_id: Uuid, mode: ScanMode, custom_paths: Option<Vec<String>>) {
        let started_at = Utc::now();
        let policy = self.storage.get_policy().unwrap_or_default();
        let caps = self.provider.probe_capabilities(policy.mode);

        let target_paths = self.resolve_targets(mode, custom_paths);

        let mut job_summary = ScanJobSummary {
            id: scan_id,
            mode,
            status: ScanStatus::Running,
            started_at,
            completed_at: None,
            files_scanned: 0,
            files_skipped: 0,
            threats_found: 0,
            errors_count: 0,
            target_paths: target_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            threats: Vec::new(),
        };

        let _ = self.storage.insert_scan_job(&job_summary);

        info!(
            "Starting {:?} scan {} across {} target roots",
            mode,
            scan_id,
            target_paths.len()
        );

        let vault_dir = self.quarantine.vault_dir().to_path_buf();
        #[cfg(not(unix))]
        let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
        #[cfg(unix)]
        let mut visited_inodes: HashSet<(u64, u64)> = HashSet::new();

        let mut files_scanned = 0usize;
        let mut files_skipped = 0usize;
        let mut threats_found = 0usize;
        let mut errors_count = 0usize;
        let mut threats = Vec::new();
        let mut was_cancelled = false;

        let start_instant = Instant::now();

        for root in &target_paths {
            if self.cancel_flag.load(Ordering::SeqCst) {
                was_cancelled = true;
                break;
            }

            if !root.exists() {
                continue;
            }

            let mut stack = vec![root.clone()];

            while let Some(current) = stack.pop() {
                if self.cancel_flag.load(Ordering::SeqCst) {
                    was_cancelled = true;
                    break;
                }

                let path_str = current.to_string_lossy();
                if path_str.starts_with("/proc")
                    || path_str.starts_with("/sys")
                    || (path_str.starts_with("/dev") && !path_str.starts_with("/dev/shm"))
                    || path_str.starts_with("/run")
                {
                    files_skipped += 1;
                    continue;
                }

                if current.starts_with(&vault_dir) {
                    files_skipped += 1;
                    continue;
                }

                let symlink_meta = match fs::symlink_metadata(&current) {
                    Ok(m) => m,
                    Err(e) => {
                        errors_count += 1;
                        warn!("Failed metadata for {}: {}", current.display(), e);
                        continue;
                    }
                };

                if symlink_meta.file_type().is_symlink() {
                    files_skipped += 1;
                    continue;
                }

                if symlink_meta.is_dir() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        let key = (symlink_meta.dev(), symlink_meta.ino());
                        if !visited_inodes.insert(key) {
                            files_skipped += 1;
                            continue;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        if !visited_dirs.insert(current.clone()) {
                            files_skipped += 1;
                            continue;
                        }
                    }

                    let entries = match fs::read_dir(&current) {
                        Ok(entries) => entries,
                        Err(e) => {
                            errors_count += 1;
                            warn!("Cannot read dir {}: {}", current.display(), e);
                            continue;
                        }
                    };

                    for entry_res in entries {
                        match entry_res {
                            Ok(entry) => {
                                stack.push(entry.path());
                            }
                            Err(_) => {
                                errors_count += 1;
                            }
                        }
                    }
                } else if symlink_meta.is_file() {
                    if policy.is_path_excluded(&current) {
                        files_skipped += 1;
                        continue;
                    }

                    if files_scanned.is_multiple_of(10) {
                        self.update_progress(
                            scan_id,
                            &path_str,
                            files_scanned,
                            files_skipped,
                            threats_found,
                            errors_count,
                            start_instant.elapsed().as_secs_f64(),
                        );
                    }

                    match scan_file_streaming(&current, &self.rules, &policy) {
                        Ok(scan_result) => {
                            files_scanned += 1;

                            if scan_result.is_suspicious || scan_result.risk_score >= 50 {
                                threats_found += 1;
                                let mut action_taken = "Alerted".to_string();
                                let mut alert_status = AlertStatus::Open;
                                let mut quarantine_id = None;

                                if caps.active_mode != SecurityMode::Audit
                                    && scan_result.risk_score >= policy.auto_quarantine_threshold
                                {
                                    match self.quarantine.quarantine_file(
                                        &current,
                                        scan_result
                                            .threat_name
                                            .as_deref()
                                            .unwrap_or(&scan_result.summary),
                                    ) {
                                        Ok(q_rec) => {
                                            action_taken = "Quarantined".to_string();
                                            alert_status = AlertStatus::Quarantined;
                                            quarantine_id = Some(q_rec.id);
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Auto-quarantine failed for {}: {}",
                                                current.display(),
                                                e
                                            );
                                            action_taken = format!("QuarantineFailed: {}", e);
                                        }
                                    }
                                }

                                let rule_ids: Vec<String> = scan_result
                                    .matches
                                    .iter()
                                    .map(|m| m.rule_id.clone())
                                    .collect();
                                let event = SecurityEvent {
                                    id: Uuid::new_v4(),
                                    timestamp: Utc::now(),
                                    category: EventCategory::File,
                                    severity: scan_result.severity,
                                    title: format!(
                                        "Threat Detected: {}",
                                        scan_result
                                            .threat_name
                                            .as_deref()
                                            .unwrap_or("Malicious File")
                                    ),
                                    description: scan_result.summary.clone(),
                                    target: path_str.to_string(),
                                    risk_score: scan_result.risk_score,
                                    action_taken: action_taken.clone(),
                                    rule_ids,
                                    metadata: serde_json::json!({
                                        "sha256": scan_result.sha256,
                                        "entropy": scan_result.entropy,
                                        "file_type": scan_result.file_type,
                                        "confidence": scan_result.confidence,
                                    }),
                                };
                                let _ = self.storage.insert_event(&event);

                                let alert = ThreatAlert {
                                    id: Uuid::new_v4(),
                                    event_id: event.id,
                                    timestamp: event.timestamp,
                                    severity: scan_result.severity,
                                    title: event.title.clone(),
                                    explanation: scan_result.summary.clone(),
                                    target: path_str.to_string(),
                                    risk_score: scan_result.risk_score,
                                    status: alert_status,
                                    recommended_action: scan_result
                                        .matches
                                        .first()
                                        .map(|m| m.remediation.clone())
                                        .unwrap_or_else(|| {
                                            "Quarantine or isolate file.".to_string()
                                        }),
                                };
                                let _ = self.storage.insert_alert(&alert);

                                let threat_rec = ThreatRecord {
                                    id: Uuid::new_v4(),
                                    timestamp: Utc::now(),
                                    threat_name: scan_result
                                        .threat_name
                                        .clone()
                                        .unwrap_or_else(|| "Generic.Suspicious".to_string()),
                                    path: path_str.to_string(),
                                    sha256: scan_result.sha256.clone(),
                                    severity: scan_result.severity,
                                    confidence: scan_result.confidence,
                                    risk_score: scan_result.risk_score,
                                    action_taken,
                                    quarantine_id,
                                };
                                let _ = self.storage.insert_threat_record(&threat_rec);

                                threats.push(scan_result);
                            }
                        }
                        Err(e) => {
                            errors_count += 1;
                            warn!("Failed scanning {}: {}", current.display(), e);
                        }
                    }
                } else {
                    files_skipped += 1;
                }
            }
        }

        let completed_at = Utc::now();
        let final_status = if was_cancelled {
            ScanStatus::Cancelled
        } else {
            ScanStatus::Completed
        };

        job_summary.status = final_status;
        job_summary.completed_at = Some(completed_at);
        job_summary.files_scanned = files_scanned;
        job_summary.files_skipped = files_skipped;
        job_summary.threats_found = threats_found;
        job_summary.errors_count = errors_count;
        job_summary.threats = threats;

        let _ = self.storage.update_scan_job(&job_summary);

        let elapsed = start_instant.elapsed().as_secs_f64();
        info!(
            "Scan {} finished with status {:?}. Scanned {} files, skipped {}, threats {}, errors {} in {:.2}s",
            scan_id, final_status, files_scanned, files_skipped, threats_found, errors_count, elapsed
        );

        let mut guard = self.current_scan.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(ScanProgress {
            scan_id,
            mode,
            status: final_status,
            current_path: if was_cancelled {
                "Scan cancelled by user.".to_string()
            } else {
                "Scan completed.".to_string()
            },
            files_scanned,
            files_skipped,
            threats_found,
            errors_count,
            is_complete: true,
            is_cancelled: was_cancelled,
            started_at,
            elapsed_seconds: elapsed,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn update_progress(
        &self,
        scan_id: Uuid,
        current_path: &str,
        files_scanned: usize,
        files_skipped: usize,
        threats_found: usize,
        errors_count: usize,
        elapsed_seconds: f64,
    ) {
        if let Ok(mut guard) = self.current_scan.lock() {
            if let Some(ref mut p) = *guard {
                if p.scan_id == scan_id {
                    p.current_path = current_path.to_string();
                    p.files_scanned = files_scanned;
                    p.files_skipped = files_skipped;
                    p.threats_found = threats_found;
                    p.errors_count = errors_count;
                    p.elapsed_seconds = elapsed_seconds;
                }
            }
        }
    }

    fn resolve_targets(&self, mode: ScanMode, custom_paths: Option<Vec<String>>) -> Vec<PathBuf> {
        match mode {
            ScanMode::Quick => {
                let mut targets = Vec::new();
                #[cfg(target_os = "linux")]
                {
                    let candidates = [
                        "/bin",
                        "/sbin",
                        "/usr/bin",
                        "/usr/sbin",
                        "/usr/local/bin",
                        "/tmp",
                        "/dev/shm",
                        "/var/tmp",
                        "/etc/cron.d",
                        "/etc/cron.daily",
                        "/etc/cron.hourly",
                        "/etc/cron.weekly",
                        "/etc/cron.monthly",
                    ];
                    for c in candidates {
                        let p = PathBuf::from(c);
                        if p.exists() {
                            targets.push(p);
                        }
                    }
                    if let Ok(home) = std::env::var("HOME") {
                        let h = PathBuf::from(home);
                        let local_bin = h.join(".local/bin");
                        if local_bin.exists() {
                            targets.push(local_bin);
                        }
                        let downloads = h.join("Downloads");
                        if downloads.exists() {
                            targets.push(downloads);
                        }
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    if let Ok(sys_root) = std::env::var("SystemRoot") {
                        targets.push(PathBuf::from(sys_root).join("System32"));
                    }
                    if let Ok(temp) = std::env::var("TEMP") {
                        targets.push(PathBuf::from(temp));
                    }
                    if let Ok(user_prof) = std::env::var("USERPROFILE") {
                        let dl = PathBuf::from(user_prof).join("Downloads");
                        if dl.exists() {
                            targets.push(dl);
                        }
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    let candidates = ["/bin", "/sbin", "/usr/bin", "/usr/local/bin", "/tmp"];
                    for c in candidates {
                        let p = PathBuf::from(c);
                        if p.exists() {
                            targets.push(p);
                        }
                    }
                    if let Ok(home) = std::env::var("HOME") {
                        let dl = PathBuf::from(home).join("Downloads");
                        if dl.exists() {
                            targets.push(dl);
                        }
                    }
                }
                if targets.is_empty() {
                    targets.push(PathBuf::from("."));
                }
                targets
            }
            ScanMode::Full => {
                #[cfg(unix)]
                {
                    vec![PathBuf::from("/")]
                }
                #[cfg(windows)]
                {
                    vec![PathBuf::from("C:\\")]
                }
            }
            ScanMode::Custom => {
                if let Some(paths) = custom_paths {
                    paths
                        .into_iter()
                        .map(PathBuf::from)
                        .filter(|p| p.exists())
                        .collect()
                } else {
                    vec![PathBuf::from(".")]
                }
            }
        }
    }
}

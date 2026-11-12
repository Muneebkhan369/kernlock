use crate::scanner::ScanManager;
use anyhow::Result;
use chrono::Utc;
use kernlock_core::{
    analyze_command, builtin_baseline_timestamp, AlertStatus, CommandAnalysisResult,
    DefinitionStatus, EventCategory, FileScanResult, PersistenceEntry, PlatformCapabilities,
    PolicyConfig, ProcessInfo, QuarantineRecord, RuleEngine, SecurityEvent, SecurityMode,
    SecurityReport, Severity, SignedThreatBundle, ThreatAlert, BUILTIN_BASELINE_VERSION,
    OFFICIAL_PUBLIC_KEY_HEX,
};
use kernlock_platform::{
    default_provider, fanotify::FanotifyPermissionMonitor, PlatformSecurityProvider,
};
use kernlock_quarantine::QuarantineManager;
use kernlock_storage::Storage;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct KernLockEngine {
    pub rules: Arc<RuleEngine>,
    pub storage: Storage,
    pub quarantine: QuarantineManager,
    pub provider: Arc<Box<dyn PlatformSecurityProvider>>,
    pub scanner: ScanManager,
    watcher_active: Arc<Mutex<bool>>,
    fanotify_monitor: Arc<Mutex<Option<FanotifyPermissionMonitor>>>,
    definitions_status: Arc<Mutex<DefinitionStatus>>,
    trusted_keys: Arc<RwLock<HashSet<String>>>,
    update_lock: Arc<Mutex<()>>,
}

impl KernLockEngine {
    pub fn init<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let base = data_dir.as_ref();
        std::fs::create_dir_all(base)?;
        let db_path = base.join("kernlock.db");
        let vault_dir = base.join("quarantine");

        let storage = Storage::open(db_path)?;
        let quarantine = QuarantineManager::new(vault_dir, storage.clone())?;
        let recovery_report = quarantine.recover_on_startup()?;
        if !recovery_report.is_empty() {
            info!(
                "Quarantine startup recovery audit: {} recovered, {} finalized deletions, {} finalized restores, {} unverified stranded files, {} failures, {} unresolved states",
                recovery_report.recovered_to_quarantine.len(),
                recovery_report.finalized_deletions.len(),
                recovery_report.finalized_restores.len(),
                recovery_report.unverified_stranded_files.len(),
                recovery_report.recovery_failures.len(),
                recovery_report.unresolved_states.len(),
            );
        }
        let rules = Arc::new(RuleEngine::builtin());
        let provider = Arc::new(default_provider());
        let scanner = ScanManager::new(
            rules.clone(),
            storage.clone(),
            quarantine.clone(),
            provider.clone(),
        );

        let mut initial_trusted = HashSet::new();
        initial_trusted.insert(OFFICIAL_PUBLIC_KEY_HEX.to_lowercase());
        if let Ok(persisted_keys) = storage.list_trusted_keys() {
            for k in persisted_keys {
                initial_trusted.insert(k.to_lowercase());
            }
        }
        let trusted_keys = Arc::new(RwLock::new(initial_trusted));

        // Restore persisted threat definitions from database if available
        let mut initial_version = BUILTIN_BASELINE_VERSION.to_string();
        let mut initial_timestamp = builtin_baseline_timestamp();
        let mut hash_count = 5;
        let mut byte_count = 5;

        match storage.load_threat_bundle() {
            Ok(Some(persisted_bundle)) => {
                let mut is_valid = false;
                let current_trusted = trusted_keys.read().unwrap();
                for trusted in current_trusted.iter() {
                    if persisted_bundle.verify_with_hex_key(trusted).is_ok() {
                        is_valid = true;
                        break;
                    }
                }
                drop(current_trusted);

                if is_valid {
                    // Fully validate manifest (rules, regexes, hashes, byte patterns) before activation
                    match RuleEngine::validate_manifest(&persisted_bundle.manifest) {
                        Ok(()) => {
                            let new_rules = persisted_bundle.manifest.rules;
                            let new_hashes = persisted_bundle.manifest.hash_signatures;
                            let new_bytes = persisted_bundle.manifest.byte_signatures;

                            let _rule_count = new_rules.len();
                            let h_count = new_hashes.len();
                            let b_count = new_bytes.len();

                            if let Err(e) =
                                rules.replace_definitions(new_rules, new_hashes, new_bytes)
                            {
                                warn!(
                                    "Failed to activate persisted rules: {}; retaining built-in baseline",
                                    e
                                );
                            } else {
                                info!(
                                    "Restoring persisted threat definitions v{} (timestamp {})",
                                    persisted_bundle.manifest.version,
                                    persisted_bundle.manifest.timestamp
                                );
                                initial_version = persisted_bundle.manifest.version;
                                initial_timestamp = persisted_bundle.manifest.timestamp;
                                hash_count = h_count;
                                byte_count = b_count;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Persisted threat bundle failed validation on startup: {}; retaining built-in baseline",
                                e
                            );
                        }
                    }
                } else {
                    warn!(
                        "Persisted threat bundle failed signature verification against trusted keys; retaining built-in baseline"
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    "Failed to read persisted threat definitions from storage: {}; retaining built-in baseline",
                    e
                );
            }
        }

        let definitions_status = Arc::new(Mutex::new(DefinitionStatus {
            version: initial_version,
            last_updated: initial_timestamp,
            rule_count: rules.rule_count(),
            hash_signature_count: hash_count,
            byte_signature_count: byte_count,
            official_public_key: OFFICIAL_PUBLIC_KEY_HEX.to_string(),
        }));

        Ok(Self {
            rules,
            storage,
            quarantine,
            provider,
            scanner,
            watcher_active: Arc::new(Mutex::new(false)),
            fanotify_monitor: Arc::new(Mutex::new(None)),
            definitions_status,
            trusted_keys,
            update_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn add_trusted_key_hex(&self, key_hex: &str) {
        let clean = key_hex.trim().to_lowercase();
        let _ = self.storage.add_trusted_key(&clean);
        if let Ok(mut guard) = self.trusted_keys.write() {
            guard.insert(clean);
        }
    }

    pub fn capabilities(&self) -> PlatformCapabilities {
        let policy = self.storage.get_policy().unwrap_or_default();
        self.provider.probe_capabilities(policy.mode)
    }

    pub fn definition_status(&self) -> DefinitionStatus {
        let mut status = self
            .definitions_status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        status.rule_count = self.rules.rule_count();
        status
    }

    pub fn update_definitions(&self, bundle: SignedThreatBundle) -> Result<DefinitionStatus> {
        // Prevent concurrent update races
        let _lock = self
            .update_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Update lock poisoned"))?;

        // 1. Verify bundle against explicitly pinned trusted keys ONLY
        let trusted_keys = self
            .trusted_keys
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();

        let mut verified = false;
        for trusted_key in &trusted_keys {
            if bundle.verify_with_hex_key(trusted_key).is_ok() {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(anyhow::anyhow!(
                "Cryptographic signature verification failed: bundle is not signed by any pinned trusted public key (self-supplied or unknown keys rejected)"
            ));
        }

        // 2. Anti-rollback validation: version and timestamp must strictly advance
        let current_status = self
            .definitions_status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        kernlock_core::validate_version_advance(
            &current_status.version,
            Some(current_status.last_updated),
            &bundle.manifest.version,
            bundle.manifest.timestamp,
        )
        .map_err(|e| anyhow::anyhow!("Version rollback rejected: {}", e))?;

        // 3. TRANSACTIONAL INTEGRITY: Validate and compile EVERY definition before persisting to database
        RuleEngine::validate_manifest(&bundle.manifest)
            .map_err(|e| anyhow::anyhow!("Invalid definition in signed bundle: {}", e))?;

        // 4. Persist verified bundle to database atomically BEFORE activating in-memory
        self.storage.save_threat_bundle(&bundle).map_err(|e| {
            anyhow::anyhow!("Failed to persist threat definitions to database: {}", e)
        })?;

        // 5. Atomically replace rules AND dynamic hash/byte signatures in scanner engine
        let new_rule_count = bundle.manifest.rules.len();
        let new_hash_count = bundle.manifest.hash_signatures.len();
        let new_byte_count = bundle.manifest.byte_signatures.len();

        self.rules
            .replace_definitions(
                bundle.manifest.rules,
                bundle.manifest.hash_signatures,
                bundle.manifest.byte_signatures,
            )
            .map_err(|e| {
                anyhow::anyhow!("Failed to activate validated threat definitions: {}", e)
            })?;

        // 6. Update cached status only after atomic replacement succeeds
        let mut status = self
            .definitions_status
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        status.version = bundle.manifest.version;
        status.last_updated = bundle.manifest.timestamp;
        status.rule_count = new_rule_count;
        status.hash_signature_count = new_hash_count;
        status.byte_signature_count = new_byte_count;

        let updated_status = status.clone();
        drop(status);

        self.record_system_event(
            EventCategory::Config,
            Severity::Info,
            "Threat Definitions Updated",
            &format!(
                "Threat intelligence bundle v{} applied ({} rules, {} hash signatures, {} byte signatures)",
                updated_status.version,
                updated_status.rule_count,
                updated_status.hash_signature_count,
                updated_status.byte_signature_count
            ),
            "threat_definitions",
            "updated",
        );

        Ok(updated_status)
    }

    pub fn is_watcher_active(&self) -> bool {
        *self
            .watcher_active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_fanotify_active(&self) -> bool {
        if let Ok(guard) = self.fanotify_monitor.lock() {
            guard.as_ref().map(|m| m.is_running()).unwrap_or(false)
        } else {
            false
        }
    }

    pub fn fanotify_health(&self) -> kernlock_platform::fanotify::FanotifyMonitorHealth {
        if let Ok(guard) = self.fanotify_monitor.lock() {
            guard
                .as_ref()
                .map(|m| m.health())
                .unwrap_or(kernlock_platform::fanotify::FanotifyMonitorHealth::Uninitialized)
        } else {
            kernlock_platform::fanotify::FanotifyMonitorHealth::Failed
        }
    }

    pub fn start_fanotify_monitor(&self) {
        if !FanotifyPermissionMonitor::is_supported() {
            info!("fanotify is not supported on this host/environment; skipping kernel permission monitor");
            return;
        }

        match FanotifyPermissionMonitor::init() {
            Ok(monitor) => {
                let engine = self.clone();
                let vault_dir = engine.quarantine.vault_dir().to_path_buf();
                let rules = engine.rules.clone();
                let engine_for_policy = engine.clone();
                let policy_provider =
                    Arc::new(move || engine_for_policy.get_policy().unwrap_or_default());

                monitor.start(vault_dir, policy_provider, rules, move |event, alert| {
                    let _ = engine.storage.insert_event(&event);
                    let _ = engine.storage.insert_alert(&alert);
                });

                if let Ok(mut guard) = self.fanotify_monitor.lock() {
                    *guard = Some(monitor);
                }
                info!("fanotify kernel permission monitor active");
            }
            Err(e) => {
                warn!("Unable to initialize fanotify permission monitor: {}", e);
            }
        }
    }

    pub fn evaluate_authorization_request(&self, path_str: &str, pid: i32, is_exec: bool) -> bool {
        let path = Path::new(path_str);
        let policy = self.storage.get_policy().unwrap_or_default();

        // 1. Audit mode observes and allows
        if policy.mode == SecurityMode::Audit {
            return false;
        }

        // 2. Policy path exclusions
        if policy.is_path_excluded(path) {
            return false;
        }

        // 3. Scan file content directly using bounded streaming reader
        if path.is_file() {
            if let Ok(mut file) = std::fs::File::open(path) {
                if let Ok(res) = kernlock_core::analyzer::scan_stream_reader(
                    &mut file,
                    path_str,
                    &self.rules,
                    &policy,
                ) {
                    if res.is_suspicious || res.risk_score >= policy.auto_quarantine_threshold {
                        let action = if is_exec {
                            "KernelExecutionBlocked"
                        } else {
                            "KernelFileAccessBlocked"
                        };

                        let event = SecurityEvent {
                            id: Uuid::new_v4(),
                            timestamp: Utc::now(),
                            category: if is_exec {
                                EventCategory::Process
                            } else {
                                EventCategory::File
                            },
                            severity: res.severity,
                            title: format!(
                                "{} Blocked: {}",
                                if is_exec { "Execution" } else { "Access" },
                                res.threat_name.as_deref().unwrap_or("Malicious File")
                            ),
                            description: format!(
                                "Kernel authorization blocked PID {} from {} file {}",
                                pid,
                                if is_exec { "executing" } else { "opening" },
                                path_str
                            ),
                            target: path_str.to_string(),
                            risk_score: res.risk_score,
                            action_taken: action.to_string(),
                            rule_ids: res.matches.iter().map(|m| m.rule_id.clone()).collect(),
                            metadata: serde_json::json!({
                                "pid": pid,
                                "sha256": res.sha256,
                                "threat_name": res.threat_name,
                                "is_exec": is_exec,
                            }),
                        };

                        let alert = ThreatAlert {
                            id: Uuid::new_v4(),
                            event_id: event.id,
                            timestamp: event.timestamp,
                            severity: res.severity,
                            title: event.title.clone(),
                            explanation: res.summary.clone(),
                            target: path_str.to_string(),
                            risk_score: res.risk_score,
                            status: AlertStatus::Open,
                            recommended_action: if is_exec {
                                "Execution was blocked. Terminate invoking process and quarantine payload."
                                    .to_string()
                            } else {
                                "Access was blocked. Quarantine payload and inspect logs."
                                    .to_string()
                            },
                        };

                        let _ = self.storage.insert_event(&event);
                        let _ = self.storage.insert_alert(&alert);

                        return true; // BLOCKED
                    }
                } else if policy.mode == SecurityMode::Strict {
                    return true;
                }
            } else if policy.mode == SecurityMode::Strict {
                return true;
            }
        } else if policy.mode == SecurityMode::Strict {
            return true;
        }

        false // ALLOWED
    }

    #[cfg(unix)]
    pub fn start_unix_socket_server(&self, data_dir: &Path) {
        let engine = self.clone();
        let fallback_path = data_dir.join("kernlock.sock");

        tokio::spawn(async move {
            let primary_dir = Path::new("/var/run/kernlock");
            let sock_path = if std::fs::create_dir_all(primary_dir).is_ok() {
                primary_dir.join("kernlock.sock")
            } else {
                fallback_path
            };

            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }

            let listener = match tokio::net::UnixListener::bind(&sock_path) {
                Ok(l) => {
                    info!(
                        "Unix domain socket server listening on {}",
                        sock_path.display()
                    );
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &sock_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                    l
                }
                Err(e) => {
                    warn!(
                        "Failed to bind Unix domain socket at {}: {}",
                        sock_path.display(),
                        e
                    );
                    return;
                }
            };

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        // Validate peer credentials if available on Linux
                        #[cfg(target_os = "linux")]
                        if let Ok(ucred) = stream.peer_cred() {
                            let peer_uid = ucred.uid();
                            let self_uid = unsafe { libc::geteuid() };
                            // Accept connections from root (0) or self process UID
                            if peer_uid != 0 && peer_uid != self_uid {
                                warn!(
                                    "Rejected unauthorized Unix domain socket connection from UID {}",
                                    peer_uid
                                );
                                continue;
                            }
                        }

                        let eng = engine.clone();
                        tokio::spawn(async move {
                            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                            let (reader, mut writer) = stream.into_split();
                            let mut lines = BufReader::new(reader).lines();

                            while let Ok(Some(line)) = lines.next_line().await {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }

                                if trimmed.len() > 4096 {
                                    let _ = writer
                                        .write_all(b"{\"error\":\"frame_too_large\"}\n")
                                        .await;
                                    let _ = writer.flush().await;
                                    break;
                                }

                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed)
                                {
                                    if val.get("action").and_then(|v| v.as_str()) == Some("eval_es")
                                    {
                                        let path_str =
                                            val.get("path").and_then(|v| v.as_str()).unwrap_or("");
                                        let pid =
                                            val.get("pid").and_then(|v| v.as_i64()).unwrap_or(0)
                                                as i32;
                                        let is_exec = val
                                            .get("is_exec")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(false);

                                        let policy = eng.get_policy().unwrap_or_default();
                                        let mode_str = match policy.mode {
                                            SecurityMode::Audit => "audit",
                                            SecurityMode::Protection => "protection",
                                            SecurityMode::Strict => "strict",
                                        };

                                        let blocked = eng
                                            .evaluate_authorization_request(path_str, pid, is_exec);
                                        let resp = if blocked {
                                            format!(
                                                "{{\"verdict\":\"block\",\"mode\":\"{}\"}}\n",
                                                mode_str
                                            )
                                        } else {
                                            format!(
                                                "{{\"verdict\":\"allow\",\"mode\":\"{}\"}}\n",
                                                mode_str
                                            )
                                        };
                                        let _ = writer.write_all(resp.as_bytes()).await;
                                        let _ = writer.flush().await;
                                    } else {
                                        let _ = writer
                                            .write_all(b"{\"error\":\"unknown_action\"}\n")
                                            .await;
                                        let _ = writer.flush().await;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Unix socket accept error: {}", e);
                    }
                }
            }
        });
    }

    pub fn start_windows_minifilter(&self) {
        #[cfg(target_os = "windows")]
        {
            let engine = self.clone();
            let rules = self.rules.clone();
            let engine_for_policy = self.clone();
            let policy_provider =
                Arc::new(move || engine_for_policy.get_policy().unwrap_or_default());
            let client = kernlock_platform::windows::MinifilterClient::new();
            client.start(rules, policy_provider, move |event, alert| {
                let _ = engine.storage.insert_event(&event);
                let _ = engine.storage.insert_alert(&alert);
            });
            info!("Windows Minifilter listener started");
        }
    }

    pub fn get_policy(&self) -> Result<PolicyConfig> {
        Ok(self.storage.get_policy()?)
    }

    pub fn update_policy(&self, mut policy: PolicyConfig) -> Result<PolicyConfig> {
        policy.updated_at = Utc::now();
        self.storage.save_policy(&policy)?;
        self.record_system_event(
            EventCategory::Config,
            Severity::Info,
            "Security Policy Updated",
            &format!("Security mode set to {:?}", policy.mode),
            "policy_config",
            "saved",
        );
        Ok(policy)
    }

    pub fn analyze_command_text(&self, input: &str) -> Result<CommandAnalysisResult> {
        let result = analyze_command(input, &self.rules);
        if result.is_suspicious {
            let rule_ids: Vec<String> = result.matches.iter().map(|m| m.rule_id.clone()).collect();
            let event = SecurityEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                category: EventCategory::Command,
                severity: result.severity,
                title: "Suspicious Command/Script Detected".to_string(),
                description: result.summary.clone(),
                target: result.input_preview.clone(),
                risk_score: result.risk_score,
                action_taken: "analyzed_audit".to_string(),
                rule_ids,
                metadata: serde_json::json!({ "matches": result.matches }),
            };
            self.storage.insert_event(&event)?;

            let alert = ThreatAlert {
                id: Uuid::new_v4(),
                event_id: event.id,
                timestamp: event.timestamp,
                severity: result.severity,
                title: event.title.clone(),
                explanation: result
                    .matches
                    .iter()
                    .map(|m| format!("[{}] {}: {}", m.rule_id, m.rule_name, m.explanation))
                    .collect::<Vec<_>>()
                    .join("\n"),
                target: result.input_preview.clone(),
                risk_score: result.risk_score,
                status: AlertStatus::Open,
                recommended_action: result
                    .matches
                    .first()
                    .map(|m| m.remediation.clone())
                    .unwrap_or_else(|| "Review command before execution.".to_string()),
            };
            self.storage.insert_alert(&alert)?;
        }
        Ok(result)
    }

    pub fn scan_path(&self, path: &Path) -> Result<Vec<FileScanResult>> {
        let policy = self.get_policy()?;
        let caps = self.provider.probe_capabilities(policy.mode);
        let results = self.provider.scan_path(path, &self.rules, &policy)?;

        for res in &results {
            if res.is_suspicious {
                let mut action_taken = "alerted_audit".to_string();
                let mut alert_status = AlertStatus::Open;

                if caps.active_mode != SecurityMode::Audit
                    && res.risk_score >= policy.auto_quarantine_threshold
                {
                    match self.quarantine.quarantine_file(&res.path, &res.summary) {
                        Ok(_) => {
                            action_taken = "quarantined".to_string();
                            alert_status = AlertStatus::Quarantined;
                        }
                        Err(e) => {
                            warn!("Auto-quarantine failed for {}: {}", res.path, e);
                            action_taken = format!("quarantine_failed_audit_fallback: {}", e);
                        }
                    }
                }

                let rule_ids: Vec<String> = res.matches.iter().map(|m| m.rule_id.clone()).collect();
                let event = SecurityEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    category: EventCategory::File,
                    severity: res.severity,
                    title: format!("Suspicious File: {}", res.path),
                    description: res.summary.clone(),
                    target: res.path.clone(),
                    risk_score: res.risk_score,
                    action_taken,
                    rule_ids,
                    metadata: serde_json::json!({
                        "sha256": res.sha256,
                        "entropy": res.entropy,
                        "file_type": res.file_type,
                    }),
                };
                self.storage.insert_event(&event)?;

                let alert = ThreatAlert {
                    id: Uuid::new_v4(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    severity: res.severity,
                    title: event.title.clone(),
                    explanation: res
                        .matches
                        .iter()
                        .map(|m| format!("[{}] {}: {}", m.rule_id, m.rule_name, m.explanation))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    target: res.path.clone(),
                    risk_score: res.risk_score,
                    status: alert_status,
                    recommended_action: res
                        .matches
                        .first()
                        .map(|m| m.remediation.clone())
                        .unwrap_or_else(|| "Quarantine or inspect the file.".to_string()),
                };
                self.storage.insert_alert(&alert)?;
            }
        }

        Ok(results)
    }

    pub fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let policy = self.get_policy()?;
        Ok(self.provider.list_processes(&self.rules, &policy)?)
    }

    pub fn scan_persistence(&self) -> Result<Vec<PersistenceEntry>> {
        Ok(self.provider.scan_persistence(&self.rules)?)
    }

    pub fn quarantine_file(&self, path: &Path, reason: &str) -> Result<QuarantineRecord> {
        let rec = self.quarantine.quarantine_file(path, reason)?;
        self.record_system_event(
            EventCategory::Quarantine,
            Severity::Medium,
            "File Quarantined",
            reason,
            &rec.original_path,
            "quarantined",
        );
        Ok(rec)
    }

    pub fn restore_quarantine(&self, id: Uuid) -> Result<QuarantineRecord> {
        let rec = self.quarantine.restore_file(id)?;
        self.record_system_event(
            EventCategory::Quarantine,
            Severity::Info,
            "File Restored from Quarantine",
            "User restored quarantined file to original path",
            &rec.original_path,
            "restored",
        );
        Ok(rec)
    }

    pub fn delete_quarantine(&self, id: Uuid) -> Result<()> {
        self.quarantine.delete_permanently(id)?;
        self.record_system_event(
            EventCategory::Quarantine,
            Severity::Info,
            "Quarantined File Deleted",
            "User permanently deleted quarantined file",
            &id.to_string(),
            "deleted",
        );
        Ok(())
    }

    pub fn generate_report(&self) -> Result<SecurityReport> {
        let policy = self.get_policy()?;
        let capabilities = self.provider.probe_capabilities(policy.mode);
        let events = self.storage.list_events(500)?;
        let alerts = self.storage.list_alerts(500)?;
        let quarantine = self.quarantine.list()?;
        let processes_res = self.list_processes();
        let persistence_res = self.scan_persistence();

        let open_alerts = alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Open)
            .count();
        let critical_alerts = alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Open && a.severity == Severity::Critical)
            .count();
        let quarantined_files = quarantine
            .iter()
            .filter(|q| q.status == kernlock_core::QuarantineStatus::Quarantined)
            .count();
        let suspicious_processes = processes_res
            .as_ref()
            .ok()
            .map(|ps| ps.iter().filter(|p| p.risk_score >= 40).count());
        let suspicious_persistence = persistence_res
            .as_ref()
            .ok()
            .map(|ps| ps.iter().filter(|p| p.risk_score >= 40).count());

        let mut recommendations = Vec::new();
        if let Some(reason) = &capabilities.fallback_reason {
            recommendations.push(reason.clone());
        }
        match suspicious_processes {
            Some(n) if n > 0 => recommendations.push(format!(
                "Investigate {} suspicious running process(es) flagged in Process Monitor.",
                n
            )),
            None => recommendations
                .push("Process monitoring is unsupported or unavailable on this host.".to_string()),
            _ => {}
        }
        match suspicious_persistence {
            Some(n) if n > 0 => recommendations.push(format!(
                "Review {} suspicious persistence/startup entry(s).",
                n
            )),
            None => recommendations.push(
                "Persistence scanning is unsupported or unavailable on this host.".to_string(),
            ),
            _ => {}
        }
        if open_alerts > 0 {
            recommendations.push(format!("Triage {} open threat alert(s).", open_alerts));
        }
        if recommendations.is_empty() {
            recommendations.push(
                "No active threats detected. Keep watch paths and rules updated.".to_string(),
            );
        }

        Ok(SecurityReport {
            generated_at: Utc::now(),
            host_os: capabilities.os.clone(),
            hostname: capabilities.hostname.clone(),
            security_mode: capabilities.active_mode,
            total_events: events.len(),
            open_alerts,
            critical_alerts,
            quarantined_files,
            suspicious_processes,
            suspicious_persistence,
            top_alerts: alerts.into_iter().take(10).collect(),
            capabilities,
            recommendations,
        })
    }

    pub fn format_report_markdown(&self, report: &SecurityReport) -> String {
        let mut md = String::new();
        md.push_str("# KernLock Security Report\n\n");
        md.push_str(&format!(
            "- **Generated At:** {}\n",
            report.generated_at.to_rfc3339()
        ));
        md.push_str(&format!(
            "- **Host:** {} ({})\n",
            report.hostname, report.host_os
        ));
        md.push_str(&format!("- **Active Mode:** {:?}\n", report.security_mode));
        md.push_str(&format!(
            "- **Total Recorded Events:** {}\n",
            report.total_events
        ));
        md.push_str(&format!(
            "- **Open Alerts:** {} (Critical: {})\n",
            report.open_alerts, report.critical_alerts
        ));
        md.push_str(&format!(
            "- **Quarantined Files:** {}\n",
            report.quarantined_files
        ));
        md.push_str(&format!(
            "- **Suspicious Processes:** {}\n",
            report
                .suspicious_processes
                .map(|n| n.to_string())
                .unwrap_or_else(|| "N/A (Unsupported on this platform)".to_string())
        ));
        md.push_str(&format!(
            "- **Suspicious Persistence Entries:** {}\n\n",
            report
                .suspicious_persistence
                .map(|n| n.to_string())
                .unwrap_or_else(|| "N/A (Unsupported on this platform)".to_string())
        ));

        md.push_str("## Recommendations\n\n");
        for rec in &report.recommendations {
            md.push_str(&format!("- {}\n", rec));
        }
        md.push('\n');

        md.push_str("## Platform Capabilities\n\n");
        for cap in &report.capabilities.capabilities {
            md.push_str(&format!(
                "- **{}**: {} (`{}`)\n",
                cap.name, cap.active_mode, cap.details
            ));
        }
        md
    }

    pub fn start_realtime_watcher(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel::<PathBuf>(256);

            let watcher_res =
                notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                            for p in event.paths {
                                let _ = tx.blocking_send(p);
                            }
                        }
                    }
                });

            let mut watcher: RecommendedWatcher = match watcher_res {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to initialize filesystem watcher: {}", e);
                    return;
                }
            };

            let policy = engine.get_policy().unwrap_or_default();
            let mut watched_any = false;
            let mut paths = policy.watch_paths;
            if paths.is_empty() {
                if let Ok(home) = std::env::var("HOME") {
                    let dl = PathBuf::from(&home).join("Downloads");
                    if dl.exists() {
                        paths.push(dl.display().to_string());
                    }
                }
                if Path::new("/tmp").exists() {
                    paths.push("/tmp".to_string());
                }
            }

            for p in paths {
                let path = PathBuf::from(&p);
                if path.exists() {
                    if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                        warn!("Unable to watch {}: {}", p, e);
                    } else {
                        info!("Real-time file watcher active on {}", p);
                        watched_any = true;
                    }
                }
            }

            if let Ok(mut guard) = engine.watcher_active.lock() {
                *guard = watched_any;
            }

            while let Some(path) = rx.recv().await {
                if path.is_file() {
                    let _ = engine.scan_path(&path);
                }
            }
        });
    }

    fn record_system_event(
        &self,
        category: EventCategory,
        severity: Severity,
        title: &str,
        description: &str,
        target: &str,
        action_taken: &str,
    ) {
        let ev = SecurityEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category,
            severity,
            title: title.to_string(),
            description: description.to_string(),
            target: target.to_string(),
            risk_score: 0,
            action_taken: action_taken.to_string(),
            rule_ids: Vec::new(),
            metadata: serde_json::json!({}),
        };
        let _ = self.storage.insert_event(&ev);
    }
}

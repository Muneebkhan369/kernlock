use anyhow::Result;
use chrono::Utc;
use kernlock_core::{
    analyze_command, AlertStatus, CommandAnalysisResult, EventCategory, FileScanResult,
    PersistenceEntry, PlatformCapabilities, PolicyConfig, ProcessInfo, QuarantineRecord,
    RuleEngine, SecurityEvent, SecurityMode, SecurityReport, Severity, ThreatAlert,
};
use kernlock_platform::{default_provider, PlatformSecurityProvider};
use kernlock_quarantine::QuarantineManager;
use kernlock_storage::Storage;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct KernLockEngine {
    pub rules: Arc<RuleEngine>,
    pub storage: Storage,
    pub quarantine: QuarantineManager,
    pub provider: Arc<Box<dyn PlatformSecurityProvider>>,
    watcher_active: Arc<Mutex<bool>>,
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
                "Quarantine startup recovery audit: {} recovered, {} finalized deletions, {} unverified stranded files",
                recovery_report.recovered_to_quarantine.len(),
                recovery_report.finalized_deletions.len(),
                recovery_report.unverified_stranded_files.len()
            );
        }
        let rules = Arc::new(RuleEngine::builtin());
        let provider = Arc::new(default_provider());

        Ok(Self {
            rules,
            storage,
            quarantine,
            provider,
            watcher_active: Arc::new(Mutex::new(false)),
        })
    }

    pub fn capabilities(&self) -> PlatformCapabilities {
        let policy = self.storage.get_policy().unwrap_or_default();
        self.provider.probe_capabilities(policy.mode)
    }

    pub fn is_watcher_active(&self) -> bool {
        *self
            .watcher_active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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

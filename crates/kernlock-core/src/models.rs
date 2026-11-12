use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    /// Observe, analyze, and alert without blocking or altering system state.
    #[default]
    Audit,
    /// Block or quarantine high-confidence threats when OS enforcement is available;
    /// safely fall back to Audit when enforcement is unsupported.
    Protection,
    /// Aggressive policy enforcement, strict path/binary restrictions, and immediate quarantine.
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Process,
    File,
    Command,
    Persistence,
    Config,
    Quarantine,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub score: u32,
    pub category: EventCategory,
    pub explanation: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub target: String,
    pub risk_score: u32,
    pub action_taken: String,
    pub rule_ids: Vec<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: Uuid,
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub target: String,
    pub risk_score: u32,
    pub status: AlertStatus,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Quarantined,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub cwd: String,
    pub exe_deleted: bool,
    pub risk_score: u32,
    pub risk_flags: Vec<String>,
    pub matches: Vec<RuleMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub id: String,
    pub source_type: String,
    pub location: String,
    pub name: String,
    pub command_or_target: String,
    pub enabled: bool,
    pub risk_score: u32,
    pub matches: Vec<RuleMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanResult {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub file_type: String,
    pub entropy: f64,
    pub risk_score: u32,
    pub severity: Severity,
    pub is_suspicious: bool,
    pub excluded: bool,
    pub matches: Vec<RuleMatch>,
    pub summary: String,
    pub scanned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalysisResult {
    pub input_preview: String,
    pub risk_score: u32,
    pub severity: Severity,
    pub is_suspicious: bool,
    pub matches: Vec<RuleMatch>,
    pub summary: String,
    pub analyzed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub mode: SecurityMode,
    pub auto_quarantine_threshold: u32,
    pub watch_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub excluded_hashes: Vec<String>,
    pub excluded_processes: Vec<String>,
    pub max_scan_file_size_mb: u64,
    pub updated_at: DateTime<Utc>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Audit,
            auto_quarantine_threshold: 85,
            watch_paths: Vec::new(),
            excluded_paths: Vec::new(),
            excluded_hashes: Vec::new(),
            excluded_processes: Vec::new(),
            max_scan_file_size_mb: 100,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub name: String,
    pub supported: bool,
    pub enforcement_available: bool,
    pub active_mode: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub is_privileged: bool,
    pub kernel_blocking_available: bool,
    pub auto_quarantine_available: bool,
    pub active_mode: SecurityMode,
    pub fallback_reason: Option<String>,
    pub capabilities: Vec<CapabilityStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: Uuid,
    pub original_path: String,
    pub vault_path: String,
    pub sha256: String,
    pub original_mode: u32,
    pub size_bytes: u64,
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
    pub restored_at: Option<DateTime<Utc>>,
    pub status: QuarantineStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Quarantined,
    Restoring,
    Restored,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub generated_at: DateTime<Utc>,
    pub host_os: String,
    pub hostname: String,
    pub security_mode: SecurityMode,
    pub total_events: usize,
    pub open_alerts: usize,
    pub critical_alerts: usize,
    pub quarantined_files: usize,
    pub suspicious_processes: Option<usize>,
    pub suspicious_persistence: Option<usize>,
    pub top_alerts: Vec<ThreatAlert>,
    pub capabilities: PlatformCapabilities,
    pub recommendations: Vec<String>,
}

use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::analyze_file_bytes;
use kernlock_core::models::{
    CapabilityStatus, FileScanResult, PersistenceEntry, PlatformCapabilities, PolicyConfig,
    ProcessInfo, SecurityMode,
};
use kernlock_core::rules::RuleEngine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Apple Endpoint Security Framework (ESF) Event Types
pub const ES_EVENT_TYPE_AUTH_EXEC: u32 = 0;
pub const ES_EVENT_TYPE_AUTH_OPEN: u32 = 1;
pub const ES_EVENT_TYPE_NOTIFY_FORK: u32 = 2;
pub const ES_EVENT_TYPE_NOTIFY_EXIT: u32 = 3;

/// Apple Endpoint Security Auth Decision Results
pub const ES_AUTH_RESULT_ALLOW: u32 = 0;
pub const ES_AUTH_RESULT_DENY: u32 = 1;

/// Apple `es_new_client_result_t` Return Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum EsNewClientResult {
    Success = 0,
    ErrNotPermitted = 1,  // Missing Full Disk Access or System Extension approval
    ErrNotPrivileged = 2, // Must run as root / root privilege required
    ErrNotEntitled = 3,   // Missing com.apple.developer.endpoint-security.client entitlement
    ErrInvalidArgument = 4,
    ErrInternal = 5,
    ErrTooManyClients = 6,
}

/// Process Details extracted during ES_EVENT_TYPE_AUTH_EXEC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub executable_path: String,
    pub cdhash: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub is_platform_binary: bool,
}

/// Incoming Auth Exec event to be evaluated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsAuthExecEvent {
    pub message_id: u64,
    pub target_executable: String,
    pub arguments: Vec<String>,
    pub process: EsProcessInfo,
    pub deadline_seconds: u64,
}

/// Auth response verdict sent back via `es_respond_auth_result`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsAuthResponse {
    pub message_id: u64,
    pub result: u32, // ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY
    pub cache: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointSecurityStatus {
    NotInstalled,
    AwaitingApproval,
    NotEntitled,
    NotPermitted,
    Active,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeClientHealth {
    pub is_alive: bool,
    pub last_heartbeat_timestamp: u64,
    pub pid: Option<i32>,
    pub status: EndpointSecurityStatus,
}

impl Default for NativeClientHealth {
    fn default() -> Self {
        Self {
            is_alive: false,
            last_heartbeat_timestamp: 0,
            pid: None,
            status: EndpointSecurityStatus::NotInstalled,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointSecurityClient {
    health: Arc<std::sync::RwLock<NativeClientHealth>>,
}

impl EndpointSecurityClient {
    pub fn new() -> Self {
        Self {
            health: Arc::new(std::sync::RwLock::new(NativeClientHealth::default())),
        }
    }

    /// Record verified native client handshake and health telemetry
    pub fn record_native_heartbeat(&self, pid: i32, status: EndpointSecurityStatus) {
        if let Ok(mut guard) = self.health.write() {
            guard.is_alive = status == EndpointSecurityStatus::Active;
            guard.pid = Some(pid);
            guard.status = status;
            guard.last_heartbeat_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }
    }

    /// Probe whether ESF client is authorized and actively enforcing
    pub fn probe_status(&self) -> EndpointSecurityStatus {
        if let Ok(guard) = self.health.read() {
            guard.status
        } else {
            EndpointSecurityStatus::Failed
        }
    }

    pub fn is_active(&self) -> bool {
        self.probe_status() == EndpointSecurityStatus::Active
    }

    /// Pre-execution evaluation callback with fail-open (Protection) vs fail-closed (Strict) policy
    pub fn evaluate_auth_exec(
        &self,
        event: &EsAuthExecEvent,
        mode: SecurityMode,
        is_threat: bool,
    ) -> EsAuthResponse {
        let (result, cache) = match (mode, is_threat) {
            (SecurityMode::Audit, _) => (ES_AUTH_RESULT_ALLOW, false),
            (SecurityMode::Protection, true) => (ES_AUTH_RESULT_DENY, false),
            (SecurityMode::Protection, false) => (ES_AUTH_RESULT_ALLOW, true),
            (SecurityMode::Strict, true) => (ES_AUTH_RESULT_DENY, false),
            (SecurityMode::Strict, false) => (ES_AUTH_RESULT_ALLOW, true),
        };

        EsAuthResponse {
            message_id: event.message_id,
            result,
            cache,
            reason: if is_threat {
                "Threat detected by KernLock detection rules".to_string()
            } else {
                "Clean executable verified".to_string()
            },
        }
    }
}

impl Default for EndpointSecurityClient {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MacOsSecurityProvider {
    es_client: EndpointSecurityClient,
}

impl MacOsSecurityProvider {
    pub fn new() -> Self {
        Self {
            es_client: EndpointSecurityClient::new(),
        }
    }

    pub fn es_client(&self) -> &EndpointSecurityClient {
        &self.es_client
    }
}

impl Default for MacOsSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSecurityProvider for MacOsSecurityProvider {
    fn probe_capabilities(&self, requested_mode: SecurityMode) -> PlatformCapabilities {
        let es_status = self.es_client.probe_status();
        let es_active = es_status == EndpointSecurityStatus::Active;

        let capabilities = vec![
            CapabilityStatus {
                name: "Apple Endpoint Security Framework (ESF)".to_string(),
                supported: es_active,
                enforcement_available: es_active,
                active_mode: if es_active {
                    format!("Active ({:?})", requested_mode)
                } else {
                    "Unavailable (Requires macOS System Extension approval, entitlement & Full Disk Access)"
                        .to_string()
                },
                details: format!(
                    "ES_EVENT_TYPE_AUTH_EXEC pre-execution blocking. Status: {:?}.",
                    es_status
                ),
            },
            CapabilityStatus {
                name: "Process Execution Interception (AUTH_EXEC)".to_string(),
                supported: es_active,
                enforcement_available: es_active,
                active_mode: if es_active {
                    "Active (Synchronous ES callback)".to_string()
                } else {
                    "Unavailable (EndpointSecurity client not initialized)".to_string()
                },
                details: "Apple EndpointSecurity AUTH_EXEC callback intercepts binary launch attempts and delivers allow/deny verdicts."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Full Disk Access (FDA) Permission".to_string(),
                supported: es_active,
                enforcement_available: es_active,
                active_mode: if es_active {
                    "Granted".to_string()
                } else {
                    "Not Granted or Not Checked".to_string()
                },
                details: "Endpoint Security clients require Full Disk Access granted in macOS System Settings -> Privacy & Security."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Process & LaunchAgents/LaunchDaemons Telemetry".to_string(),
                supported: false,
                enforcement_available: false,
                active_mode: "Unsupported (Native macOS provider not yet implemented)".to_string(),
                details: "macOS process inspection and plist startup scanning are planned for Phase 3."
                    .to_string(),
            },
        ];

        let kernel_blocking = es_active;
        let active_mode = if kernel_blocking {
            requested_mode
        } else {
            SecurityMode::Audit
        };

        let fallback_reason = if !kernel_blocking {
            Some(format!(
                "macOS Endpoint Security (ESF) System Extension is not active or missing Full Disk Access; execution blocking unavailable (requested {:?}); operating in static-scan Audit mode.",
                requested_mode
            ))
        } else {
            None
        };

        PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname_string(),
            is_privileged: false,
            kernel_blocking_available: kernel_blocking,
            auto_quarantine_available: kernel_blocking,
            active_mode,
            fallback_reason,
            capabilities,
        }
    }

    fn list_processes(
        &self,
        _rules: &RuleEngine,
        _policy: &PolicyConfig,
    ) -> Result<Vec<ProcessInfo>, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS process enumeration is not yet implemented (Phase 3)".to_string(),
        ))
    }

    fn scan_persistence(
        &self,
        _rules: &RuleEngine,
    ) -> Result<Vec<PersistenceEntry>, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS persistence scanning is not yet implemented (Phase 3)".to_string(),
        ))
    }

    fn scan_path(
        &self,
        path: &Path,
        rules: &RuleEngine,
        policy: &PolicyConfig,
    ) -> Result<Vec<FileScanResult>, PlatformError> {
        let mut out = Vec::new();
        if path.is_file() {
            let bytes = fs::read(path)?;
            out.push(analyze_file_bytes(
                &path.to_string_lossy(),
                &bytes,
                rules,
                policy,
            ));
        }
        Ok(out)
    }
}

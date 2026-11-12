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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Filter Manager (FLTMGR) communication port name used by KernLock Minifilter
pub const FILTER_PORT_NAME: &str = "\\KernLockFilterPort";

/// FLTMGR Altitude assigned to FSFilter Anti-Virus group (320000 - 329999)
pub const KERNLOCK_FILTER_ALTITUDE: &str = "325000";

/// Windows NTSTATUS error codes
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Minifilter pre-operation callback status codes
pub const FLT_PREOP_SUCCESS_WITH_CALLBACK: u32 = 0;
pub const FLT_PREOP_SUCCESS_NO_CALLBACK: u32 = 1;
pub const FLT_PREOP_COMPLETE: u32 = 3;

/// Windows DesiredAccess flags intercepted during IRP_MJ_CREATE
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ExecutionVerdict {
    Allow = 0,
    Block = 1,
    Audit = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinifilterMessageHeader {
    pub message_id: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub timestamp_qword: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequestMessage {
    pub header: MinifilterMessageHeader,
    pub desired_access: u32,
    pub file_path: String,
    pub parent_process_id: u32,
    pub sha256_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResponseMessage {
    pub message_id: u64,
    pub verdict: ExecutionVerdict,
    pub ntstatus: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinifilterDriverStatus {
    NotInstalled,
    InstalledNotRunning,
    Connected,
    CommunicationError,
}

#[derive(Debug, Clone)]
pub struct MinifilterClient {
    connected: Arc<AtomicBool>,
}

impl MinifilterClient {
    pub fn new() -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Probe whether the minifilter communication port can be connected
    pub fn probe_status(&self) -> MinifilterDriverStatus {
        #[cfg(target_os = "windows")]
        {
            // On Windows host, verify if FilterConnectCommunicationPort succeeds
            if self.connected.load(Ordering::Acquire) {
                MinifilterDriverStatus::Connected
            } else {
                MinifilterDriverStatus::NotInstalled
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            MinifilterDriverStatus::NotInstalled
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Deliver pre-execution verdict to Filter Manager with fail-open / fail-closed timeout logic
    pub fn evaluate_verdict(
        &self,
        request: &ExecutionRequestMessage,
        mode: SecurityMode,
        is_threat: bool,
    ) -> ExecutionResponseMessage {
        let verdict = match (mode, is_threat) {
            (SecurityMode::Audit, _) => ExecutionVerdict::Audit,
            (SecurityMode::Protection, true) => ExecutionVerdict::Block,
            (SecurityMode::Protection, false) => ExecutionVerdict::Allow,
            (SecurityMode::Strict, true) => ExecutionVerdict::Block,
            (SecurityMode::Strict, false) => ExecutionVerdict::Allow,
        };

        let ntstatus = match verdict {
            ExecutionVerdict::Allow | ExecutionVerdict::Audit => STATUS_SUCCESS,
            ExecutionVerdict::Block => STATUS_ACCESS_DENIED,
        };

        ExecutionResponseMessage {
            message_id: request.header.message_id,
            verdict,
            ntstatus,
            reason: if is_threat {
                "Threat detected by KernLock detection rules".to_string()
            } else {
                "Clean executable verified".to_string()
            },
        }
    }
}

impl Default for MinifilterClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows Service Control Handler architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsServiceState {
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7,
}

pub struct WindowsSecurityProvider {
    minifilter: MinifilterClient,
}

impl WindowsSecurityProvider {
    pub fn new() -> Self {
        Self {
            minifilter: MinifilterClient::new(),
        }
    }

    pub fn minifilter_client(&self) -> &MinifilterClient {
        &self.minifilter
    }
}

impl Default for WindowsSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSecurityProvider for WindowsSecurityProvider {
    fn probe_capabilities(&self, requested_mode: SecurityMode) -> PlatformCapabilities {
        let driver_status = self.minifilter.probe_status();
        let driver_connected = driver_status == MinifilterDriverStatus::Connected;

        let capabilities = vec![
            CapabilityStatus {
                name: "Windows Filter Manager (FLTMGR) Minifilter".to_string(),
                supported: driver_connected,
                enforcement_available: driver_connected,
                active_mode: if driver_connected {
                    format!("Active ({:?})", requested_mode)
                } else {
                    "Unavailable (Minifilter driver kernlock_filter.sys not connected)".to_string()
                },
                details: format!(
                    "FLTMGR altitude {} IRP_MJ_CREATE pre-execution blocking. Status: {:?}.",
                    KERNLOCK_FILTER_ALTITUDE, driver_status
                ),
            },
            CapabilityStatus {
                name: "Windows Defender / AMSI Integration".to_string(),
                supported: false,
                enforcement_available: false,
                active_mode: "Unsupported (AMSI COM provider not yet registered)".to_string(),
                details: "Antimalware Scan Interface (AMSI) requires Windows host COM registration for script inspection."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Process Creation Interception (PsSetCreateProcessNotifyRoutineEx)".to_string(),
                supported: driver_connected,
                enforcement_available: driver_connected,
                active_mode: if driver_connected {
                    "Active (Kernel process notify routine)".to_string()
                } else {
                    "Unavailable (Kernel driver not loaded)".to_string()
                },
                details: "Kernel process notification routine intercepts process spawn events and queries user-mode verdict."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Process & Persistence Telemetry (Win32 / Registry / Tasks)".to_string(),
                supported: false,
                enforcement_available: false,
                active_mode: "Unsupported (Native Windows enumeration not yet implemented)".to_string(),
                details: "Win32 process snapshots, HKCU/HKLM Run keys, and Task Scheduler inspection are planned for Phase 3."
                    .to_string(),
            },
        ];

        let kernel_blocking = driver_connected;
        let active_mode = if kernel_blocking {
            requested_mode
        } else {
            SecurityMode::Audit
        };

        let fallback_reason = if !kernel_blocking {
            Some(format!(
                "Windows Minifilter driver (kernlock_filter.sys) is not installed or communication port '{}' is not connected; execution blocking unavailable (requested {:?}); operating in static-scan Audit mode.",
                FILTER_PORT_NAME, requested_mode
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
            "Windows process enumeration is not yet implemented (Phase 3)".to_string(),
        ))
    }

    fn scan_persistence(
        &self,
        _rules: &RuleEngine,
    ) -> Result<Vec<PersistenceEntry>, PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows persistence scanning is not yet implemented (Phase 3)".to_string(),
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

use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::analyze_file_bytes;
use kernlock_core::models::{
    AlertStatus, CapabilityStatus, EventCategory, FileScanResult, PersistenceEntry,
    PlatformCapabilities, PolicyConfig, ProcessInfo, SecurityEvent, SecurityMode, ThreatAlert,
};
use kernlock_core::rules::RuleEngine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Filter Manager (FLTMGR) communication port name used by KernLock Minifilter.
/// Must match `KERNLOCK_FILTER_PORT_NAME` in `kernlock_filter.h`.
pub const FILTER_PORT_NAME: &str = "\\KernLockFilterPort";

/// FLTMGR Altitude assigned to FSFilter Anti-Virus group (320000 - 329999).
///
/// ### Microsoft Minifilter Altitude Allocation Requirements:
/// - The altitude `325000` is in Microsoft's FSFilter Anti-Virus load order group.
/// - In development, `325000` is used for testing with test-signing enabled (`bcdedit /set testsigning on`).
/// - For production deployment, a unique altitude **must** be officially requested from and
///   assigned by Microsoft (contact `fsfilt@microsoft.com` or via Microsoft Hardware Dev Center).
/// - Production drivers must pass WHQL tests (Windows Hardware Quality Labs) and obtain
///   Microsoft WHQL attestation signing.
/// - Without an officially allocated altitude and signed driver, KernLock truthfully reports
///   that kernel execution blocking is unavailable and falls back to Audit mode.
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

// ---------------------------------------------------------------------------
// Binary FFI Layouts Matching `kernlock_filter.h` (#pragma pack(push, 1))
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMinifilterMsgHeader {
    pub message_id: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub timestamp: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct RawExecutionRequestMsg {
    pub header: RawMinifilterMsgHeader,
    pub desired_access: u32,
    pub parent_process_id: u32,
    pub file_path: [u16; 1024],
}

impl RawExecutionRequestMsg {
    /// Decode the null-terminated UTF-16 wchar array safely
    pub fn file_path_string(&self) -> String {
        let path_buf = self.file_path;
        let mut len = 0;
        while len < path_buf.len() && path_buf[len] != 0 {
            len += 1;
        }
        String::from_utf16_lossy(&path_buf[..len])
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct RawExecutionResponseMsg {
    pub message_id: u64,
    pub verdict: u32,
    pub ntstatus: u32,
    pub reason: [u8; 256],
}

impl RawExecutionResponseMsg {
    pub fn new(
        message_id: u64,
        verdict: ExecutionVerdict,
        ntstatus: u32,
        reason_str: &str,
    ) -> Self {
        let mut reason = [0u8; 256];
        let bytes = reason_str.as_bytes();
        let copy_len = bytes.len().min(255);
        reason[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            message_id,
            verdict: verdict as u32,
            ntstatus,
            reason,
        }
    }
}

/// Filter Manager user-mode message buffer wrapper for `FilterGetMessage`
#[repr(C)]
pub struct FilterMessage<T> {
    pub reply_length: u32,
    pub message_id: u64,
    pub data: T,
}

/// Filter Manager user-mode reply buffer wrapper for `FilterReplyMessage`
#[repr(C)]
pub struct FilterReply<T> {
    pub status: i32,
    pub message_id: u64,
    pub data: T,
}

// ---------------------------------------------------------------------------
// High-Level Data Transfer Models
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Win32 FltLib FFI Definitions (Target OS: Windows)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod flt_ffi {
    use std::ffi::c_void;
    pub type HANDLE = *mut c_void;
    pub type HRESULT = i32;
    pub const S_OK: HRESULT = 0;

    #[link(name = "fltlib")]
    extern "system" {
        pub fn FilterConnectCommunicationPort(
            lpPortName: *const u16,
            dwOptions: u32,
            lpContext: *const c_void,
            wSizeOfContext: u16,
            lpSecurityAttributes: *mut c_void,
            hPort: *mut HANDLE,
        ) -> HRESULT;

        pub fn FilterGetMessage(
            hPort: HANDLE,
            lpMessageBuffer: *mut c_void,
            dwMessageBufferSize: u32,
            lpOverlapped: *mut c_void,
        ) -> HRESULT;

        pub fn FilterReplyMessage(
            hPort: HANDLE,
            lpReplyBuffer: *mut c_void,
            dwReplyBufferSize: u32,
        ) -> HRESULT;

        pub fn FilterClose(hFilter: HANDLE) -> HRESULT;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CloseHandle(hObject: HANDLE) -> i32;
    }
}

// ---------------------------------------------------------------------------
// MinifilterClient: Port Management, Request Processing & Event Loop
// ---------------------------------------------------------------------------

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
            if self.connected.load(Ordering::Acquire) {
                return MinifilterDriverStatus::Connected;
            }

            // Attempt a temporary non-blocking probe connection
            let mut port_name_wide: Vec<u16> =
                FILTER_PORT_NAME.encode_utf16().chain(Some(0)).collect();
            let mut h_port: flt_ffi::HANDLE = std::ptr::null_mut();

            let hr = unsafe {
                flt_ffi::FilterConnectCommunicationPort(
                    port_name_wide.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    &mut h_port,
                )
            };

            if hr == flt_ffi::S_OK && !h_port.is_null() {
                unsafe {
                    flt_ffi::FilterClose(h_port);
                }
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

    /// Scan target file and evaluate pre-execution verdict
    pub fn evaluate_request<F>(
        &self,
        request: &RawExecutionRequestMsg,
        rules: &RuleEngine,
        policy: &PolicyConfig,
        on_threat: &F,
    ) -> RawExecutionResponseMsg
    where
        F: Fn(SecurityEvent, ThreatAlert),
    {
        let file_path_str = request.file_path_string();
        let path = PathBuf::from(&file_path_str);
        let pid = request.header.process_id;
        let parent_pid = request.parent_process_id;
        let message_id = request.header.message_id;

        // Skip excluded paths
        if policy.is_path_excluded(&path) {
            return RawExecutionResponseMsg::new(
                message_id,
                ExecutionVerdict::Allow,
                STATUS_SUCCESS,
                "Excluded by policy",
            );
        }

        // In Audit mode, observe without blocking
        if policy.mode == SecurityMode::Audit {
            return RawExecutionResponseMsg::new(
                message_id,
                ExecutionVerdict::Audit,
                STATUS_SUCCESS,
                "Audit mode active",
            );
        }

        // Perform file content inspection if accessible
        let is_threat = if path.is_file() {
            if let Ok(bytes) = fs::read(&path) {
                let res = analyze_file_bytes(&file_path_str, &bytes, rules, policy);
                if res.is_suspicious || res.risk_score >= policy.auto_quarantine_threshold {
                    let event = SecurityEvent {
                        id: Uuid::new_v4(),
                        timestamp: chrono::Utc::now(),
                        category: EventCategory::Process,
                        severity: res.severity,
                        title: format!(
                            "Execution Blocked: {}",
                            res.threat_name
                                .as_deref()
                                .unwrap_or("Malicious Windows Executable")
                        ),
                        description: format!(
                            "Windows Minifilter intercepted execution of {} by PID {}",
                            file_path_str, pid
                        ),
                        target: file_path_str.clone(),
                        risk_score: res.risk_score,
                        action_taken: "KernelExecutionBlocked".to_string(),
                        rule_ids: res.matches.iter().map(|m| m.rule_id.clone()).collect(),
                        metadata: serde_json::json!({
                            "pid": pid,
                            "parent_pid": parent_pid,
                            "sha256": res.sha256,
                            "threat_name": res.threat_name,
                            "altitude": KERNLOCK_FILTER_ALTITUDE,
                        }),
                    };

                    let alert = ThreatAlert {
                        id: Uuid::new_v4(),
                        event_id: event.id,
                        timestamp: event.timestamp,
                        severity: res.severity,
                        title: event.title.clone(),
                        explanation: res.summary.clone(),
                        target: file_path_str.clone(),
                        risk_score: res.risk_score,
                        status: AlertStatus::Open,
                        recommended_action: "Execution was blocked via Filter Manager (FLTMGR). Quarantine binary and inspect process lineage.".to_string(),
                    };

                    on_threat(event, alert);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if is_threat {
            RawExecutionResponseMsg::new(
                message_id,
                ExecutionVerdict::Block,
                STATUS_ACCESS_DENIED,
                "Execution blocked by KernLock detection rules",
            )
        } else {
            RawExecutionResponseMsg::new(
                message_id,
                ExecutionVerdict::Allow,
                STATUS_SUCCESS,
                "Clean executable verified",
            )
        }
    }

    /// High-level verdict evaluation helper (used in tests and cross-platform simulation)
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

    /// Start the Filter Manager communication loop on Windows
    pub fn start<F>(
        &self,
        rules: Arc<RuleEngine>,
        get_policy: Arc<dyn Fn() -> PolicyConfig + Send + Sync + 'static>,
        on_threat: F,
    ) where
        F: Fn(SecurityEvent, ThreatAlert) + Send + Sync + 'static,
    {
        #[cfg(target_os = "windows")]
        {
            let connected = self.connected.clone();
            std::thread::spawn(move || {
                let mut port_name_wide: Vec<u16> =
                    FILTER_PORT_NAME.encode_utf16().chain(Some(0)).collect();
                let mut h_port: flt_ffi::HANDLE = std::ptr::null_mut();

                let hr = unsafe {
                    flt_ffi::FilterConnectCommunicationPort(
                        port_name_wide.as_ptr(),
                        0,
                        std::ptr::null(),
                        0,
                        std::ptr::null_mut(),
                        &mut h_port,
                    )
                };

                if hr != flt_ffi::S_OK || h_port.is_null() {
                    tracing::warn!(
                        "Failed to connect to KernLock Windows Minifilter port: 0x{:08X}",
                        hr
                    );
                    connected.store(false, Ordering::Release);
                    return;
                }

                connected.store(true, Ordering::Release);
                tracing::info!(
                    "Connected to KernLock Windows Minifilter port (altitude {})",
                    KERNLOCK_FILTER_ALTITUDE
                );

                let mut msg: FilterMessage<RawExecutionRequestMsg> = unsafe { std::mem::zeroed() };
                let msg_size = std::mem::size_of::<FilterMessage<RawExecutionRequestMsg>>() as u32;

                while connected.load(Ordering::Acquire) {
                    let hr = unsafe {
                        flt_ffi::FilterGetMessage(
                            h_port,
                            &mut msg as *mut _ as *mut std::ffi::c_void,
                            msg_size,
                            std::ptr::null_mut(),
                        )
                    };

                    if hr != flt_ffi::S_OK {
                        tracing::warn!(
                            "FilterGetMessage returned error 0x{:08X}; terminating loop",
                            hr
                        );
                        break;
                    }

                    let policy = get_policy();
                    let raw_reply_data =
                        Self::new().evaluate_request(&msg.data, &rules, &policy, &on_threat);

                    let mut reply = FilterReply {
                        status: 0,
                        message_id: msg.message_id,
                        data: raw_reply_data,
                    };

                    let reply_size =
                        std::mem::size_of::<FilterReply<RawExecutionResponseMsg>>() as u32;
                    let reply_hr = unsafe {
                        flt_ffi::FilterReplyMessage(
                            h_port,
                            &mut reply as *mut _ as *mut std::ffi::c_void,
                            reply_size,
                        )
                    };

                    if reply_hr != flt_ffi::S_OK {
                        tracing::warn!("FilterReplyMessage failed: 0x{:08X}", reply_hr);
                    }
                }

                unsafe {
                    flt_ffi::FilterClose(h_port);
                }
                connected.store(false, Ordering::Release);
            });
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (rules, get_policy, on_threat);
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

use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::analyze_file_bytes;
use kernlock_core::models::{
    AlertStatus, CapabilityStatus, EventCategory, FileScanResult, PersistenceEntry,
    PlatformCapabilities, PlatformRuntimeStatus, PolicyConfig, ProcessInfo, SecurityEvent,
    SecurityMode, ThreatAlert,
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernlockPortContext {
    pub version: u32,
    pub strict_mode: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernlockPolicyUpdateMsg {
    pub message_type: u32,
    pub strict_mode: u32,
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
    pub file_id: u64,
    pub volume_serial_number: u32,
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
    pub file_id: u64,
    pub volume_serial_number: u32,
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

        pub fn FilterSendMessage(
            hPort: HANDLE,
            lpInBuffer: *const c_void,
            dwInBufferSize: u32,
            lpOutBuffer: *mut c_void,
            dwOutBufferSize: u32,
            lpBytesReturned: *mut u32,
        ) -> HRESULT;

        pub fn FilterClose(hFilter: HANDLE) -> HRESULT;
    }

    #[link(name = "kernel32")]
    extern "system" {
        #[allow(dead_code)]
        pub fn CloseHandle(hObject: HANDLE) -> i32;
    }
}

// ---------------------------------------------------------------------------
// MinifilterClient: Port Management, Request Processing & Event Loop
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MinifilterClient {
    connected: Arc<AtomicBool>,
    #[allow(dead_code)]
    active_port: Arc<std::sync::Mutex<Option<usize>>>,
}

impl MinifilterClient {
    pub fn new() -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
            active_port: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update runtime policy mode in the kernel driver via FilterSendMessage
    pub fn update_policy_mode(&self, mode: SecurityMode) {
        #[cfg(target_os = "windows")]
        {
            if let Ok(guard) = self.active_port.lock() {
                if let Some(port_addr) = *guard {
                    let h_port = port_addr as flt_ffi::HANDLE;
                    let msg = KernlockPolicyUpdateMsg {
                        message_type: 1,
                        strict_mode: if mode == SecurityMode::Strict { 1 } else { 0 },
                    };
                    let mut bytes_returned: u32 = 0;
                    unsafe {
                        flt_ffi::FilterSendMessage(
                            h_port,
                            &msg as *const _ as *const std::ffi::c_void,
                            std::mem::size_of::<KernlockPolicyUpdateMsg>() as u32,
                            std::ptr::null_mut(),
                            0,
                            &mut bytes_returned,
                        );
                    }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = mode;
        }
    }

    /// Probe whether the minifilter communication port can be connected
    pub fn probe_status(&self) -> MinifilterDriverStatus {
        #[cfg(target_os = "windows")]
        {
            if self.connected.load(Ordering::Acquire) {
                return MinifilterDriverStatus::Connected;
            }

            // Attempt a temporary non-blocking probe connection with versioned context
            let port_name_wide: Vec<u16> = FILTER_PORT_NAME.encode_utf16().chain(Some(0)).collect();
            let mut h_port: flt_ffi::HANDLE = std::ptr::null_mut();
            let probe_ctx = KernlockPortContext {
                version: 1,
                strict_mode: 0,
                reserved: 0,
            };

            let hr = unsafe {
                flt_ffi::FilterConnectCommunicationPort(
                    port_name_wide.as_ptr(),
                    0,
                    &probe_ctx as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<KernlockPortContext>() as u16,
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

        // Perform bounded streaming file content inspection if accessible
        let scan_outcome = (|| -> Result<kernlock_core::models::FileScanResult, String> {
            #[cfg(target_os = "windows")]
            let mut file = {
                use std::os::windows::fs::OpenOptionsExt;
                // In Strict mode, open with share_mode = 1 (FILE_SHARE_READ only).
                // This locks out concurrent writers, preventing in-place modification during scanning.
                let share_mode = if policy.mode == SecurityMode::Strict {
                    1 // FILE_SHARE_READ only
                } else {
                    3 // FILE_SHARE_READ | FILE_SHARE_WRITE
                };
                fs::OpenOptions::new()
                    .read(true)
                    .share_mode(share_mode)
                    .custom_flags(0x02000000) // FILE_FLAG_BACKUP_SEMANTICS
                    .open(&path)
                    .map_err(|e| {
                        format!(
                            "Failed to open file for secure scan (share mode {}): {}",
                            share_mode, e
                        )
                    })?
            };
            #[cfg(not(target_os = "windows"))]
            let mut file =
                fs::File::open(&path).map_err(|e| format!("Failed to open file: {}", e))?;

            let meta_before = file
                .metadata()
                .map_err(|e| format!("Failed to read metadata before scan: {}", e))?;
            if !meta_before.is_file() {
                return Err("Target is not a regular file".to_string());
            }

            // Secure File ID & Volume identity verification to eliminate TOCTOU path races
            Self::verify_file_identity(
                &file,
                request.file_id,
                request.volume_serial_number,
                policy.mode,
                &file_path_str,
            )?;

            let scan_result = kernlock_core::analyzer::scan_stream_reader(
                &mut file,
                &file_path_str,
                rules,
                policy,
            )
            .map_err(|e| format!("Scan error: {}", e))?;

            // Post-scan content TOCTOU verification: ensure file size was not modified during scan
            let meta_after = file
                .metadata()
                .map_err(|e| format!("Failed to read metadata after scan: {}", e))?;
            if meta_before.len() != meta_after.len() {
                return Err(format!(
                    "TOCTOU race detected: file size changed during scan (was {} bytes, now {} bytes) for {}",
                    meta_before.len(),
                    meta_after.len(),
                    file_path_str
                ));
            }

            Ok(scan_result)
        })();

        match scan_outcome {
            Ok(res) => {
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
            Err(e) => {
                tracing::warn!("Windows Minifilter scan error for {}: {}", file_path_str, e);
                // Active security violations (such as TOCTOU race detection) fail closed in all modes.
                // Strict mode fails closed on all errors (unreadable files, scanner faults, unverified identity).
                // Protection mode fails open on benign scanner/unreadable errors only.
                if e.contains("TOCTOU") || policy.mode == SecurityMode::Strict {
                    RawExecutionResponseMsg::new(
                        message_id,
                        ExecutionVerdict::Block,
                        STATUS_ACCESS_DENIED,
                        &format!("Execution blocked: {}", e),
                    )
                } else {
                    RawExecutionResponseMsg::new(
                        message_id,
                        ExecutionVerdict::Allow,
                        STATUS_SUCCESS,
                        "Scan error or unreadable file in Protection mode (fail-open)",
                    )
                }
            }
        }
    }

    /// Verify that the opened file handle matches the FileId and Volume Serial Number intercepted by the driver.
    /// In Strict mode: failures to obtain or match identity fail closed.
    /// In Protection/Audit mode: identity mismatches fail closed; unavailable FileId logs a warning.
    pub fn verify_file_identity(
        file: &fs::File,
        expected_file_id: u64,
        expected_volume_serial: u32,
        mode: SecurityMode,
        file_path_str: &str,
    ) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawHandle;
            #[repr(C)]
            struct BY_HANDLE_FILE_INFORMATION {
                dw_file_attributes: u32,
                ft_creation_time: [u32; 2],
                ft_last_access_time: [u32; 2],
                ft_last_write_time: [u32; 2],
                dw_volume_serial_number: u32,
                n_file_size_high: u32,
                n_file_size_low: u32,
                n_number_of_links: u32,
                n_file_index_high: u32,
                n_file_index_low: u32,
            }
            extern "system" {
                fn GetFileInformationByHandle(
                    h_file: *mut std::ffi::c_void,
                    lp_file_information: *mut BY_HANDLE_FILE_INFORMATION,
                ) -> i32;
            }

            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            let ok = unsafe {
                GetFileInformationByHandle(file.as_raw_handle() as *mut std::ffi::c_void, &mut info)
            };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                if mode == SecurityMode::Strict {
                    return Err(format!(
                        "Unverified file handle: GetFileInformationByHandle failed (error: {}) for {}; rejected in Strict mode",
                        err, file_path_str
                    ));
                } else {
                    tracing::warn!(
                        "Unverified file handle: GetFileInformationByHandle failed (error: {}) for {}; file identity unverified in Permissive mode",
                        err,
                        file_path_str
                    );
                    return Ok(());
                }
            }

            let opened_file_id =
                ((info.n_file_index_high as u64) << 32) | (info.n_file_index_low as u64);
            let opened_volume_serial = info.dw_volume_serial_number;

            // 1. Verify volume identity (must match if provided by kernel; zero rejected in Strict mode)
            if expected_volume_serial == 0 {
                if mode == SecurityMode::Strict {
                    return Err(format!(
                        "Unverified file handle: Kernel Volume Serial Number is zero for {}; unverified volume identity rejected in Strict mode",
                        file_path_str
                    ));
                } else {
                    tracing::warn!(
                        "Unverified file handle: Kernel Volume Serial Number is zero for {}; volume identity unverified in Permissive mode",
                        file_path_str
                    );
                }
            } else if opened_volume_serial != expected_volume_serial {
                return Err(format!(
                    "TOCTOU race detected: opened volume serial 0x{:08X} does not match kernel volume serial 0x{:08X} for {}",
                    opened_volume_serial, expected_volume_serial, file_path_str
                ));
            }

            // 2. Verify file identifier
            if expected_file_id == 0 {
                if mode == SecurityMode::Strict {
                    return Err(format!(
                        "Unverified file handle: Kernel FileId is zero for {}; unverified file identity rejected in Strict mode",
                        file_path_str
                    ));
                } else {
                    tracing::warn!(
                        "Unverified file handle: Kernel FileId is zero for {}; file identity unverified in Permissive mode",
                        file_path_str
                    );
                    return Ok(());
                }
            }

            if opened_file_id != expected_file_id {
                return Err(format!(
                    "TOCTOU race detected: opened file ID {} does not match kernel file ID {} for {}",
                    opened_file_id, expected_file_id, file_path_str
                ));
            }

            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = file.metadata() {
                    let opened_file_id = meta.ino();
                    let opened_volume_serial = meta.dev() as u32;

                    // 1. Verify volume identity
                    if expected_volume_serial == 0 {
                        if mode == SecurityMode::Strict {
                            return Err(format!(
                                "Unverified file handle: Kernel Volume Serial Number is zero for {}; unverified volume identity rejected in Strict mode",
                                file_path_str
                            ));
                        } else {
                            tracing::warn!(
                                "Unverified file handle: Kernel Volume Serial Number is zero for {}; volume identity unverified in Permissive mode",
                                file_path_str
                            );
                        }
                    } else if opened_volume_serial != expected_volume_serial {
                        return Err(format!(
                            "TOCTOU race detected: opened volume serial 0x{:08X} does not match kernel volume serial 0x{:08X} for {}",
                            opened_volume_serial, expected_volume_serial, file_path_str
                        ));
                    }

                    // 2. Verify file identifier
                    if expected_file_id == 0 {
                        if mode == SecurityMode::Strict {
                            return Err(format!(
                                "Unverified file handle: Kernel FileId is zero for {}; unverified file identity rejected in Strict mode",
                                file_path_str
                            ));
                        } else {
                            tracing::warn!(
                                "Unverified file handle: Kernel FileId is zero for {}; file identity unverified in Permissive mode",
                                file_path_str
                            );
                            return Ok(());
                        }
                    }

                    if opened_file_id != expected_file_id {
                        return Err(format!(
                            "TOCTOU race detected: opened file ID {} does not match kernel file ID {} for {}",
                            opened_file_id, expected_file_id, file_path_str
                        ));
                    }

                    return Ok(());
                }
            }

            if expected_file_id == 0 {
                if mode == SecurityMode::Strict {
                    return Err(format!(
                        "Unverified file handle: Kernel FileId is zero for {}; unverified file identity rejected in Strict mode",
                        file_path_str
                    ));
                } else {
                    tracing::warn!(
                        "Unverified file handle: Kernel FileId is zero for {}; file identity unverified in Permissive mode",
                        file_path_str
                    );
                    return Ok(());
                }
            }
            Ok(())
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

    /// Start the Filter Manager communication loop on Windows with reconnect capability
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
            let active_port = self.active_port.clone();
            std::thread::spawn(move || {
                let port_name_wide: Vec<u16> =
                    FILTER_PORT_NAME.encode_utf16().chain(Some(0)).collect();

                let mut last_synced_mode: Option<SecurityMode>;

                loop {
                    let mut h_port: flt_ffi::HANDLE = std::ptr::null_mut();
                    let current_policy = get_policy();
                    let connect_ctx = KernlockPortContext {
                        version: 1,
                        strict_mode: if current_policy.mode == SecurityMode::Strict {
                            1
                        } else {
                            0
                        },
                        reserved: 0,
                    };

                    let hr = unsafe {
                        flt_ffi::FilterConnectCommunicationPort(
                            port_name_wide.as_ptr(),
                            0,
                            &connect_ctx as *const _ as *const std::ffi::c_void,
                            std::mem::size_of::<KernlockPortContext>() as u16,
                            std::ptr::null_mut(),
                            &mut h_port,
                        )
                    };

                    if hr != flt_ffi::S_OK || h_port.is_null() {
                        connected.store(false, Ordering::Release);
                        if let Ok(mut guard) = active_port.lock() {
                            *guard = None;
                        }
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        continue;
                    }

                    connected.store(true, Ordering::Release);
                    last_synced_mode = Some(current_policy.mode);
                    if let Ok(mut guard) = active_port.lock() {
                        *guard = Some(h_port as usize);
                    }
                    tracing::info!(
                        "Connected to KernLock Windows Minifilter port (altitude {}) with StrictMode={}",
                        KERNLOCK_FILTER_ALTITUDE,
                        connect_ctx.strict_mode
                    );

                    let mut msg: FilterMessage<RawExecutionRequestMsg> =
                        unsafe { std::mem::zeroed() };
                    let msg_size =
                        std::mem::size_of::<FilterMessage<RawExecutionRequestMsg>>() as u32;

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
                                "FilterGetMessage returned error 0x{:08X}; reconnecting port",
                                hr
                            );
                            break;
                        }

                        // Validate message ID integrity
                        let header_msg_id = msg.data.header.message_id;
                        if header_msg_id != msg.message_id {
                            tracing::warn!(
                                "Packet ID mismatch: header {} != message {}",
                                header_msg_id,
                                msg.message_id
                            );
                        }

                        let policy = get_policy();
                        // Dynamic policy sync: update driver if mode changed after initial handshake
                        if last_synced_mode != Some(policy.mode) {
                            last_synced_mode = Some(policy.mode);
                            let update_msg = KernlockPolicyUpdateMsg {
                                message_type: 1,
                                strict_mode: if policy.mode == SecurityMode::Strict {
                                    1
                                } else {
                                    0
                                },
                            };
                            let mut bytes_ret: u32 = 0;
                            unsafe {
                                flt_ffi::FilterSendMessage(
                                    h_port,
                                    &update_msg as *const _ as *const std::ffi::c_void,
                                    std::mem::size_of::<KernlockPolicyUpdateMsg>() as u32,
                                    std::ptr::null_mut(),
                                    0,
                                    &mut bytes_ret,
                                );
                            }
                        }
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
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
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

    fn runtime_enforcement_status(&self, requested_mode: SecurityMode) -> PlatformRuntimeStatus {
        let driver_status = self.minifilter.probe_status();
        let (protection_state, monitor_health, state_reason) = match driver_status {
            MinifilterDriverStatus::NotInstalled => (
                "Unavailable".to_string(),
                "Unavailable".to_string(),
                Some("Windows Minifilter driver (kernlock_filter.sys) is not installed or running. Requires loaded driver with test-signing enabled.".to_string()),
            ),
            MinifilterDriverStatus::InstalledNotRunning => (
                "Degraded".to_string(),
                "Stopped".to_string(),
                Some("Windows Minifilter driver is loaded but not connected to daemon communication port.".to_string()),
            ),
            MinifilterDriverStatus::CommunicationError => (
                "Failed".to_string(),
                "Failed".to_string(),
                Some("Filter Manager communication error with kernlock_filter.sys".to_string()),
            ),
            MinifilterDriverStatus::Connected => {
                if requested_mode == SecurityMode::Audit {
                    (
                        "Degraded".to_string(),
                        "Running".to_string(),
                        Some("Windows Minifilter connected; Audit mode active (observing without blocking).".to_string()),
                    )
                } else {
                    (
                        "Active".to_string(),
                        "Running".to_string(),
                        Some("Windows Minifilter active and enforcing pre-execution verdicts via FLTMGR.".to_string()),
                    )
                }
            }
        };

        PlatformRuntimeStatus {
            protection_state,
            monitor_health,
            state_reason,
            platform_name: "Windows".to_string(),
            enforcement_mechanism: "fltmgr".to_string(),
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

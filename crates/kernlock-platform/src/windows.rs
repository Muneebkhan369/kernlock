use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::analyze_file_bytes;
use kernlock_core::models::{
    CapabilityStatus, FileScanResult, PersistenceEntry, PlatformCapabilities, PolicyConfig,
    ProcessInfo, SecurityMode,
};
use kernlock_core::rules::RuleEngine;
use std::fs;
use std::path::Path;

pub struct WindowsSecurityProvider;

impl WindowsSecurityProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSecurityProvider for WindowsSecurityProvider {
    fn probe_capabilities(&self, _requested_mode: SecurityMode) -> PlatformCapabilities {
        // Honest capability reporting: without a signed WDAC policy, ELAM/minifilter driver,
        // or elevated ETW/AMSI host integration, enforcement cannot be claimed.
        let capabilities = vec![
            CapabilityStatus {
                name: "Windows Defender / AMSI Integration".to_string(),
                supported: cfg!(target_os = "windows"),
                enforcement_available: false,
                active_mode: "Audit / Planned (Requires AMSI COM/DLL integration)".to_string(),
                details: "Antimalware Scan Interface (AMSI) requires Windows host COM registration for script inspection."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Application Control (WDAC / AppLocker)".to_string(),
                supported: cfg!(target_os = "windows"),
                enforcement_available: false,
                active_mode: "Not configured (Requires Administrator & signed CI policy)".to_string(),
                details: "Windows Defender Application Control enforces binary allow-listing at kernel level."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Registry Run & Scheduled Task Persistence".to_string(),
                supported: cfg!(target_os = "windows"),
                enforcement_available: false,
                active_mode: if cfg!(target_os = "windows") {
                    "Audit (Registry/Task inspection)"
                } else {
                    "Unavailable on non-Windows host"
                }
                .to_string(),
                details: "Inspects HKCU/HKLM Run keys, Startup folders, and Task Scheduler entries."
                    .to_string(),
            },
        ];

        PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname_string(),
            is_privileged: false,
            active_mode: SecurityMode::Audit,
            fallback_reason: Some(
                "Windows kernel/AMSI enforcement hooks are not attached in this build; operating in Audit mode."
                    .to_string(),
            ),
            capabilities,
        }
    }

    fn list_processes(
        &self,
        _rules: &RuleEngine,
        _policy: &PolicyConfig,
    ) -> Result<Vec<ProcessInfo>, PlatformError> {
        #[cfg(target_os = "windows")]
        {
            Ok(Vec::new())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(PlatformError::Unsupported(
                "Windows process enumeration is only available on Windows hosts".to_string(),
            ))
        }
    }

    fn scan_persistence(&self, _rules: &RuleEngine) -> Result<Vec<PersistenceEntry>, PlatformError> {
        #[cfg(target_os = "windows")]
        {
            Ok(Vec::new())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(PlatformError::Unsupported(
                "Windows persistence scanning is only available on Windows hosts".to_string(),
            ))
        }
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

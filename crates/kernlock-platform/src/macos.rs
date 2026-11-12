use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::analyze_file_bytes;
use kernlock_core::models::{
    CapabilityStatus, FileScanResult, PersistenceEntry, PlatformCapabilities, PolicyConfig,
    ProcessInfo, SecurityMode,
};
use kernlock_core::rules::RuleEngine;
use std::fs;
use std::path::Path;

pub struct MacOsSecurityProvider;

impl MacOsSecurityProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacOsSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSecurityProvider for MacOsSecurityProvider {
    fn probe_capabilities(&self, requested_mode: SecurityMode) -> PlatformCapabilities {
        let capabilities = vec![
            CapabilityStatus {
                name: "Apple Endpoint Security Framework (ESF)".to_string(),
                supported: false,
                enforcement_available: false,
                active_mode: "Unsupported (ESF client not implemented; requires Apple entitlement & FDA)"
                    .to_string(),
                details: "ESF ES_EVENT_TYPE_AUTH_EXEC requires Apple-approved entitlement, notarization, and Full Disk Access."
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

        PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname_string(),
            is_privileged: false,
            kernel_blocking_available: false,
            auto_quarantine_available: false,
            active_mode: SecurityMode::Audit,
            fallback_reason: Some(format!(
                "macOS native monitoring and Endpoint Security enforcement are not yet implemented (requested {:?}); operating in static-scan Audit mode only.",
                requested_mode
            )),
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

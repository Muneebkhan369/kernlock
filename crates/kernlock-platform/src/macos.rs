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
    fn probe_capabilities(&self, _requested_mode: SecurityMode) -> PlatformCapabilities {
        let capabilities = vec![
            CapabilityStatus {
                name: "Apple Endpoint Security Framework (ESF)".to_string(),
                supported: cfg!(target_os = "macos"),
                enforcement_available: false,
                active_mode: "Unavailable (Requires Apple com.apple.developer.endpoint-security.client entitlement & FDA)"
                    .to_string(),
                details: "ESF ES_EVENT_TYPE_AUTH_EXEC requires Apple-approved entitlement, notarization, and Full Disk Access."
                    .to_string(),
            },
            CapabilityStatus {
                name: "LaunchAgents & LaunchDaemons Persistence".to_string(),
                supported: cfg!(target_os = "macos"),
                enforcement_available: false,
                active_mode: if cfg!(target_os = "macos") {
                    "Audit (~/Library/LaunchAgents, /Library/LaunchDaemons)"
                } else {
                    "Unavailable on non-macOS host"
                }
                .to_string(),
                details: "Inspects plist startup items and login hooks for suspicious commands."
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
                "Apple Endpoint Security entitlement is not present; operating in Audit mode."
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
        #[cfg(target_os = "macos")]
        {
            Ok(Vec::new())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(PlatformError::Unsupported(
                "macOS process enumeration is only available on macOS hosts".to_string(),
            ))
        }
    }

    fn scan_persistence(&self, _rules: &RuleEngine) -> Result<Vec<PersistenceEntry>, PlatformError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Vec::new())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(PlatformError::Unsupported(
                "macOS persistence scanning is only available on macOS hosts".to_string(),
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

use kernlock_core::{
    FileScanResult, PersistenceEntry, PlatformCapabilities, PolicyConfig, ProcessInfo, RuleEngine,
    SecurityMode,
};
use std::path::Path;
use thiserror::Error;

pub mod fanotify;
pub mod linux;
pub mod macos;
pub mod windows;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported operation on current OS: {0}")]
    Unsupported(String),
}

pub trait PlatformSecurityProvider: Send + Sync {
    fn probe_capabilities(&self, requested_mode: SecurityMode) -> PlatformCapabilities;
    fn list_processes(
        &self,
        rules: &RuleEngine,
        policy: &PolicyConfig,
    ) -> Result<Vec<ProcessInfo>, PlatformError>;
    fn scan_persistence(&self, rules: &RuleEngine) -> Result<Vec<PersistenceEntry>, PlatformError>;
    fn scan_path(
        &self,
        path: &Path,
        rules: &RuleEngine,
        policy: &PolicyConfig,
    ) -> Result<Vec<FileScanResult>, PlatformError>;
}

pub fn default_provider() -> Box<dyn PlatformSecurityProvider> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSecurityProvider::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsSecurityProvider::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsSecurityProvider::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(linux::LinuxSecurityProvider::new())
    }
}

pub fn hostname_string() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

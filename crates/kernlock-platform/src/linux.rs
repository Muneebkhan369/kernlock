use crate::{hostname_string, PlatformError, PlatformSecurityProvider};
use kernlock_core::analyzer::{aggregate_score, analyze_file_bytes};
use kernlock_core::models::{
    CapabilityStatus, EventCategory, FileScanResult, PersistenceEntry, PlatformCapabilities,
    PolicyConfig, ProcessInfo, RuleMatch, SecurityMode, Severity,
};
use kernlock_core::rules::{RuleEngine, RuleTarget};
use std::fs;
use std::path::{Path, PathBuf};

pub struct LinuxSecurityProvider;

impl LinuxSecurityProvider {
    pub fn new() -> Self {
        Self
    }

    fn is_root() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("Uid:") {
                        let euid = rest.split_whitespace().nth(1).unwrap_or("1000");
                        return euid == "0";
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn read_lsm_list() -> Vec<String> {
        fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.trim().split(',').map(|x| x.to_string()).collect())
            .unwrap_or_default()
    }
}

impl Default for LinuxSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSecurityProvider for LinuxSecurityProvider {
    fn probe_capabilities(&self, requested_mode: SecurityMode) -> PlatformCapabilities {
        let is_root = Self::is_root();
        let lsms = Self::read_lsm_list();
        let has_bpf_fs = Path::new("/sys/fs/bpf").exists();
        let has_auditd = Path::new("/sbin/auditd").exists()
            || Path::new("/usr/sbin/auditd").exists()
            || Path::new("/run/auditd.pid").exists();

        let fanotify_probe = crate::fanotify::FanotifyPermissionMonitor::probe_support();
        let inotify_supported = Path::new("/proc/sys/fs/inotify/max_user_watches").exists();

        let kernel_blocking_available = fanotify_probe.exec_blocking_available;
        let auto_quarantine_available = true;

        let (active_mode, fallback_reason) = match requested_mode {
            SecurityMode::Audit => (SecurityMode::Audit, None),
            SecurityMode::Protection | SecurityMode::Strict => {
                if kernel_blocking_available {
                    (requested_mode, None)
                } else {
                    (
                        requested_mode,
                        Some(format!(
                            "Pre-execution kernel blocking is unavailable ({}). {:?} mode performs post-write detection and automatic quarantine only.",
                            fanotify_probe.details,
                            requested_mode
                        )),
                    )
                }
            }
        };

        let capabilities = vec![
            CapabilityStatus {
                name: "File System Watch (inotify)".to_string(),
                supported: inotify_supported,
                enforcement_available: false,
                active_mode: if inotify_supported {
                    "Active (Post-write event monitoring)".to_string()
                } else {
                    "Unavailable".to_string()
                },
                details: "Monitors configured directories for created/modified files without requiring root."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Automatic Post-Write Quarantine".to_string(),
                supported: true,
                enforcement_available: true,
                active_mode: if requested_mode == SecurityMode::Audit {
                    "Standby (Audit mode active)".to_string()
                } else {
                    "Active (Moves high-risk files to 0600 vault)".to_string()
                },
                details: "Reversibly quarantines high-risk files after detection when Protection or Strict mode is enabled."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Pre-Execution / Access Blocking (fanotify)".to_string(),
                supported: fanotify_probe.supported,
                enforcement_available: fanotify_probe.exec_blocking_available,
                active_mode: if fanotify_probe.exec_blocking_available {
                    match requested_mode {
                        SecurityMode::Audit => "Standby (Audit mode active)".to_string(),
                        SecurityMode::Protection => {
                            "Active (FAN_OPEN_EXEC_PERM execution blocking)".to_string()
                        }
                        SecurityMode::Strict => {
                            "Active (Strict execution blocking, fail-closed)".to_string()
                        }
                    }
                } else if fanotify_probe.supported {
                    "Degraded (FAN_OPEN_PERM only; execution blocking unavailable)".to_string()
                } else {
                    format!("Unavailable ({})", fanotify_probe.details)
                },
                details: format!(
                    "Kernel execution blocking. Monitored mounts: {}. Unmonitored mounts: {}. Status: {}",
                    if fanotify_probe.monitored_mounts.is_empty() {
                        "None".to_string()
                    } else {
                        fanotify_probe.monitored_mounts.join(", ")
                    },
                    if fanotify_probe.unmonitored_mounts.is_empty() {
                        "None".to_string()
                    } else {
                        fanotify_probe.unmonitored_mounts.join(", ")
                    },
                    fanotify_probe.details
                ),
            },
            CapabilityStatus {
                name: "Process Telemetry (/proc)".to_string(),
                supported: Path::new("/proc").exists(),
                enforcement_available: false,
                active_mode: "Active (Live process inspection)".to_string(),
                details: "Inspects running PIDs, command lines, executable paths, and deleted-binary anomalies."
                    .to_string(),
            },
            CapabilityStatus {
                name: "Linux Security Modules (LSM)".to_string(),
                supported: !lsms.is_empty(),
                enforcement_available: false,
                active_mode: if lsms.is_empty() {
                    "Not detected".to_string()
                } else {
                    format!("Detected: {}", lsms.join(", "))
                },
                details: "Kernel-level MAC/sandboxing subsystems reported via /sys/kernel/security/lsm (read-only telemetry)."
                    .to_string(),
            },
            CapabilityStatus {
                name: "eBPF / Audit Subsystem".to_string(),
                supported: has_bpf_fs || has_auditd,
                enforcement_available: false,
                active_mode: format!(
                    "bpffs={}, auditd={}",
                    if has_bpf_fs { "mounted" } else { "absent" },
                    if has_auditd { "present" } else { "absent" }
                ),
                details: "Kernel tracing and audit infrastructure; eBPF probes are not yet attached in Phase 1.1."
                    .to_string(),
            },
        ];

        PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname_string(),
            is_privileged: is_root,
            kernel_blocking_available,
            auto_quarantine_available,
            active_mode,
            fallback_reason,
            capabilities,
        }
    }

    fn list_processes(
        &self,
        rules: &RuleEngine,
        policy: &PolicyConfig,
    ) -> Result<Vec<ProcessInfo>, PlatformError> {
        let mut processes = Vec::new();
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(e) => return Err(PlatformError::Io(e)),
        };

        for entry in proc_dir.flatten() {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };

            let pid_path = entry.path();
            let status = fs::read_to_string(pid_path.join("status")).unwrap_or_default();
            let mut name = String::new();
            let mut ppid = 0u32;
            let mut uid = 0u32;

            for line in status.lines() {
                if let Some(v) = line.strip_prefix("Name:") {
                    name = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("PPid:") {
                    ppid = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Uid:") {
                    uid = v
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }

            if policy.excluded_processes.contains(&name) {
                continue;
            }

            let cmdline_bytes = fs::read(pid_path.join("cmdline")).unwrap_or_default();
            let cmdline = cmdline_bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ");

            let exe_raw = fs::read_link(pid_path.join("exe"))
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let exe_deleted = exe_raw.ends_with(" (deleted)");
            let exe_path = exe_raw.trim_end_matches(" (deleted)").to_string();

            let cwd = fs::read_link(pid_path.join("cwd"))
                .map(|p| p.display().to_string())
                .unwrap_or_default();

            let mut matches = Vec::new();
            let mut risk_flags = Vec::new();

            if exe_deleted {
                risk_flags.push("deleted_executable".to_string());
                matches.push(RuleMatch {
                    rule_id: "KL-PROC-DEL".to_string(),
                    rule_name: "Process Running Deleted Executable".to_string(),
                    severity: Severity::High,
                    score: 70,
                    category: EventCategory::Process,
                    explanation: "Process is executing a binary that has been unlinked from disk (common in fileless staging or unpatched updates).".to_string(),
                    evidence: exe_raw.clone(),
                    remediation: "Verify if a recent package upgrade replaced this binary; otherwise inspect and terminate.".to_string(),
                });
            }

            if !exe_path.is_empty() {
                let proc_matches = rules.evaluate(RuleTarget::Process, &exe_path);
                for m in proc_matches {
                    risk_flags.push(m.rule_id.clone());
                    matches.push(m);
                }
            }

            if !cmdline.is_empty() {
                let cmd_matches = rules.evaluate(RuleTarget::Command, &cmdline);
                for m in cmd_matches {
                    risk_flags.push(m.rule_id.clone());
                    matches.push(m);
                }
            }

            let risk_score = aggregate_score(&matches);

            processes.push(ProcessInfo {
                pid,
                ppid,
                uid,
                name,
                exe_path,
                cmdline,
                cwd,
                exe_deleted,
                risk_score,
                risk_flags,
                matches,
            });
        }

        processes.sort_by(|a, b| b.risk_score.cmp(&a.risk_score).then(a.pid.cmp(&b.pid)));
        Ok(processes)
    }

    fn scan_persistence(&self, rules: &RuleEngine) -> Result<Vec<PersistenceEntry>, PlatformError> {
        let mut entries = Vec::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        // 1. Systemd unit files (system and user)
        let systemd_dirs = [
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from(&home).join(".config/systemd/user"),
        ];
        for dir in &systemd_dirs {
            if let Ok(rd) = fs::read_dir(dir) {
                for item in rd.flatten() {
                    let path = item.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("service") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            let exec_lines: Vec<&str> = content
                                .lines()
                                .filter(|l| l.trim_start().starts_with("ExecStart="))
                                .collect();
                            let target_cmd = exec_lines.join(" ; ");
                            let matches = evaluate_persistence(rules, &target_cmd);
                            entries.push(PersistenceEntry {
                                id: format!("systemd:{}", path.display()),
                                source_type: "systemd_service".to_string(),
                                location: path.display().to_string(),
                                name: path
                                    .file_name()
                                    .map(|s| s.to_string_lossy().to_string())
                                    .unwrap_or_default(),
                                command_or_target: target_cmd,
                                enabled: true,
                                risk_score: aggregate_score(&matches),
                                matches,
                            });
                        }
                    }
                }
            }
        }

        // 2. XDG Autostart entries
        let autostart_dir = PathBuf::from(&home).join(".config/autostart");
        if let Ok(rd) = fs::read_dir(&autostart_dir) {
            for item in rd.flatten() {
                let path = item.path();
                if path.extension().and_then(|s| s.to_str()) == Some("desktop") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let exec_line = content
                            .lines()
                            .find(|l| l.trim_start().starts_with("Exec="))
                            .unwrap_or("")
                            .to_string();
                        let matches = evaluate_persistence(rules, &exec_line);
                        entries.push(PersistenceEntry {
                            id: format!("autostart:{}", path.display()),
                            source_type: "xdg_autostart".to_string(),
                            location: path.display().to_string(),
                            name: path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            command_or_target: exec_line,
                            enabled: !content.contains("Hidden=true"),
                            risk_score: aggregate_score(&matches),
                            matches,
                        });
                    }
                }
            }
        }

        // 3. Cron files
        let mut cron_paths = vec![PathBuf::from("/etc/crontab")];
        if let Ok(rd) = fs::read_dir("/etc/cron.d") {
            for item in rd.flatten() {
                cron_paths.push(item.path());
            }
        }
        for path in cron_paths {
            if let Ok(content) = fs::read_to_string(&path) {
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty()
                        || trimmed.starts_with('#')
                        || trimmed.contains('=') && !trimmed.contains(' ')
                    {
                        continue;
                    }
                    let matches = evaluate_persistence(rules, trimmed);
                    if !matches.is_empty() || trimmed.contains('/') {
                        entries.push(PersistenceEntry {
                            id: format!("cron:{}:{}", path.display(), idx + 1),
                            source_type: "cron_job".to_string(),
                            location: format!("{}:{}", path.display(), idx + 1),
                            name: path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            command_or_target: trimmed.to_string(),
                            enabled: true,
                            risk_score: aggregate_score(&matches),
                            matches,
                        });
                    }
                }
            }
        }

        // 4. /etc/ld.so.preload check
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            if let Ok(content) = fs::read_to_string(preload_path) {
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let matches = vec![RuleMatch {
                        rule_id: "KL-PERSIST-PRELOAD".to_string(),
                        rule_name: "Global Dynamic Linker Preload Entry".to_string(),
                        severity: Severity::High,
                        score: 80,
                        category: EventCategory::Persistence,
                        explanation: "/etc/ld.so.preload forces a shared library into every dynamically linked process on the system.".to_string(),
                        evidence: trimmed.to_string(),
                        remediation: "Verify whether this library is an authorized security/profiling agent; remove if unrecognized.".to_string(),
                    }];
                    entries.push(PersistenceEntry {
                        id: format!("ld_preload:{}", idx + 1),
                        source_type: "ld_so_preload".to_string(),
                        location: "/etc/ld.so.preload".to_string(),
                        name: trimmed.to_string(),
                        command_or_target: trimmed.to_string(),
                        enabled: true,
                        risk_score: 80,
                        matches,
                    });
                }
            }
        }

        // 5. Shell startup scripts (suspicious lines only to avoid noise)
        for rc_name in [".bashrc", ".profile", ".zshrc"] {
            let rc_path = PathBuf::from(&home).join(rc_name);
            if let Ok(content) = fs::read_to_string(&rc_path) {
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let matches = evaluate_persistence(rules, trimmed);
                    if !matches.is_empty() {
                        entries.push(PersistenceEntry {
                            id: format!("shell:{}:{}", rc_path.display(), idx + 1),
                            source_type: "shell_profile".to_string(),
                            location: format!("{}:{}", rc_path.display(), idx + 1),
                            name: rc_name.to_string(),
                            command_or_target: trimmed.to_string(),
                            enabled: true,
                            risk_score: aggregate_score(&matches),
                            matches,
                        });
                    }
                }
            }
        }

        entries.sort_by_key(|a| std::cmp::Reverse(a.risk_score));
        Ok(entries)
    }

    fn scan_path(
        &self,
        path: &Path,
        rules: &RuleEngine,
        policy: &PolicyConfig,
    ) -> Result<Vec<FileScanResult>, PlatformError> {
        let mut results = Vec::new();
        let max_bytes = policy.max_scan_file_size_mb * 1024 * 1024;
        scan_recursive(path, rules, policy, max_bytes, &mut results)?;
        Ok(results)
    }
}

fn evaluate_persistence(rules: &RuleEngine, cmd: &str) -> Vec<RuleMatch> {
    let mut matches = rules.evaluate(RuleTarget::Persistence, cmd);
    matches.extend(rules.evaluate(RuleTarget::Command, cmd));
    let mut seen = std::collections::HashSet::new();
    matches.retain(|m| seen.insert(m.rule_id.clone()));
    matches
}

fn scan_recursive(
    path: &Path,
    rules: &RuleEngine,
    policy: &PolicyConfig,
    max_bytes: u64,
    results: &mut Vec<FileScanResult>,
) -> Result<(), PlatformError> {
    let path_str = path.to_string_lossy();
    if path_str == "/proc" || path_str == "/sys" || path_str == "/dev" || path_str == "/run" {
        return Ok(());
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        if meta.len() <= max_bytes {
            if let Ok(bytes) = fs::read(path) {
                results.push(analyze_file_bytes(&path_str, &bytes, rules, policy));
            }
        }
        return Ok(());
    }
    if meta.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            for entry in rd.flatten() {
                scan_recursive(&entry.path(), rules, policy, max_bytes, results)?;
            }
        }
    }
    Ok(())
}

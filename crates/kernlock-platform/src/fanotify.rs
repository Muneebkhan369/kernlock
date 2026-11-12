use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use {
    chrono::Utc,
    kernlock_core::{
        scan_file_from_fd, AlertStatus, EventCategory, PolicyConfig, RuleEngine, SecurityEvent,
        SecurityMode, ThreatAlert,
    },
    std::fs,
    std::path::PathBuf,
    std::sync::RwLock,
    std::thread,
    tracing::{error, info, warn},
    uuid::Uuid,
};

#[cfg(target_os = "linux")]
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

#[derive(Debug, Clone)]
pub struct FanotifyProbeDetails {
    pub supported: bool,
    pub exec_blocking_available: bool,
    pub details: String,
    pub monitored_mounts: Vec<String>,
    pub unmonitored_mounts: Vec<String>,
}

#[derive(Clone)]
pub struct FanotifyPermissionMonitor {
    #[cfg(target_os = "linux")]
    fanotify_fd: i32,
    is_running: Arc<AtomicBool>,
    exec_blocking_supported: Arc<AtomicBool>,
    monitored_mounts: Arc<RwLock<Vec<String>>>,
    unmonitored_mounts: Arc<RwLock<Vec<String>>>,
}

impl FanotifyPermissionMonitor {
    pub fn is_supported() -> bool {
        Self::probe_support().supported
    }

    pub fn is_exec_blocking_available() -> bool {
        Self::probe_support().exec_blocking_available
    }

    pub fn probe_support() -> FanotifyProbeDetails {
        #[cfg(target_os = "linux")]
        {
            let (monitored, unmonitored) = Self::discover_mounts();

            let fd = unsafe {
                libc::fanotify_init(
                    libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
                    libc::O_RDONLY as u32,
                )
            };

            if fd < 0 {
                return FanotifyProbeDetails {
                    supported: false,
                    exec_blocking_available: false,
                    details: format!("fanotify_init failed: {}", std::io::Error::last_os_error()),
                    monitored_mounts: Vec::new(),
                    unmonitored_mounts: unmonitored,
                };
            }

            let root_c = match std::ffi::CString::new("/") {
                Ok(c) => c,
                Err(e) => {
                    unsafe { libc::close(fd) };
                    return FanotifyProbeDetails {
                        supported: false,
                        exec_blocking_available: false,
                        details: format!("CString error: {}", e),
                        monitored_mounts: Vec::new(),
                        unmonitored_mounts: unmonitored,
                    };
                }
            };

            // 1. Probe with FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM
            let full_mask = libc::FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM;
            let mark_res = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                    full_mask,
                    libc::AT_FDCWD,
                    root_c.as_ptr(),
                )
            };

            if mark_res == 0 {
                unsafe { libc::close(fd) };
                return FanotifyProbeDetails {
                    supported: true,
                    exec_blocking_available: true,
                    details: "fanotify initialized and mount marked with FAN_OPEN_EXEC_PERM"
                        .to_string(),
                    monitored_mounts: monitored,
                    unmonitored_mounts: unmonitored,
                };
            }

            let mark_err = std::io::Error::last_os_error();
            if mark_err.raw_os_error() == Some(libc::EINVAL) {
                // Retry with FAN_OPEN_PERM only (kernel lacking FAN_OPEN_EXEC_PERM)
                let fallback = unsafe {
                    libc::fanotify_mark(
                        fd,
                        libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                        libc::FAN_OPEN_PERM,
                        libc::AT_FDCWD,
                        root_c.as_ptr(),
                    )
                };

                unsafe { libc::close(fd) };

                if fallback == 0 {
                    return FanotifyProbeDetails {
                        supported: true,
                        exec_blocking_available: false,
                        details: "Kernel supports FAN_OPEN_PERM but lacks FAN_OPEN_EXEC_PERM execution blocking (kernel < 5.0)".to_string(),
                        monitored_mounts: monitored,
                        unmonitored_mounts: unmonitored,
                    };
                }
            }

            unsafe { libc::close(fd) };
            FanotifyProbeDetails {
                supported: false,
                exec_blocking_available: false,
                details: format!("fanotify_mark failed: {}", mark_err),
                monitored_mounts: Vec::new(),
                unmonitored_mounts: unmonitored,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            FanotifyProbeDetails {
                supported: false,
                exec_blocking_available: false,
                details: "fanotify is only supported on Linux kernels".to_string(),
                monitored_mounts: Vec::new(),
                unmonitored_mounts: Vec::new(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn discover_mounts() -> (Vec<String>, Vec<String>) {
        let mut monitored = Vec::new();
        let mut unmonitored = Vec::new();

        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let mountpoint = parts[1];
                    let fstype = parts[2];

                    if mountpoint == "/" {
                        monitored.push(format!("{mountpoint} ({fstype})"));
                    } else if fstype == "proc"
                        || fstype == "sysfs"
                        || fstype == "devpts"
                        || fstype == "cgroup"
                        || fstype == "cgroup2"
                        || fstype == "securityfs"
                        || fstype == "tmpfs"
                        || mountpoint.starts_with("/sys")
                        || mountpoint.starts_with("/proc")
                        || mountpoint.starts_with("/dev")
                        || mountpoint.starts_with("/run")
                    {
                        unmonitored.push(format!("{mountpoint} ({fstype})"));
                    } else {
                        // Separate filesystem mounts (e.g. /home, /boot, external mounts)
                        unmonitored.push(format!(
                            "{mountpoint} ({fstype}, separate filesystem mount)"
                        ));
                    }
                }
            }
        } else {
            monitored.push("/ (rootfs)".to_string());
            unmonitored.push("/proc, /sys, /dev, /run (pseudo-filesystems)".to_string());
        }

        (monitored, unmonitored)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn discover_mounts() -> (Vec<String>, Vec<String>) {
        (Vec::new(), Vec::new())
    }

    #[cfg(target_os = "linux")]
    pub fn init() -> Result<Self, String> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_NONBLOCK | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };

        if fd < 0 {
            return Err(format!(
                "fanotify_init failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut exec_supported = true;
        let mask = libc::FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM;
        let root_c = std::ffi::CString::new("/").map_err(|e| e.to_string())?;

        let res = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                root_c.as_ptr(),
            )
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                exec_supported = false;
                let fallback = unsafe {
                    libc::fanotify_mark(
                        fd,
                        libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                        libc::FAN_OPEN_PERM,
                        libc::AT_FDCWD,
                        root_c.as_ptr(),
                    )
                };
                if fallback < 0 {
                    unsafe { libc::close(fd) };
                    return Err(format!(
                        "fanotify_mark mount failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            } else {
                unsafe { libc::close(fd) };
                return Err(format!("fanotify_mark mount failed: {}", err));
            }
        }

        let (monitored, unmonitored) = Self::discover_mounts();

        info!(
            "Fanotify kernel execution blocking monitor initialized (fd: {}, exec_blocking: {})",
            fd, exec_supported
        );
        Ok(Self {
            fanotify_fd: fd,
            is_running: Arc::new(AtomicBool::new(false)),
            exec_blocking_supported: Arc::new(AtomicBool::new(exec_supported)),
            monitored_mounts: Arc::new(RwLock::new(monitored)),
            unmonitored_mounts: Arc::new(RwLock::new(unmonitored)),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn init() -> Result<Self, String> {
        Err("fanotify is only supported on Linux kernels with CAP_SYS_ADMIN".to_string())
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn is_exec_blocking_supported(&self) -> bool {
        self.exec_blocking_supported.load(Ordering::SeqCst)
    }

    pub fn monitored_mounts(&self) -> Vec<String> {
        self.monitored_mounts
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn unmonitored_mounts(&self) -> Vec<String> {
        self.unmonitored_mounts
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    pub fn start<F>(
        &self,
        vault_dir: PathBuf,
        get_policy: Arc<dyn Fn() -> PolicyConfig + Send + Sync + 'static>,
        rules: Arc<RuleEngine>,
        on_threat: F,
    ) where
        F: Fn(SecurityEvent, ThreatAlert) + Send + Sync + 'static,
    {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return;
        }

        let is_running = self.is_running.clone();
        let fanotify_fd = self.fanotify_fd;
        let self_pid = std::process::id() as i32;

        thread::spawn(move || {
            info!("fanotify kernel permission event loop started");
            let mut buf = [0u8; 64 * 1024];

            while is_running.load(Ordering::SeqCst) {
                let mut pfd = libc::pollfd {
                    fd: fanotify_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };

                let poll_res = unsafe { libc::poll(&mut pfd, 1, 50) };
                if poll_res <= 0 {
                    continue;
                }

                if (pfd.revents & libc::POLLIN) == 0 {
                    continue;
                }

                let n = unsafe {
                    libc::read(
                        fanotify_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EAGAIN)
                        || err.raw_os_error() == Some(libc::EINTR)
                    {
                        continue;
                    }
                    warn!("fanotify event read error: {}", err);
                    continue;
                }

                let mut offset = 0;
                while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
                    let metadata = unsafe {
                        &*(buf[offset..].as_ptr() as *const libc::fanotify_event_metadata)
                    };

                    // Handle event queue overflow
                    if (metadata.mask & libc::FAN_Q_OVERFLOW) != 0 {
                        warn!("fanotify kernel event queue overflowed: some events were dropped");
                        break;
                    }

                    if metadata.event_len
                        < std::mem::size_of::<libc::fanotify_event_metadata>() as u32
                    {
                        warn!("malformed fanotify event metadata: event_len too short");
                        break;
                    }

                    let event_fd = metadata.fd;
                    let event_pid = metadata.pid;
                    let event_mask = metadata.mask;

                    if event_fd >= 0 {
                        let policy = get_policy();
                        let decision = Self::evaluate_event(
                            event_fd, event_pid, self_pid, event_mask, &vault_dir, &policy, &rules,
                            &on_threat,
                        );

                        let response = libc::fanotify_response {
                            fd: event_fd,
                            response: decision,
                        };

                        let write_res = unsafe {
                            libc::write(
                                fanotify_fd,
                                &response as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::fanotify_response>(),
                            )
                        };

                        if write_res < 0 {
                            error!(
                                "Failed to send fanotify permission response for fd {} (decision: {}): {}",
                                event_fd,
                                decision,
                                std::io::Error::last_os_error()
                            );
                        }

                        unsafe {
                            libc::close(event_fd);
                        }
                    }

                    offset += metadata.event_len as usize;
                }
            }

            info!("fanotify kernel permission event loop terminated");
        });
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_event<F>(
        event_fd: i32,
        event_pid: i32,
        self_pid: i32,
        event_mask: u64,
        vault_dir: &Path,
        policy: &PolicyConfig,
        rules: &RuleEngine,
        on_threat: &F,
    ) -> u32
    where
        F: Fn(SecurityEvent, ThreatAlert),
    {
        // 1. Self-exclusion: Never block KernLock daemon itself
        if event_pid == self_pid {
            return libc::FAN_ALLOW;
        }

        // 2. Identify whether this is an execution attempt (FAN_OPEN_EXEC_PERM) vs normal open (FAN_OPEN_PERM)
        let is_exec = (event_mask & FAN_OPEN_EXEC_PERM) != 0;

        // 3. Resolve diagnostic path from /proc/self/fd/<fd>
        let fd_path = format!("/proc/self/fd/{}", event_fd);
        let real_path =
            fs::read_link(&fd_path).unwrap_or_else(|_| PathBuf::from(format!("<fd:{event_fd}>")));
        let path_str = real_path.to_string_lossy().to_string();

        // 4. Skip internal / pseudo-filesystems and quarantine vault
        if real_path.starts_with(vault_dir)
            || path_str.starts_with("/proc")
            || path_str.starts_with("/sys")
            || (path_str.starts_with("/dev") && !path_str.starts_with("/dev/shm"))
            || path_str.starts_with("/run")
        {
            return libc::FAN_ALLOW;
        }

        // 5. Policy path exclusions
        if policy.is_path_excluded(&real_path) {
            return libc::FAN_ALLOW;
        }

        // 6. In Audit mode, observe without blocking
        if policy.mode == SecurityMode::Audit {
            return libc::FAN_ALLOW;
        }

        // 7. Scan the ACTUAL OPENED FILE OBJECT directly from event_fd (no TOCTOU path races)
        match scan_file_from_fd(event_fd, &path_str, rules, policy) {
            Ok(res) => {
                if res.is_suspicious || res.risk_score >= policy.auto_quarantine_threshold {
                    let action = if is_exec {
                        "KernelExecutionBlocked"
                    } else {
                        "KernelFileAccessBlocked"
                    };

                    warn!(
                        "fanotify BLOCKED (exec={}): {} (pid: {}, risk: {}, threat: {:?})",
                        is_exec, path_str, event_pid, res.risk_score, res.threat_name
                    );

                    let title = if is_exec {
                        format!(
                            "Execution Blocked: {}",
                            res.threat_name.as_deref().unwrap_or("Malicious Binary")
                        )
                    } else {
                        format!(
                            "File Access Blocked: {}",
                            res.threat_name.as_deref().unwrap_or("Malicious File")
                        )
                    };

                    let category = if is_exec {
                        EventCategory::Process
                    } else {
                        EventCategory::File
                    };

                    let event = SecurityEvent {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        category,
                        severity: res.severity,
                        title,
                        description: format!(
                            "Kernel fanotify blocked PID {} from {} file {}",
                            event_pid,
                            if is_exec { "executing" } else { "opening" },
                            path_str
                        ),
                        target: path_str.clone(),
                        risk_score: res.risk_score,
                        action_taken: action.to_string(),
                        rule_ids: res.matches.iter().map(|m| m.rule_id.clone()).collect(),
                        metadata: serde_json::json!({
                            "pid": event_pid,
                            "sha256": res.sha256,
                            "threat_name": res.threat_name,
                            "is_exec": is_exec,
                            "mask": event_mask,
                        }),
                    };

                    let alert = ThreatAlert {
                        id: Uuid::new_v4(),
                        event_id: event.id,
                        timestamp: event.timestamp,
                        severity: res.severity,
                        title: event.title.clone(),
                        explanation: res.summary.clone(),
                        target: path_str,
                        risk_score: res.risk_score,
                        status: AlertStatus::Open,
                        recommended_action: if is_exec {
                            "Execution was blocked in kernel. Terminate invoking process and quarantine payload."
                                .to_string()
                        } else {
                            "Access was blocked in kernel. Quarantine file and review endpoint logs."
                                .to_string()
                        },
                    };

                    on_threat(event, alert);

                    // Block execution / open in kernel
                    libc::FAN_DENY
                } else {
                    libc::FAN_ALLOW
                }
            }
            Err(e) => {
                warn!("fanotify fd scan error for {}: {}", path_str, e);
                // Fail-closed in Strict mode, fail-open in Protection mode
                if policy.mode == SecurityMode::Strict {
                    libc::FAN_DENY
                } else {
                    libc::FAN_ALLOW
                }
            }
        }
    }

    pub fn stop(&self) {
        if self.is_running.swap(false, Ordering::SeqCst) {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::close(self.fanotify_fd);
            }
            info!("fanotify permission monitor stopped");
        }
    }
}

impl Drop for FanotifyPermissionMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

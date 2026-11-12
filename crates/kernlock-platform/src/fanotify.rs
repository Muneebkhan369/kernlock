use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use {
    chrono::Utc,
    kernlock_core::{
        scan_file_streaming, AlertStatus, EventCategory, PolicyConfig, RuleEngine, SecurityEvent,
        SecurityMode, ThreatAlert,
    },
    std::fs,
    std::path::PathBuf,
    std::thread,
    tracing::{info, warn},
    uuid::Uuid,
};

#[cfg(target_os = "linux")]
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

#[derive(Clone)]
pub struct FanotifyPermissionMonitor {
    #[cfg(target_os = "linux")]
    fanotify_fd: i32,
    is_running: Arc<AtomicBool>,
}

impl FanotifyPermissionMonitor {
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe {
                libc::fanotify_init(
                    libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
                    libc::O_RDONLY as u32,
                )
            };
            if fd >= 0 {
                unsafe { libc::close(fd) };
                true
            } else {
                false
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
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

        // Try marking root mount with FAN_OPEN_PERM and FAN_OPEN_EXEC_PERM
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
            // If EINVAL, retry with FAN_OPEN_PERM only (kernel < 5.0 compatibility)
            if err.raw_os_error() == Some(libc::EINVAL) {
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

        info!(
            "Fanotify kernel execution blocking monitor initialized (fd: {})",
            fd
        );
        Ok(Self {
            fanotify_fd: fd,
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn init() -> Result<Self, String> {
        Err("fanotify is only supported on Linux kernels with CAP_SYS_ADMIN".to_string())
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
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
            return; // Already running
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

                let poll_res = unsafe { libc::poll(&mut pfd, 1, 100) };
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

                if n <= 0 {
                    continue;
                }

                let mut offset = 0;
                while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
                    let metadata = unsafe {
                        &*(buf[offset..].as_ptr() as *const libc::fanotify_event_metadata)
                    };

                    if metadata.event_len
                        < std::mem::size_of::<libc::fanotify_event_metadata>() as u32
                    {
                        break;
                    }

                    let event_fd = metadata.fd;
                    let event_pid = metadata.pid;

                    if event_fd >= 0 {
                        let policy = get_policy();
                        let decision = Self::evaluate_event(
                            event_fd, event_pid, self_pid, &vault_dir, &policy, &rules, &on_threat,
                        );

                        let response = libc::fanotify_response {
                            fd: event_fd,
                            response: decision,
                        };

                        unsafe {
                            libc::write(
                                fanotify_fd,
                                &response as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::fanotify_response>(),
                            );
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
    fn evaluate_event<F>(
        event_fd: i32,
        event_pid: i32,
        self_pid: i32,
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

        // 2. Resolve accessed file path from /proc/self/fd/<fd>
        let fd_path = format!("/proc/self/fd/{}", event_fd);
        let real_path = match fs::read_link(&fd_path) {
            Ok(p) => p,
            Err(_) => {
                // If path resolution fails, fail-closed in Strict mode, fail-open in Protection mode
                return if policy.mode == SecurityMode::Strict {
                    libc::FAN_DENY
                } else {
                    libc::FAN_ALLOW
                };
            }
        };

        let path_str = real_path.to_string_lossy();

        // 3. Skip internal / pseudo-filesystems and quarantine vault
        if real_path.starts_with(vault_dir)
            || path_str.starts_with("/proc")
            || path_str.starts_with("/sys")
            || (path_str.starts_with("/dev") && !path_str.starts_with("/dev/shm"))
            || path_str.starts_with("/run")
        {
            return libc::FAN_ALLOW;
        }

        // 4. Policy path exclusions
        if policy.is_path_excluded(&real_path) {
            return libc::FAN_ALLOW;
        }

        // 5. In Audit mode, observe and alert without blocking
        if policy.mode == SecurityMode::Audit {
            return libc::FAN_ALLOW;
        }

        // 6. Inspect file content via streaming scanner
        match scan_file_streaming(&real_path, rules, policy) {
            Ok(res) => {
                if res.is_suspicious || res.risk_score >= policy.auto_quarantine_threshold {
                    warn!(
                        "fanotify BLOCKED: {} (pid: {}, risk: {}, threat: {:?})",
                        path_str, event_pid, res.risk_score, res.threat_name
                    );

                    let event = SecurityEvent {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        category: EventCategory::Process,
                        severity: res.severity,
                        title: format!(
                            "Execution Blocked: {}",
                            res.threat_name.as_deref().unwrap_or("Malicious Binary")
                        ),
                        description: format!(
                            "Kernel fanotify blocked process PID {} from opening/executing suspicious file {}",
                            event_pid, path_str
                        ),
                        target: path_str.to_string(),
                        risk_score: res.risk_score,
                        action_taken: "KernelExecutionBlocked".to_string(),
                        rule_ids: res.matches.iter().map(|m| m.rule_id.clone()).collect(),
                        metadata: serde_json::json!({
                            "pid": event_pid,
                            "sha256": res.sha256,
                            "threat_name": res.threat_name,
                        }),
                    };

                    let alert = ThreatAlert {
                        id: Uuid::new_v4(),
                        event_id: event.id,
                        timestamp: event.timestamp,
                        severity: res.severity,
                        title: event.title.clone(),
                        explanation: res.summary.clone(),
                        target: path_str.to_string(),
                        risk_score: res.risk_score,
                        status: AlertStatus::Open,
                        recommended_action: "Quarantine file and inspect the invoking process."
                            .to_string(),
                    };

                    on_threat(event, alert);

                    // Block execution in kernel
                    libc::FAN_DENY
                } else {
                    libc::FAN_ALLOW
                }
            }
            Err(e) => {
                warn!("fanotify scan error for {}: {}", path_str, e);
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

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kernlock_core::paths::{auth_token_path, default_data_dir, read_validated_token_file};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;

const DAEMON_PORT: u16 = 17420;

#[derive(Debug, Clone, Serialize)]
struct DaemonStatus {
    running: bool,
    managed_by_desktop: bool,
    error: Option<String>,
}

struct DaemonState {
    child: Mutex<Option<Child>>,
    status: Mutex<DaemonStatus>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            status: Mutex::new(DaemonStatus {
                running: false,
                managed_by_desktop: false,
                error: None,
            }),
        }
    }
}

fn daemon_binary_name() -> &'static str {
    if cfg!(windows) {
        "kernlock.exe"
    } else {
        "kernlock"
    }
}

fn locate_daemon_binary() -> PathBuf {
    let bin_name = daemon_binary_name();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(bin_name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(bin_name)
}

fn probe_daemon_health(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let req = format!(
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n]);
            text.contains("200 OK") && text.contains("kernlockd")
        }
        _ => false,
    }
}

fn ensure_daemon_running(state: &DaemonState) -> DaemonStatus {
    // 1. Prevent duplicate daemon instances: reuse an already-healthy daemon.
    if probe_daemon_health(DAEMON_PORT) {
        let status = DaemonStatus {
            running: true,
            managed_by_desktop: false,
            error: None,
        };
        *state.status.lock().unwrap() = status.clone();
        return status;
    }

    // 2. Clean up any previously tracked exited child.
    {
        let mut guard = state.child.lock().unwrap();
        if let Some(mut existing) = guard.take() {
            let _ = existing.kill();
            let _ = existing.wait();
        }
    }

    let data_dir = default_data_dir();
    if let Err(e) = fs::create_dir_all(&data_dir) {
        let status = DaemonStatus {
            running: false,
            managed_by_desktop: false,
            error: Some(format!(
                "Failed to create KernLock data directory {}: {}",
                data_dir.display(),
                e
            )),
        };
        *state.status.lock().unwrap() = status.clone();
        return status;
    }

    let log_path = data_dir.join("daemon.log");
    let (stdout_cfg, stderr_cfg) = match OpenOptions::new().create(true).append(true).open(&log_path)
    {
        Ok(file) => match file.try_clone() {
            Ok(err_file) => (Stdio::from(file), Stdio::from(err_file)),
            Err(_) => (Stdio::null(), Stdio::null()),
        },
        Err(_) => (Stdio::null(), Stdio::null()),
    };

    let bin_path = locate_daemon_binary();
    let mut cmd = Command::new(&bin_path);
    cmd.arg("--data-dir")
        .arg(&data_dir)
        .arg("serve")
        .arg("--port")
        .arg(DAEMON_PORT.to_string())
        .stdout(stdout_cfg)
        .stderr(stderr_cfg);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let status = DaemonStatus {
                running: false,
                managed_by_desktop: false,
                error: Some(format!(
                    "Failed to start KernLock daemon ({}): {}",
                    bin_path.display(),
                    e
                )),
            };
            *state.status.lock().unwrap() = status.clone();
            return status;
        }
    };

    // 3. Wait up to 5 seconds for health endpoint readiness.
    for _ in 0..25 {
        if probe_daemon_health(DAEMON_PORT) {
            *state.child.lock().unwrap() = Some(child);
            let status = DaemonStatus {
                running: true,
                managed_by_desktop: true,
                error: None,
            };
            *state.status.lock().unwrap() = status.clone();
            return status;
        }
        if let Ok(Some(exit)) = child.try_wait() {
            let status = DaemonStatus {
                running: false,
                managed_by_desktop: false,
                error: Some(format!(
                    "KernLock daemon exited prematurely with status {}. Check {}",
                    exit,
                    log_path.display()
                )),
            };
            *state.status.lock().unwrap() = status.clone();
            return status;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = child.kill();
    let _ = child.wait();
    let status = DaemonStatus {
        running: false,
        managed_by_desktop: false,
        error: Some(format!(
            "Timed out waiting for KernLock daemon on 127.0.0.1:{}. Check {}",
            DAEMON_PORT,
            log_path.display()
        )),
    };
    *state.status.lock().unwrap() = status.clone();
    status
}

fn shutdown_daemon(state: &DaemonState) {
    if let Some(mut child) = state.child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[tauri::command]
fn get_api_token() -> Result<String, String> {
    if let Ok(env_token) = std::env::var("KERNLOCK_API_TOKEN") {
        let trimmed = env_token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let token_path = auth_token_path(default_data_dir());
    read_validated_token_file(&token_path)
        .map_err(|e| format!("Failed to load API token from {}: {}", token_path.display(), e))
}

#[tauri::command]
fn get_daemon_status(state: tauri::State<'_, DaemonState>) -> DaemonStatus {
    let mut current = state.status.lock().unwrap().clone();
    current.running = probe_daemon_health(DAEMON_PORT);
    current
}

#[tauri::command]
fn restart_daemon(state: tauri::State<'_, DaemonState>) -> DaemonStatus {
    ensure_daemon_running(&state)
}

fn main() {
    let app = tauri::Builder::default()
        .manage(DaemonState::default())
        .setup(|app| {
            let state = app.state::<DaemonState>();
            ensure_daemon_running(&state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_api_token,
            get_daemon_status,
            restart_daemon
        ])
        .build(tauri::generate_context!())
        .expect("error while building KernLock desktop application");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            let state = app_handle.state::<DaemonState>();
            shutdown_daemon(&state);
        }
    });
}

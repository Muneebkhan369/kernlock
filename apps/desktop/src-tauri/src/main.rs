#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kernlock_core::paths::{
    auth_token_path, default_data_dir, probe_authenticated_daemon, read_validated_token_file,
    validate_env_token, DaemonProbeResult,
};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

const DAEMON_PORT: u16 = 17420;

#[derive(Debug, Clone, Serialize)]
struct DaemonStatus {
    running: bool,
    managed_by_desktop: bool,
    error: Option<String>,
}

enum ManagedChild {
    Sidecar(CommandChild),
    Process(Child),
}

impl ManagedChild {
    fn kill(&mut self) {
        match self {
            ManagedChild::Sidecar(c) => {
                let _ = c.kill();
            }
            ManagedChild::Process(c) => {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

struct DaemonState {
    child: Mutex<Option<ManagedChild>>,
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

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Fallback helper to locate sidecar next to current_exe() if direct sidecar lookup needs fallback.
fn locate_bundled_daemon() -> Result<PathBuf, String> {
    let bin_name = daemon_binary_name();
    let exe = std::env::current_exe()
        .map_err(|e| format!("Failed to resolve current executable path: {e}"))?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| "Desktop executable has no parent directory".to_string())?;

    // 1. Sibling binary (production installed layout)
    let sibling = exe_dir.join(bin_name);
    if sibling.exists() {
        if is_executable_file(&sibling) {
            return Ok(sibling);
        }
        return Err(format!(
            "Bundled KernLock daemon at {} is not executable",
            sibling.display()
        ));
    }

    // 2. binaries/kernlock-* in app bundle / dev layout
    let binaries_dir = exe_dir.join("binaries");
    if let Ok(entries) = fs::read_dir(&binaries_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("kernlock-"))
                && is_executable_file(&p)
            {
                return Ok(p);
            }
        }
    }

    Err(format!(
        "Bundled KernLock daemon binary ({}) not found next to {}",
        bin_name,
        exe.display()
    ))
}

fn load_configured_token() -> Result<Option<String>, String> {
    if let Ok(env_token) = std::env::var("KERNLOCK_API_TOKEN") {
        match validate_env_token(&env_token) {
            Ok(Some(valid)) => return Ok(Some(valid)),
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let token_path = auth_token_path(default_data_dir());
    if fs::symlink_metadata(&token_path).is_ok() {
        let tok = read_validated_token_file(&token_path).map_err(|e| e.to_string())?;
        return Ok(Some(tok));
    }
    Ok(None)
}

fn set_status(state: &DaemonState, status: DaemonStatus) -> DaemonStatus {
    *state.status.lock().unwrap() = status.clone();
    status
}

fn ensure_daemon_running(app: &tauri::AppHandle, state: &DaemonState) -> DaemonStatus {
    let existing_token = match load_configured_token() {
        Ok(tok) => tok,
        Err(e) => {
            return set_status(
                state,
                DaemonStatus {
                    running: false,
                    managed_by_desktop: false,
                    error: Some(format!("Invalid local API token configuration: {e}")),
                },
            );
        }
    };

    // 1. Verify port 17420 with an authenticated /api/status probe (never trust /api/health alone).
    match probe_authenticated_daemon(DAEMON_PORT, existing_token.as_deref()) {
        DaemonProbeResult::AuthenticatedKernLock => {
            return set_status(
                state,
                DaemonStatus {
                    running: true,
                    managed_by_desktop: false,
                    error: None,
                },
            );
        }
        DaemonProbeResult::OccupiedByOtherService { detail } => {
            return set_status(
                state,
                DaemonStatus {
                    running: false,
                    managed_by_desktop: false,
                    error: Some(format!(
                        "Port {DAEMON_PORT} is already in use and did not pass KernLock authentication: {detail}"
                    )),
                },
            );
        }
        DaemonProbeResult::NotListening => {}
    }

    // 2. Clean up any previously tracked exited child.
    {
        let mut guard = state.child.lock().unwrap();
        if let Some(mut existing) = guard.take() {
            existing.kill();
        }
    }

    let data_dir = default_data_dir();
    if let Err(e) = fs::create_dir_all(&data_dir) {
        return set_status(
            state,
            DaemonStatus {
                running: false,
                managed_by_desktop: false,
                error: Some(format!(
                    "Failed to create KernLock data directory {}: {}",
                    data_dir.display(),
                    e
                )),
            },
        );
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

    // 3. Spawn daemon: try official Tauri 2 Shell sidecar first, then fallback to locate_bundled_daemon
    let sidecar_result = app
        .shell()
        .sidecar("kernlock")
        .and_then(|cmd| {
            cmd.args([
                "--data-dir",
                data_dir.to_str().unwrap_or("."),
                "serve",
                "--port",
                &DAEMON_PORT.to_string(),
            ])
            .spawn()
        });

    let child = match sidecar_result {
        Ok((_rx, sidecar_child)) => ManagedChild::Sidecar(sidecar_child),
        Err(sidecar_err) => match locate_bundled_daemon() {
            Ok(bin_path) => {
                let mut cmd = Command::new(&bin_path);
                cmd.arg("--data-dir")
                    .arg(&data_dir)
                    .arg("serve")
                    .arg("--port")
                    .arg(DAEMON_PORT.to_string())
                    .stdout(stdout_cfg)
                    .stderr(stderr_cfg);
                match cmd.spawn() {
                    Ok(process_child) => ManagedChild::Process(process_child),
                    Err(proc_err) => {
                        return set_status(
                            state,
                            DaemonStatus {
                                running: false,
                                managed_by_desktop: false,
                                error: Some(format!(
                                    "Failed to start sidecar ({sidecar_err}) and process fallback ({}): {proc_err}",
                                    bin_path.display()
                                )),
                            },
                        );
                    }
                }
            }
            Err(loc_err) => {
                return set_status(
                    state,
                    DaemonStatus {
                        running: false,
                        managed_by_desktop: false,
                        error: Some(format!(
                            "Failed to start Tauri sidecar ({sidecar_err}); fallback lookup failed: {loc_err}"
                        )),
                    },
                );
            }
        },
    };

    // 4. Wait up to 5 seconds for authenticated readiness.
    for _ in 0..25 {
        if let Ok(Some(tok)) = load_configured_token() {
            if probe_authenticated_daemon(DAEMON_PORT, Some(&tok))
                == DaemonProbeResult::AuthenticatedKernLock
            {
                *state.child.lock().unwrap() = Some(child);
                return set_status(
                    state,
                    DaemonStatus {
                        running: true,
                        managed_by_desktop: true,
                        error: None,
                    },
                );
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let mut doomed = child;
    doomed.kill();
    set_status(
        state,
        DaemonStatus {
            running: false,
            managed_by_desktop: false,
            error: Some(format!(
                "Timed out waiting for authenticated KernLock daemon on 127.0.0.1:{DAEMON_PORT}. Check {}",
                log_path.display()
            )),
        },
    )
}

fn shutdown_daemon(state: &DaemonState) {
    if let Some(mut child) = state.child.lock().unwrap().take() {
        child.kill();
    }
}

#[tauri::command]
fn get_api_token() -> Result<String, String> {
    match load_configured_token()? {
        Some(tok) => Ok(tok),
        None => Err(format!(
            "API token not found at {}",
            auth_token_path(default_data_dir()).display()
        )),
    }
}

#[tauri::command]
fn get_daemon_status(state: tauri::State<'_, DaemonState>) -> DaemonStatus {
    let mut current = state.status.lock().unwrap().clone();
    let token = load_configured_token().ok().flatten();
    current.running =
        probe_authenticated_daemon(DAEMON_PORT, token.as_deref()) == DaemonProbeResult::AuthenticatedKernLock;
    current
}

#[tauri::command]
fn restart_daemon(app: tauri::AppHandle, state: tauri::State<'_, DaemonState>) -> DaemonStatus {
    shutdown_daemon(&state);
    ensure_daemon_running(&app, &state)
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(DaemonState::default())
        .setup(|app| {
            let app_handle = app.handle().clone();
            let state = app.state::<DaemonState>();
            ensure_daemon_running(&app_handle, &state);
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

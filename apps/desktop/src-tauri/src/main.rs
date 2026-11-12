#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

#[tauri::command]
fn get_api_token() -> Result<String, String> {
    let base = if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("kernlock")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/kernlock")
    } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(appdata).join("kernlock")
    } else {
        PathBuf::from(".kernlock")
    };
    let token_path = base.join("auth.token");
    std::fs::read_to_string(&token_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read {}: {}", token_path.display(), e))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_api_token])
        .run(tauri::generate_context!())
        .expect("error while running KernLock desktop application");
}

use anyhow::Result;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn load_or_create_token<P: AsRef<Path>>(data_dir: P) -> Result<String> {
    if let Ok(env_token) = std::env::var("KERNLOCK_API_TOKEN") {
        let trimmed = env_token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let token_path = data_dir.as_ref().join("auth.token");
    if token_path.exists() {
        let existing = fs::read_to_string(&token_path)?.trim().to_string();
        if existing.len() >= 32 {
            return Ok(existing);
        }
    }

    fs::create_dir_all(data_dir.as_ref())?;
    let token = generate_token();
    fs::write(&token_path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(token)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn is_valid_loopback_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h == "127.0.0.1" || h == "localhost" || h == "[::1]" {
        return true;
    }
    if let Some(port) = h.strip_prefix("127.0.0.1:") {
        return !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    }
    if let Some(port) = h.strip_prefix("localhost:") {
        return !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    }
    if let Some(port) = h.strip_prefix("[::1]:") {
        return !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    }
    false
}

pub fn is_allowed_origin(origin: &str) -> bool {
    let o = origin.trim().to_ascii_lowercase();
    if o == "tauri://localhost" || o == "http://tauri.localhost" || o == "https://tauri.localhost" {
        return true;
    }
    if let Some(rest) = o.strip_prefix("http://") {
        return is_valid_loopback_host(rest);
    }
    false
}

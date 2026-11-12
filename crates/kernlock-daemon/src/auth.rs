use anyhow::Result;
use kernlock_core::paths::{auth_token_path, read_validated_token_file};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
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

    let dir = data_dir.as_ref();
    let token_path = auth_token_path(dir);

    if fs::symlink_metadata(&token_path).is_ok() {
        return Ok(read_validated_token_file(&token_path)?);
    }

    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }

    let token = generate_token();
    let tmp_path = dir.join(format!(".auth.token.tmp.{}", Uuid::new_v4()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let write_res = (|| -> std::io::Result<()> {
        let mut file = opts.open(&tmp_path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    match fs::hard_link(&tmp_path, &token_path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp_path);
            Ok(read_validated_token_file(&token_path)?)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp_path);
            Ok(read_validated_token_file(&token_path)?)
        }
        Err(e) => {
            // Fallback for filesystems where hard links are unsupported: rename if not already present.
            if fs::symlink_metadata(&token_path).is_ok() {
                let _ = fs::remove_file(&tmp_path);
                return Ok(read_validated_token_file(&token_path)?);
            }
            if let Err(rename_err) = fs::rename(&tmp_path, &token_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(anyhow::anyhow!(
                    "Failed to publish token file ({e}; rename fallback: {rename_err})"
                ));
            }
            Ok(read_validated_token_file(&token_path)?)
        }
    }
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

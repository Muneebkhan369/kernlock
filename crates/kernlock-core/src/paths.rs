use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Resolve the KernLock data directory for a specific OS and environment inputs.
///
/// - Linux/Unix: `$XDG_DATA_HOME/kernlock`, else `$HOME/.local/share/kernlock`
/// - Windows: `%LOCALAPPDATA%\kernlock`, else `%USERPROFILE%\AppData\Local\kernlock`
/// - macOS: `$HOME/Library/Application Support/kernlock`
pub fn resolve_data_dir_for_os(
    os: &str,
    xdg_data_home: Option<&str>,
    home: Option<&str>,
    local_app_data: Option<&str>,
    user_profile: Option<&str>,
) -> PathBuf {
    fn non_empty(opt: Option<&str>) -> Option<&str> {
        opt.map(str::trim).filter(|s| !s.is_empty())
    }

    match os {
        "windows" => {
            if let Some(appdata) = non_empty(local_app_data) {
                return PathBuf::from(appdata).join("kernlock");
            }
            if let Some(profile) = non_empty(user_profile).or_else(|| non_empty(home)) {
                return PathBuf::from(profile)
                    .join("AppData")
                    .join("Local")
                    .join("kernlock");
            }
            PathBuf::from(".kernlock")
        }
        "macos" => {
            if let Some(h) = non_empty(home) {
                return PathBuf::from(h)
                    .join("Library")
                    .join("Application Support")
                    .join("kernlock");
            }
            PathBuf::from(".kernlock")
        }
        _ => {
            if let Some(xdg) = non_empty(xdg_data_home) {
                return PathBuf::from(xdg).join("kernlock");
            }
            if let Some(h) = non_empty(home) {
                return PathBuf::from(h)
                    .join(".local")
                    .join("share")
                    .join("kernlock");
            }
            PathBuf::from(".kernlock")
        }
    }
}

/// Resolve the default KernLock data directory for the current host OS.
pub fn default_data_dir() -> PathBuf {
    let xdg = std::env::var("XDG_DATA_HOME").ok();
    let home = std::env::var("HOME").ok();
    let local_app_data = std::env::var("LOCALAPPDATA").ok();
    let user_profile = std::env::var("USERPROFILE").ok();
    resolve_data_dir_for_os(
        std::env::consts::OS,
        xdg.as_deref(),
        home.as_deref(),
        local_app_data.as_deref(),
        user_profile.as_deref(),
    )
}

/// Resolve the canonical `auth.token` path inside a data directory.
pub fn auth_token_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join("auth.token")
}

/// Validate and read an existing `auth.token` file.
///
/// Rejects symbolic links (`symlink_metadata` + `O_NOFOLLOW` on Unix) and
/// rejects token files on Unix whose permissions allow group or world access (`mode & 0o077 != 0`).
pub fn read_validated_token_file<P: AsRef<Path>>(token_path: P) -> io::Result<String> {
    let path = token_path.as_ref();
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing symlinked API token file: {}", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("API token path is not a regular file: {}", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Refusing API token file {} with overly permissive mode {:04o}; expected 0600",
                    path.display(),
                    mode
                ),
            ));
        }
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = opts.open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let trimmed = contents.trim().to_string();
    if trimmed.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "API token file {} is empty or shorter than 32 characters",
                path.display()
            ),
        ));
    }
    Ok(trimmed)
}

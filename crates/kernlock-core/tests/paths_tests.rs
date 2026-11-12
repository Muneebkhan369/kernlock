use kernlock_core::paths::{
    auth_token_path, read_validated_token_file, resolve_data_dir_for_os, validate_env_token,
};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn resolves_platform_data_dirs_consistently() {
    let linux_xdg = resolve_data_dir_for_os(
        "linux",
        Some("/custom/xdg"),
        Some("/home/alice"),
        None,
        None,
    );
    assert_eq!(linux_xdg, PathBuf::from("/custom/xdg/kernlock"));

    let linux_default = resolve_data_dir_for_os("linux", Some(""), Some("/home/alice"), None, None);
    assert_eq!(
        linux_default,
        PathBuf::from("/home/alice/.local/share/kernlock")
    );

    let windows_local = resolve_data_dir_for_os(
        "windows",
        None,
        None,
        Some(r"C:\Users\alice\AppData\Local"),
        None,
    );
    assert_eq!(
        windows_local,
        PathBuf::from(r"C:\Users\alice\AppData\Local").join("kernlock")
    );

    let macos_support = resolve_data_dir_for_os("macos", None, Some("/Users/alice"), None, None);
    assert_eq!(
        macos_support,
        PathBuf::from("/Users/alice/Library/Application Support/kernlock")
    );

    assert_eq!(
        auth_token_path(&linux_default),
        PathBuf::from("/home/alice/.local/share/kernlock/auth.token")
    );
}

#[test]
fn validates_custom_env_token_length() {
    assert_eq!(validate_env_token("   ").unwrap(), None);
    assert!(validate_env_token("short-token").is_err());
    let valid = "0123456789abcdef0123456789abcdef";
    assert_eq!(validate_env_token(valid).unwrap().as_deref(), Some(valid));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_and_permissive_token_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempdir().unwrap();
    let real_token = dir.path().join("real.token");
    fs::write(&real_token, "0123456789abcdef0123456789abcdef").unwrap();
    fs::set_permissions(&real_token, fs::Permissions::from_mode(0o600)).unwrap();

    // Symlink must be rejected
    let link_path = dir.path().join("auth.token");
    symlink(&real_token, &link_path).unwrap();
    let sym_err = read_validated_token_file(&link_path).unwrap_err();
    assert!(
        sym_err.to_string().contains("symlink"),
        "expected symlink error, got {sym_err}"
    );
    fs::remove_file(&link_path).unwrap();

    // Overly permissive regular file (0644) must be rejected
    let perm_path = dir.path().join("auth.token");
    fs::write(&perm_path, "0123456789abcdef0123456789abcdef").unwrap();
    fs::set_permissions(&perm_path, fs::Permissions::from_mode(0o644)).unwrap();
    let perm_err = read_validated_token_file(&perm_path).unwrap_err();
    assert!(
        perm_err.to_string().contains("0644"),
        "expected permission error, got {perm_err}"
    );

    // Restrictive 0600 regular file must succeed
    fs::set_permissions(&perm_path, fs::Permissions::from_mode(0o600)).unwrap();
    let token = read_validated_token_file(&perm_path).unwrap();
    assert_eq!(token, "0123456789abcdef0123456789abcdef");
}

# KernLock Security Roadmap

## Phase 1 — Core Engine, Linux Audit/Quarantine & Console (Completed)
- [x] Rust workspace (`kernlock-core`, `kernlock-storage`, `kernlock-quarantine`, `kernlock-platform`, `kernlock-daemon`)
- [x] SQLite storage for events, alerts, quarantine records, and policies
- [x] Structured YAML detection rules (command, file content, file path, process, persistence)
- [x] Linux `/proc` process monitor, persistence scanner, and `inotify` real-time file watcher
- [x] Reversible quarantine vault with SHA-256 integrity checks & permission restoration
- [x] React + TypeScript security console + Tauri 2 desktop configuration
- [x] Unit & integration tests with harmless fixtures

## Phase 1.1 — Security Hardening & Reliability (Completed)
- [x] Loopback-only Axum API with `Host`/`Origin` validation and per-installation `0600` Bearer token authentication
- [x] Honest Linux `fanotify_init` syscall probing and separation of post-write auto-quarantine vs unavailable kernel pre-execution blocking
- [x] Failure-safe quarantine and restore with `O_NOFOLLOW`/symlink rejection, vault-path rejection, and automatic rollback on permission/DB failures
- [x] Honest `PlatformError::Unsupported` (`501 Not Implemented`) reporting for unimplemented Windows & macOS process/persistence subsystems
- [x] Official Tauri 2 CLI (`@tauri-apps/cli`, `@tauri-apps/api`) integration with `get_api_token` IPC and `.github/workflows/ci.yml`

## Phase 1.2 — Critical Reliability Fixes (Completed)
- [x] `RollbackFailed(Box<RollbackFailureInfo>)` error type in `kernlock-quarantine` with zero ignored `let _ =` rollback paths and full stranded-file recovery metadata
- [x] Atomic no-clobber file moves (`RENAME_NOREPLACE` on Linux, `RENAME_EXCL` on macOS, `hard_link` fallback) and staged cross-filesystem copy cleanup
- [x] Unified cross-platform data-directory & `auth.token` resolution in `kernlock-core::paths` (`XDG_DATA_HOME`, `LOCALAPPDATA`, `Application Support`), atomic `0600` creation, and symlink/permission validation
- [x] Tauri 2 daemon lifecycle management (health probe, duplicate-instance reuse, startup error reporting, clean shutdown) with zero URL token exposure

## Phase 2 — Privileged Linux Enforcement & YARA/Sigma Parity
- [ ] Privileged `fanotify` (`FAN_OPEN_PERM`) helper daemon with PolicyKit/sudo privilege separation
- [ ] Optional `libyara` / `yara-x` integration for native `.yar` rule files
- [ ] Sigma YAML converter for importing community Sigma rules
- [ ] eBPF `execve` / `connect` telemetry collector (CO-RE via `aya`)

## Phase 3 — Windows & macOS Native Providers
- [ ] Windows: Win32 process enumeration, Registry Run/Scheduled Tasks scanner, ETW & AMSI integration
- [ ] macOS: `LaunchAgents`/`LaunchDaemons` plist scanner, process inspection, and Endpoint Security (`es_new_client`) integration for signed builds
- [ ] Cross-platform installer packages (`.deb`, `.rpm`, `.msi`, `.dmg`)

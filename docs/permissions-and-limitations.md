# Permissions, Platform Mechanisms & Known Limitations

KernLock intentionally avoids undocumented OS hacks or unstable kernel modules. Below is the exact status of native security mechanisms per operating system.

## Linux (Primary Validated Target)

- **Validated Capabilities**:
  - `/proc` process inspection (PID, PPID, UID, command line, executable path, deleted-executable detection).
  - Real-time directory monitoring via `inotify` (`notify` crate).
  - Static file & script scanning, Shannon entropy analysis, and command risk analysis.
  - Persistence inspection (`~/.config/systemd/user/`, `~/.config/autostart/`, `/etc/crontab`, `/etc/cron.d/`, `/etc/ld.so.preload`, shell profiles).
  - Post-write automatic quarantine (`auto_quarantine_available = true`) for user-owned files in `Protection` / `Strict` modes.
- **Privileged / Kernel Enforcement (Current Limitation)**:
  - `LinuxSecurityProvider::probe_capabilities` probes `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY)` rather than assuming root (`uid == 0`) implies `fanotify` support.
  - **Pre-execution kernel blocking (`kernel_blocking_available`) is currently `false` (unavailable)** even as root, because the asynchronous `FAN_OPEN_PERM` decision loop is not yet implemented (scheduled for Phase 2).
  - `Protection` and `Strict` modes therefore perform post-write detection and automatic quarantine on watched paths, **not** kernel-level pre-execution blocking.

## Windows (Architectural Module — Unsupported Subsystems Return `Unsupported`)

- **Planned Native Integrations**:
  - Antimalware Scan Interface (AMSI) for PowerShell/script inspection.
  - ETW (Event Tracing for Windows) process & image-load telemetry.
  - WDAC / AppLocker policy status & Registry `Run`/`RunOnce` + Scheduled Task persistence scanning.
- **Current Limitation**: `WindowsSecurityProvider` returns `PlatformError::Unsupported` (mapped to HTTP `501 Not Implemented`) for `list_processes` and `scan_persistence` rather than returning empty lists, and reports `Audit` mode with `kernel_blocking_available = false` and `auto_quarantine_available = false`. Security reports display `N/A (Unsupported)` for those counts.

## macOS (Architectural Module — Unsupported Subsystems Return `Unsupported`)

- **Planned Native Integrations**:
  - Apple Endpoint Security Framework (`ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`).
  - `LaunchAgents` / `LaunchDaemons` plist persistence inspection.
- **Current Limitation**: Apple Endpoint Security requires a Developer ID signed binary with the `com.apple.developer.endpoint-security.client` entitlement and user-granted Full Disk Access (FDA). `MacOsSecurityProvider` returns `PlatformError::Unsupported` (HTTP `501 Not Implemented`) for `list_processes` and `scan_persistence` and reports `Audit` mode with `kernel_blocking_available = false` and `auto_quarantine_available = false`.

## Local API Security

- `kernlockd` binds strictly to `127.0.0.1` and requires a Bearer token (`<data_dir>/auth.token`, mode `0600`) for all `/api/*` routes except `/api/health`.
- Requests with non-loopback `Host` headers or disallowed `Origin` headers are rejected with `403 Forbidden`.

## Desktop Packaging & Sidecar Build Limitations

- **Linux Native Packaging Prerequisites**: Compiling the native Tauri desktop frontend into `.deb` or `AppImage` packages requires system development libraries: `libgtk-3-dev` (providing `gdk-3.0`), `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, and `librsvg2-dev`. On headless servers or environments lacking these libraries, `gdk-sys` build scripts fail.
- **Standalone Daemon & Web UI**: The KernLock security core, daemon, CLI, and static web dashboard (`kernlock serve --ui-dir apps/desktop/dist`) do NOT require GTK or WebKit and run on any standard Linux distribution.
- **Sidecar Target Triples**: The sidecar builder (`prepare-sidecar.mjs`) validates ELF, PE, and Mach-O headers and verifies target machine architectures (`x86_64`, `aarch64`) before placing sidecars into `src-tauri/binaries/`, refusing to mislabel binaries.

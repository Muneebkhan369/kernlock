# Permissions, Platform Mechanisms & Known Limitations

KernLock intentionally avoids undocumented OS hacks or unstable kernel modules. Below is the exact status of native security mechanisms per operating system.

## Linux (Primary Validated Target)

- **Unprivileged Mode (Works out of the box)**:
  - `/proc` process inspection (PID, PPID, UID, command line, executable path, deleted-executable detection).
  - Real-time directory monitoring via `inotify` (`notify` crate).
  - Static file & script scanning, Shannon entropy analysis, and command risk analysis.
  - Persistence inspection (`~/.config/systemd/user/`, `~/.config/autostart/`, `/etc/crontab`, `/etc/cron.d/`, `/etc/ld.so.preload`, shell profiles).
  - Reversible quarantine for user-owned files.
- **Privileged / Kernel Enforcement (Requires `root` / `CAP_SYS_ADMIN` / `CAP_BPF`)**:
  - `fanotify` (`FAN_OPEN_PERM`) pre-execution/open blocking requires `CAP_SYS_ADMIN`. Without it, KernLock safely falls back to **Audit** mode.
  - eBPF/LSM probes and `auditd` rule management require root/capabilities and are probed via `/sys/fs/bpf` and `/sys/kernel/security/lsm`.

## Windows (Architectural Module — Pending Host Validation)

- **Planned Native Integrations**:
  - Antimalware Scan Interface (AMSI) for PowerShell/script inspection.
  - ETW (Event Tracing for Windows) process & image-load telemetry.
  - WDAC / AppLocker policy status & Registry `Run`/`RunOnce` + Scheduled Task persistence scanning.
- **Current Limitation**: Windows host-specific API bindings (Win32/ETW/AMSI) are stubbed behind `WindowsSecurityProvider` and honestly report `Audit` mode until implemented and tested on Windows.

## macOS (Architectural Module — Pending Entitlement & Host Validation)

- **Planned Native Integrations**:
  - Apple Endpoint Security Framework (`ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`).
  - `LaunchAgents` / `LaunchDaemons` plist persistence inspection.
- **Current Limitation**: Apple Endpoint Security requires a Developer ID signed binary with the `com.apple.developer.endpoint-security.client` entitlement and user-granted Full Disk Access (FDA). Without these, `MacOsSecurityProvider` reports `Audit` mode.

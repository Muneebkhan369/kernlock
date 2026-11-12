# KernLock Security Roadmap

## Phase 1 — Core Engine, Linux Audit/Quarantine & Console (Completed)
- [x] Rust workspace (`kernlock-core`, `kernlock-storage`, `kernlock-quarantine`, `kernlock-platform`, `kernlock-daemon`)
- [x] SQLite storage for events, alerts, quarantine records, and policies
- [x] Structured YAML detection rules (command, file content, file path, process, persistence)
- [x] Linux `/proc` process monitor, persistence scanner, and `inotify` real-time file watcher
- [x] Reversible quarantine vault with SHA-256 integrity checks & permission restoration
- [x] React + TypeScript security console + Tauri 2 desktop configuration
- [x] Unit & integration tests with harmless fixtures

## Phase 2 — Privileged Linux Enforcement & YARA/Sigma Parity
- [ ] Privileged `fanotify` (`FAN_OPEN_PERM`) helper daemon with PolicyKit/sudo privilege separation
- [ ] Optional `libyara` / `yara-x` integration for native `.yar` rule files
- [ ] Sigma YAML converter for importing community Sigma rules
- [ ] eBPF `execve` / `connect` telemetry collector (CO-RE via `aya`)

## Phase 3 — Windows & macOS Native Providers
- [ ] Windows: Win32 process enumeration, Registry Run/Scheduled Tasks scanner, ETW & AMSI integration
- [ ] macOS: `LaunchAgents`/`LaunchDaemons` plist scanner, process inspection, and Endpoint Security (`es_new_client`) integration for signed builds
- [ ] Cross-platform installer packages (`.deb`, `.rpm`, `.msi`, `.dmg`)

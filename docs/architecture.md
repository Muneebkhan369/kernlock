# KernLock Security Architecture

**Tagline:** Detect. Block. Explain.

KernLock is designed as a modular, cross-platform endpoint protection system built in Rust with a React/TypeScript desktop console (packaged via Tauri 2 or served locally by `kernlockd`).

## Workspace Structure

```text
kernlock/
├── crates/
│   ├── kernlock-core/        # Domain models, YAML rule engine, static file & command analyzers
│   ├── kernlock-storage/     # SQLite persistence (events, alerts, quarantine metadata, policies)
│   ├── kernlock-quarantine/  # Reversible quarantine vault with 0600 permissions & SHA-256 checks
│   ├── kernlock-platform/    # OS abstraction trait + Linux, Windows, macOS providers
│   └── kernlock-daemon/      # CLI (`kernlock`), real-time watcher, and localhost HTTP API (`kernlockd`)
├── apps/
│   └── desktop/              # React + TypeScript UI + Tauri 2 (`src-tauri/`)
├── rules/
│   └── builtin_rules.yaml    # Structured detection rules (command, file, process, persistence)
└── docs/                     # Architecture, permissions/limitations, and roadmap
```

## Core Design Principles

1. **Never Execute Untrusted Inputs**: File, script, and command analysis are strictly static (hashing, Shannon entropy, magic bytes, regex/Sigma-compatible rule evaluation).
2. **Honest Capability Reporting**: Each OS provider implements `probe_capabilities(requested_mode)`. If kernel/privileged enforcement (e.g., Linux `fanotify` with `CAP_SYS_ADMIN`, Windows WDAC/AMSI, macOS Endpoint Security entitlement) is unavailable, KernLock automatically falls back to `Audit` mode and surfaces the exact reason to the user.
3. **Reversible Quarantine**: Files moved to the quarantine vault have execute bits stripped (`0600` on Unix) and are indexed in SQLite with their original path, permissions, and SHA-256 digest so they can be cleanly restored or explicitly deleted.
4. **Explainable Decisions**: Every rule match produces a rule ID, severity, risk score (`0-100`), matched evidence snippet, human-readable explanation, and remediation guidance.

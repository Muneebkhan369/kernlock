# KernLock Security Architecture

**Tagline:** Detect. Block. Explain.

KernLock is designed as a modular, cross-platform endpoint protection system built in Rust with a React/TypeScript desktop console (packaged via Tauri 2 or served locally by `kernlockd`).

## Workspace Structure

```text
kernlock/
├── crates/
│   ├── kernlock-core/        # Domain models, YAML rule engine, static file & command analyzers
│   ├── kernlock-storage/     # SQLite persistence (events, alerts, quarantine metadata, policies)
│   ├── kernlock-quarantine/  # Failure-safe reversible quarantine vault (O_NOFOLLOW, 0600, rollback)
│   ├── kernlock-platform/    # OS abstraction trait + Linux, Windows, macOS providers
│   └── kernlock-daemon/      # CLI (`kernlock`), watcher, and authenticated loopback HTTP API
├── apps/
│   └── desktop/              # React + TypeScript UI + Tauri 2 (`src-tauri/`)
├── rules/
│   └── builtin_rules.yaml    # Structured detection rules (command, file, process, persistence)
├── .github/workflows/ci.yml  # Cross-platform CI (Ubuntu, Windows, macOS)
└── docs/                     # Architecture, permissions/limitations, and roadmap
```

## Core Design Principles

1. **Never Execute Untrusted Inputs**: File, script, and command analysis are strictly static (hashing, Shannon entropy, magic bytes, regex/Sigma-compatible rule evaluation).
2. **Authenticated Loopback API**: `kernlockd` binds strictly to `127.0.0.1`. Middleware validates `Host` (loopback only), `Origin` (same-origin loopback / `tauri://localhost` / `http://tauri.localhost` only — no wildcard CORS), and constant-time `Authorization: Bearer <token>` on all `/api/*` endpoints except `/api/health`. The per-installation token is stored with `0600` permissions at `<data_dir>/auth.token` and retrieved in Tauri via the `get_api_token` command.
3. **Honest Capability Reporting**: `PlatformCapabilities` explicitly separates `kernel_blocking_available` (pre-execution kernel blocking) from `auto_quarantine_available` (post-write user-space quarantine). Root access alone never claims `fanotify` enforcement; `fanotify_init` is probed directly, and unimplemented Windows/macOS subsystems return `PlatformError::Unsupported` (`501 Not Implemented`) rather than empty clean results.
4. **Failure-Safe Reversible Quarantine**: Before moving a file, the vault rejects symlinks (including `O_NOFOLLOW` verification on Unix) and paths inside the vault. If stripping permissions (`0600`) or writing the SQLite record fails, the file is rolled back to its original path and permissions. Restore operations similarly roll back if permission restoration or database updates fail.
5. **Explainable Decisions**: Every rule match produces a rule ID, severity, risk score (`0-100`), matched evidence snippet, human-readable explanation, and remediation guidance.

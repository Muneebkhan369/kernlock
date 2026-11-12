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
2. **Authenticated Loopback API & Unified Token Storage**: `kernlockd` binds strictly to `127.0.0.1`. Middleware validates `Host` (loopback only), `Origin` (same-origin loopback / `tauri://localhost` / `http://tauri.localhost` only — no wildcard CORS), and constant-time `Authorization: Bearer <token>` on all `/api/*` endpoints except `/api/health`. Both `kernlockd` and `src-tauri` resolve `<data_dir>/auth.token` via `kernlock_core::paths` (`XDG_DATA_HOME` / `~/.local/share/kernlock` on Linux, `%LOCALAPPDATA%\kernlock` on Windows, `~/Library/Application Support/kernlock` on macOS), create it atomically with `0600` permissions, reject symlinked or overly permissive token files, and never expose the token in URLs or logs.
3. **Honest Capability Reporting**: `PlatformCapabilities` explicitly separates `kernel_blocking_available` (pre-execution kernel blocking) from `auto_quarantine_available` (post-write user-space quarantine). Root access alone never claims `fanotify` enforcement; `fanotify_init` is probed directly, and unimplemented Windows/macOS subsystems return `PlatformError::Unsupported` (`501 Not Implemented`) rather than empty clean results.
4. **Failure-Safe, No-Clobber Reversible Quarantine**: Before moving a file, the vault rejects symlinks (including `O_NOFOLLOW` verification on Unix) and paths inside the vault. Moves use atomic no-clobber primitives (`renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS, `hard_link` + unlink fallback, and staged cross-filesystem copy with temp-file cleanup) so existing user files are never overwritten even under TOCTOU races. Rollback failures are never ignored: `RollbackFailed` surfaces both the original error and rollback error with stranded-file recovery metadata.
5. **Explainable Decisions**: Every rule match produces a rule ID, severity, risk score (`0-100`), matched evidence snippet, human-readable explanation, and remediation guidance.

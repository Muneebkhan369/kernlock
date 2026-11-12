# KernLock Security - Platform Integration & Capabilities Matrix

This document provides a comprehensive technical overview of the real platform integrations implemented in KernLock Security across Linux, Windows, and macOS.

---

## 1. Operating System Integration Matrix

| Platform | Subsystem / Mechanism | Kernel / Driver Interface | User-Mode Interception | Execution Blocking Capability | Status & Honest Reporting |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Linux** | `fanotify` (FAN_CLASS_CONTENT) | `FAN_OPEN_PERM` & `FAN_OPEN_EXEC_PERM` | `crates/kernlock-platform/src/fanotify.rs` | Supported (`FAN_OPEN_EXEC_PERM`) | **Active** when monitor running; **Standby** when probed but stopped; **Degraded** on overflow; **Unavailable** on non-root / unprivileged kernels. |
| **Windows** | Filter Manager (`FLTMGR`) Minifilter | `IRP_MJ_CREATE` (`FILE_EXECUTE`) & `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` (`SyncTypeCreateSection`) | `crates/kernlock-platform/src/windows.rs` | Supported via `kernlock_filter.sys` (Altitude `325000`) | **Active** when driver connected; **Audit Fallback** when driver not installed or WHQL unsigned. |
| **macOS** | Endpoint Security Framework (`ESF`) | `ES_EVENT_TYPE_AUTH_EXEC` & `ES_EVENT_TYPE_AUTH_OPEN` | `/var/run/kernlock/kernlock.sock` (0600 permissions) | Supported via System Extension (`main.c`) | **Active** when System Extension and socket connected; **Unavailable** when not installed / not entitled. |

---

## 2. Linux Fanotify Architecture & Recovery Policy

### Kernel Permission Event Loop
- Initialized via `libc::fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE | O_CLOEXEC)`.
- Mounts monitored: marks `/` (`FAN_MARK_MOUNT`) with `FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM`.
- Mount discovery reports actively monitored filesystems vs unmonitored pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`).

### Permission-Response Write Recovery Policy
- In Linux fanotify, failing to reply to a permission event causes the calling process to hang in an uninterruptible sleep (`D` state).
- KernLock implements a bounded exponential backoff retry loop (`send_response_with_retry`):
  - Retries on `EAGAIN` (buffer full) up to 5 times.
  - Automatically retries on `EINTR` (interrupted by signal).
  - If a fatal error occurs, immediately logs the error, transitions `FanotifyMonitorHealth` to `Failed`, closes the event file descriptor, and halts the loop cleanly to prevent subsequent hangs.

### Event Queue Overflow Handling
- When `metadata.mask & FAN_Q_OVERFLOW` occurs, KernLock:
  - Transitions health state to `FanotifyMonitorHealth::Degraded`.
  - Advances buffer offset safely by `metadata.event_len` without discarding subsequent valid events in the buffer.

### TOCTOU Race Safety
- The engine evaluates target binaries directly from the opened `event_fd` using `scan_file_from_fd` and `scan_stream_reader`.
- Even if an attacker unlinks or replaces the file at its path prior to analysis, the kernel file object held by `event_fd` is inspected directly.

---

## 3. Windows Minifilter Architecture & Bug Fixes

### Critical `STATUS_TIMEOUT` Fix
- In Windows NTSTATUS, `STATUS_TIMEOUT` is `0x00000102`.
- Because `NT_SUCCESS(status)` evaluates `status >= 0`, `NT_SUCCESS(STATUS_TIMEOUT)` evaluates to **TRUE**!
- In previous versions, timing out on `FltSendMessage` resulted in the driver evaluating uninitialized stack memory in `responseMsg.Verdict`.
- Fixed in `kernlock_filter.c`:
  - Explicitly asserts `status == STATUS_SUCCESS`.
  - Validates `replyLength >= sizeof(EXECUTION_RESPONSE_MSG)`.
  - Validates `responseMsg.MessageId == requestMsg.Header.MessageId`.
  - Explicit timeout policy defaults to fail-open to prevent deadlocking system processes.

### Section Synchronization Interception
- Intercepts `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`.
- Inspects `Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection`.
- Inspects executable page protection flags (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`).
- Blocks execution mapping with `STATUS_ACCESS_DENIED`.

### Bounded-Memory Scanning
- User-mode `MinifilterClient` replaces unbounded `fs::read` with streaming 64KB chunked scanning via `scan_stream_reader`.
- Reconnect loop automatically restores connection if Filter Manager port drops.

---

## 4. macOS Endpoint Security Architecture

### System Extension & Unix Domain Socket
- Endpoint Security System Extension runs as root and communicates with the KernLock daemon over `/var/run/kernlock/kernlock.sock`.
- Socket permissions enforced as `0600` (read/write by owner only).
- Insecure `/tmp` fallback removed.

### Authorization Protocol (`eval_es`)
- System Extension sends JSON request:
  ```json
  {"action":"eval_es","path":"/Applications/Target.app/Contents/MacOS/binary","pid":1234,"ppid":1,"is_exec":true}
  ```
- Daemon inspects file with `scan_stream_reader` and responds:
  ```json
  {"verdict":"block"}
  ```
  or
  ```json
  {"verdict":"allow"}
  ```

### Deadline Monitoring
- Checks `is_deadline_imminent` using `mach_absolute_time()` and `mach_timebase_info()`.
- If less than 50ms remains before `message->deadline`, falls back immediately according to policy (fail-open in Protection mode, fail-closed in Strict mode) to prevent kernel watchdogs from terminating the extension.

---

## 5. Threat Intelligence Update & Verification Core

1. **Strict Key Pinning**: Pinned trusted public keys only (`OFFICIAL_PUBLIC_KEY_HEX` and dynamically added trusted keys). Self-supplied keys rejected.
2. **Anti-Rollback Protection**: Version semantic tuple and Unix timestamp must strictly advance beyond previous accepted state and deterministic baseline (`BUILTIN_BASELINE_VERSION = 2026.11.1`).
3. **Transactional Persistence**: Bundle saved to SQLite database before in-memory swap; restored on daemon startup.
4. **Offline Signing Utility**:
   - `kernlock generate-signing-key` (generates Ed25519 keypair via CSPRNG).
   - `kernlock sign-bundle` (signs threat bundle manifest).
5. **Streaming Multi-Pattern Matching**: Bounded-memory scanning across chunk boundaries with 64KB chunks and signature window overlap.

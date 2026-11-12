#!/usr/bin/env bash
set -euo pipefail

# KernLock Security - Privileged Fanotify Execution Blocking Acceptance Runner
# Must be executed in an environment with CAP_SYS_ADMIN / root (e.g. privileged container)

echo "==> Running Linux Privileged Fanotify Execution Blocking Acceptance Test..."
export KERNLOCK_REQUIRE_PRIVILEGED=1

# Ensure cargo is in PATH if cargo is not found
if ! command -v cargo &>/dev/null; then
    for candidate in "$HOME/.cargo/bin/cargo" "/root/.cargo/bin/cargo" "/home/runner/.cargo/bin/cargo"; do
        if [ -x "$candidate" ]; then
            export PATH="$(dirname "$candidate"):$PATH"
            break
        fi
    done
fi

cargo test -p kernlock-platform --test fanotify_tests test_privileged_linux_fanotify_execution_blocking -- --nocapture

echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."

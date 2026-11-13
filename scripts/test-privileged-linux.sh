#!/usr/bin/env bash
set -euo pipefail

# KernLock Security - Privileged Fanotify Execution Blocking Acceptance Runner
# Must be executed in an environment with CAP_SYS_ADMIN / root (e.g. privileged container or sudo)

echo "==> Building Linux Privileged Fanotify Test Binary..."
# Ensure cargo is in PATH if cargo is not found
if ! command -v cargo &>/dev/null; then
    for candidate in "$HOME/.cargo/bin/cargo" "/root/.cargo/bin/cargo" "/home/runner/.cargo/bin/cargo"; do
        if [ -x "$candidate" ]; then
            export PATH="$(dirname "$candidate"):$PATH"
            break
        fi
    done
fi

cargo test -p kernlock-platform --test fanotify_tests --no-run

echo "==> Locating compiled fanotify_tests test runner binary..."
TEST_BIN=$(ls -t target/debug/deps/fanotify_tests-* | grep -v '\.d$' | head -n 1)

echo "==> Running Linux Privileged Fanotify Execution Blocking Acceptance Test..."
if [ "$(id -u)" -eq 0 ]; then
    echo "==> Running with root (CAP_SYS_ADMIN)..."
    export KERNLOCK_REQUIRE_PRIVILEGED=1
    "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."
elif sudo -n true 2>/dev/null; then
    echo "==> Running with passwordless sudo (CAP_SYS_ADMIN)..."
    sudo env KERNLOCK_REQUIRE_PRIVILEGED=1 "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."
else
    echo "==> Notice: Running unprivileged on local workstation (non-root without passwordless sudo)."
    echo "==> Executing test runner in diagnostic mode to verify clean error reporting without panic..."
    "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Diagnostic state verified cleanly (unprivileged capability skip verified without panic or exit 101)."
    echo "==> To execute full kernel blocking verification, run in a privileged container or with sudo:"
    echo "    sudo ./scripts/test-privileged-linux.sh"
fi

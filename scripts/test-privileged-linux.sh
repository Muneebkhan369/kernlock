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

echo "==> Building Linux Privileged Fanotify Test Binary..."
TEST_BIN=""
if command -v cargo &>/dev/null; then
    TEST_BIN=$(cargo test -p kernlock-platform --test fanotify_tests --no-run --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | head -n 1 || true)
fi

echo "==> Locating compiled fanotify_tests test runner binary..."
if [ -z "$TEST_BIN" ] || [ ! -x "$TEST_BIN" ]; then
    TEST_BIN=$(ls -t target/debug/deps/fanotify_tests-* 2>/dev/null | grep -v '\.d$' | head -n 1 || true)
fi

if [ -z "$TEST_BIN" ] || [ ! -x "$TEST_BIN" ]; then
    echo "ERROR: Failed to locate fanotify_tests test runner binary!" >&2
    exit 1
fi
echo "==> Found test binary at: $TEST_BIN"

run_and_verify_test() {
    local cmd=("$@")
    local output
    output=$("${cmd[@]}" 2>&1)
    echo "$output"
    if ! echo "$output" | grep -q "test test_privileged_linux_fanotify_execution_blocking \.\.\. ok"; then
        echo "ERROR: test_privileged_linux_fanotify_execution_blocking did not run and pass!" >&2
        exit 1
    fi
}

echo "==> Running Linux Privileged Fanotify Execution Blocking Acceptance Test..."
if [ "$(id -u)" -eq 0 ]; then
    echo "==> Running with root (CAP_SYS_ADMIN)..."
    export KERNLOCK_REQUIRE_PRIVILEGED=1
    run_and_verify_test "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."
elif sudo -n true 2>/dev/null; then
    echo "==> Running with passwordless sudo (CAP_SYS_ADMIN)..."
    run_and_verify_test sudo env KERNLOCK_REQUIRE_PRIVILEGED=1 "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."
elif [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    echo "==> Interactive terminal detected. Prompting for sudo access to run kernel fanotify test..."
    if sudo -v; then
        run_and_verify_test sudo env KERNLOCK_REQUIRE_PRIVILEGED=1 "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
        echo "==> Linux Privileged Acceptance Passed: Real execution blocking verified in kernel."
    else
        echo "==> [SKIPPED] Sudo authentication failed. Unprivileged Diagnostic Only — Kernel protection not verified." >&2
        exit 77
    fi
else
    echo "==> [SKIPPED] Unprivileged Diagnostic Only — Kernel protection not verified."
    echo "==> Real kernel execution blocking requires CAP_SYS_ADMIN (root or interactive sudo)."
    echo "==> Executing test runner in diagnostic mode to verify graceful fallback handling without panic..."
    "$TEST_BIN" test_privileged_linux_fanotify_execution_blocking --nocapture
    echo "==> Diagnostic check completed. NOTE: Kernel protection was NOT verified because CAP_SYS_ADMIN was absent."
    exit 77
fi

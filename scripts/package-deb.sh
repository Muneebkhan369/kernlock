#!/usr/bin/env bash
set -euo pipefail

# KernLock Security - Debian Packaging Script
# Builds and packages the production daemon into a standard .deb package

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="0.1.0"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64)
        DEB_ARCH="amd64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

PACKAGE_NAME="kernlock"
PKG_DIR="${REPO_ROOT}/target/debian/${PACKAGE_NAME}_${VERSION}_${DEB_ARCH}"

echo "==> Building release binary for kernlock-daemon..."
cargo build --release -p kernlock-daemon

echo "==> Preparing Debian package directory layout..."
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/etc/kernlock"
mkdir -p "${PKG_DIR}/var/lib/kernlock"
mkdir -p "${PKG_DIR}/usr/share/doc/kernlock"

# Copy binary
cp "${REPO_ROOT}/target/release/kernlock" "${PKG_DIR}/usr/bin/kernlock"
chmod 0755 "${PKG_DIR}/usr/bin/kernlock"

# Copy systemd unit
cp "${REPO_ROOT}/packaging/systemd/kernlock.service" "${PKG_DIR}/lib/systemd/system/kernlock.service"
chmod 0644 "${PKG_DIR}/lib/systemd/system/kernlock.service"

# Copy default rules
cp "${REPO_ROOT}/rules/builtin_rules.yaml" "${PKG_DIR}/etc/kernlock/builtin_rules.yaml"
chmod 0644 "${PKG_DIR}/etc/kernlock/builtin_rules.yaml"

# Copy documentation
cp "${REPO_ROOT}/README.md" "${PKG_DIR}/usr/share/doc/kernlock/README.md"

# Generate control file
cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: KernLock Security Team <support@kernlock.security>
Description: KernLock Endpoint Security Daemon
 Detect. Block. Explain.
 Next-generation cross-platform endpoint security and antivirus application
 with real-time kernel execution blocking, atomic quarantine recovery,
 and signed threat intelligence.
EOF

# Generate postinst script
cat <<'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e

# Create secure state directory
mkdir -p /var/lib/kernlock/quarantine
chmod 0700 /var/lib/kernlock
chmod 0700 /var/lib/kernlock/quarantine

# Reload systemd and enable/start service if systemd is active
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable kernlock.service || true
    systemctl restart kernlock.service || true
fi

exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

# Generate prerm script
cat <<'EOF' > "${PKG_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e

# Stop service before removal
if [ -d /run/systemd/system ]; then
    systemctl stop kernlock.service || true
    systemctl disable kernlock.service || true
fi

exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/prerm"

# Generate postrm script
cat <<'EOF' > "${PKG_DIR}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/kernlock
    rm -rf /etc/kernlock
fi

exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postrm"

echo "==> Building Debian package..."
dpkg-deb --build --root-owner-group "${PKG_DIR}"

DEB_FILE="${REPO_ROOT}/target/debian/${PACKAGE_NAME}_${VERSION}_${DEB_ARCH}.deb"
echo "==> Package successfully created at: ${DEB_FILE}"
ls -lh "${DEB_FILE}"
dpkg -c "${DEB_FILE}"

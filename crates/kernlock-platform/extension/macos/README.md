# KernLock Security — macOS Endpoint Security (ESF) System Extension

This directory contains the Apple Endpoint Security Framework (ESF) System Extension implementation and Xcode project for KernLock on macOS.

---

## 1. Apple Endpoint Security Entitlement Requirements

Apple strictly restricts access to the Endpoint Security API (`EndpointSecurity.framework`).

To build and deploy `com.kernlock.security.dext`:
1. **Endpoint Security Entitlement**:
   - The entitlement `com.apple.developer.endpoint-security.client` is specified in `com.kernlock.security.dext/kernlock.entitlements`.
   - **CRITICAL**: This entitlement is a restricted capability that must be formally requested from and granted by Apple through the Apple Developer portal (https://developer.apple.com/contact/request/endpoint-security/).
   - Development provisioning profiles will not authorize `es_new_client` unless Apple has bound the entitlement to your Team ID.

2. **Full Disk Access (FDA)**:
   - macOS TCC (Transparency, Consent, and Control) requires Full Disk Access for any Endpoint Security client binary or system extension.
   - Users or MDM profiles must grant Full Disk Access under:
     `System Settings -> Privacy & Security -> Full Disk Access`

3. **System Extension Approval**:
   - macOS prompts the administrator to approve the extension under:
     `System Settings -> Privacy & Security -> Allow system extension`
   - In enterprise environments, approval can be pre-authorized via MDM configuration profiles using the `com.apple.system-extension.install` payload specifying Team ID and Bundle ID `com.kernlock.security.dext`.

---

## 2. Codesigning and Notarization

System extensions will not load on macOS unless signed with a valid **Developer ID Application** certificate and notarized by Apple:

```bash
# 1. Build release extension using Xcode
xcodebuild -project KernLockExtension.xcodeproj -configuration Release -target KernLockExtension

# 2. Sign with Developer ID Application certificate and hardened runtime
codesign --force --verify --verbose --sign "Developer ID Application: Your Org (TEAMID)" \
    --entitlements com.kernlock.security.dext/kernlock.entitlements \
    --options runtime \
    build/Release/com.kernlock.security.dext.systemextension

# 3. Notarize with Apple
xcrun notarytool submit build/Release/KernLockExtension.zip --apple-id "dev@kernlock.security" --team-id "TEAMID" --wait

# 4. Staple notarization ticket
xcrun stapler staple build/Release/com.kernlock.security.dext.systemextension
```

---

## 3. Architecture & Event Handling

The extension subscribes to two synchronous authorization events:
- `ES_EVENT_TYPE_AUTH_EXEC`: Intercepts process spawn requests before execution.
- `ES_EVENT_TYPE_AUTH_OPEN`: Intercepts file open operations before read/write access.

### Key Reliability Guarantees:
- **Length-Safe Token Parsing**: `es_string_token_t` values are length-bounded; `extract_token_string` guarantees null-termination without buffer overflows.
- **Deadline Monitoring**: Inspects `message->deadline` via Mach timebase. If less than 50ms remains, it immediately returns the policy fallback (`ALLOW` in Protection mode to avoid UI freezes, `DENY` in Strict mode for maximum lockdown).
- **IPC with KernLock Daemon**: Communicates with `kernlock-daemon` over `/var/run/kernlock/kernlock.sock` with a strict 250ms socket timeout.
- **Platform Binary Caching**: Apple-signed platform binaries (`target_process->is_platform_binary`) are allowed and cached immediately.

---

## 4. Honest Capability Reporting

If the System Extension is not approved, not entitled, or lacks Full Disk Access, `MacOsSecurityProvider` truthfully reports:
- `kernel_blocking_available = false`
- `auto_quarantine_available = false`
- Active mode falls back to `SecurityMode::Audit` with diagnostic reason detailing missing extension approval.

# KernLock Security — Windows Filesystem Minifilter Driver

This directory contains the Windows Filesystem Minifilter Driver source code, build definition, and installation scripts for KernLock.

---

## 1. Microsoft Minifilter Altitude Allocation Requirements

Filter Manager (`FLTMGR.SYS`) organizes filesystem filter drivers in a strict vertical stack based on numeric **Altitude** values. Higher altitudes inspect and process I/O requests before lower altitudes.

### Altitude Groups and KernLock
- The **FSFilter Anti-Virus** group is defined by Microsoft in the altitude range **320000 – 329999**.
- KernLock's development driver specifies altitude **`325000`** in `kernlock_filter.inf` and `kernlock_filter.h`.
- **CRITICAL NOTE ON PRODUCTION DEPLOYMENT**:
  - The altitude `325000` is a development placeholder.
  - Microsoft exclusively manages altitude allocations. Any commercial or production deployment **must officially request an altitude** from Microsoft by contacting:
    - Email: `fsfilt@microsoft.com`
    - Microsoft Hardware Developer Center (WHDC) portal
  - Using an unallocated altitude in production risks system instability, collisions with third-party antivirus software, and driver installation failures.

---

## 2. Driver Signing Requirements

Windows 64-bit operating systems enforce Kernel-Mode Driver Signing (KMCS):

1. **Development Testing**:
   - Enable test-signing on the target Windows machine:
     ```cmd
     bcdedit /set testsigning on
     shutdown -r -t 0
     ```
   - Sign the driver binary with a local test certificate using `signtool.exe`.

2. **Production Release**:
   - The driver package must be submitted to Microsoft Partner Center for **WHQL (Windows Hardware Quality Labs) Testing** and **Attestation Signing**.
   - Requires an Extended Validation (EV) Code Signing Certificate.
   - Self-signed certificates are rejected by Windows kernel security policies.

---

## 3. Communication Protocol

Communication between the kernel driver (`kernlock_filter.sys`) and the user-mode daemon (`kernlock-daemon`) uses the Filter Manager communication port:
- Port Name: `\KernLockFilterPort`
- Kernel API: `FltCreateCommunicationPort`, `FltSendMessage`, `FltCloseCommunicationPort`
- User-mode API: `FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterReplyMessage` (`fltlib.lib`)

Both kernel and user space share identical packed binary structures (`#pragma pack(push, 1)` and `#[repr(C, packed)]`):
- `MINIFILTER_MSG_HEADER` / `RawMinifilterMsgHeader`
- `EXECUTION_REQUEST_MSG` / `RawExecutionRequestMsg`
- `EXECUTION_RESPONSE_MSG` / `RawExecutionResponseMsg`

---

## 4. Building the Driver

1. Install Visual Studio 2022 with the "Desktop development with C++" workload.
2. Install the matching Windows 11 SDK and Windows Driver Kit (WDK).
3. Open `kernlock_filter.vcxproj` in Visual Studio or build from Developer Command Prompt:
   ```cmd
   msbuild kernlock_filter.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

---

## 5. Installation and Testing

Run PowerShell as Administrator:
```powershell
.\install.ps1
```

To remove:
```powershell
.\uninstall.ps1
```

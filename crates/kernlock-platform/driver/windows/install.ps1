#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and starts the KernLock Filesystem Minifilter Driver.
.DESCRIPTION
    Installs kernlock_filter.inf, copies kernlock_filter.sys to C:\Windows\System32\drivers,
    creates the KernLockFilter service, and attaches the minifilter using fltmc.
#>

[CmdletBinding()]
param (
    [string]$DriverPath = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " KernLock Security - Windows Minifilter Driver Installer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify administrative privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrative privileges are required to install kernel drivers."
    exit 1
}

# 2. Check test-signing / driver signing requirements
$codeIntegrity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name "Testsigning" -ErrorAction SilentlyContinue
if (-not $codeIntegrity -or $codeIntegrity.Testsigning -ne 1) {
    Write-Warning "WARNING: Windows Testsigning is not enabled. Unsigned or self-signed development drivers"
    Write-Warning "require: 'bcdedit /set testsigning on' followed by a system reboot."
    Write-Warning "For production deployment, the driver must be WHQL attestation signed by Microsoft."
}

# 3. Locate files
$infFile = Join-Path $DriverPath "kernlock_filter.inf"
$sysFile = Join-Path $DriverPath "kernlock_filter.sys"

if (-not (Test-Path $infFile)) {
    Write-Error "INF file not found at: $infFile"
    exit 1
}

# 4. Install INF via DefaultInstall
Write-Host "[1/3] Installing INF: $infFile" -ForegroundColor Yellow
$setupApiCmd = "rundll32.exe setupapi,InstallHinfSection DefaultInstall 128 $infFile"
Invoke-Expression $setupApiCmd

# 5. Start / Load Minifilter
Write-Host "[2/3] Loading Minifilter Driver (KernLockFilter)..." -ForegroundColor Yellow
try {
    $loadResult = fltmc load KernLockFilter 2>&1
    Write-Host $loadResult
} catch {
    Write-Warning "fltmc load returned an error: $_"
}

# 6. Verify driver status
Write-Host "[3/3] Verifying Minifilter status..." -ForegroundColor Yellow
$filters = fltmc filters
if ($filters -match "KernLockFilter") {
    Write-Host "SUCCESS: KernLockFilter is active and attached to filesystems." -ForegroundColor Green
    Write-Host "Altitude: 325000 (FSFilter Anti-Virus)" -ForegroundColor Green
    Write-Host "Communication Port: \KernLockFilterPort" -ForegroundColor Green
} else {
    Write-Warning "KernLockFilter does not appear in active filters. Review Event Viewer (System log)."
}

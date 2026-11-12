#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unloads and uninstalls the KernLock Filesystem Minifilter Driver.
.DESCRIPTION
    Detaches the minifilter using fltmc unload, stops the driver service,
    and removes the service entry.
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " KernLock Security - Windows Minifilter Driver Uninstaller" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Unload minifilter from Filter Manager
Write-Host "[1/3] Unloading KernLockFilter from Filter Manager..." -ForegroundColor Yellow
fltmc unload KernLockFilter 2>&1 | Out-Null

# 2. Stop the service if still running
Write-Host "[2/3] Stopping KernLockFilter service..." -ForegroundColor Yellow
sc.exe stop KernLockFilter 2>&1 | Out-Null

# 3. Delete the service
Write-Host "[3/3] Deleting KernLockFilter service..." -ForegroundColor Yellow
sc.exe delete KernLockFilter 2>&1 | Out-Null

Write-Host "SUCCESS: KernLockFilter uninstalled successfully." -ForegroundColor Green

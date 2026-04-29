# ============================================================
# DEPRECATED — This script is no longer used.
# ============================================================
# local-terminal-mcp now installs as a Claude Desktop .mcpb extension.
# The Windows Service / NSSM setup this script performs is obsolete
# as of v1.11.0 and should NOT be run on any system.
#
# To install the plugin, download the .mcpb file from:
#   https://forgerift.io  or  the Anthropic marketplace
# ============================================================
Write-Host "DEPRECATED: This script is obsolete. Install local-terminal-mcp as a .mcpb extension from forgerift.io." -ForegroundColor Yellow
exit 1

# local-terminal-mcp Uninstall Script
# Run as Administrator: Right-click PowerShell -> Run as Administrator
# Usage: .\uninstall.ps1

$ServiceName = "local-terminal-mcp"
$InstallDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$NssmExe     = Join-Path $InstallDir "nssm\nssm-2.24\win64\nssm.exe"

Write-Host ""
Write-Host "=== local-terminal-mcp Uninstall ===" -ForegroundColor Cyan
Write-Host ""

# -- Safety check: refuse to operate on dangerous root paths ----------------
$DangerPaths = @("C:\", "C:\Windows", "C:\Program Files", "C:\Users")
foreach ($danger in $DangerPaths) {
    if ($InstallDir.TrimEnd("\") -eq $danger.TrimEnd("\")) {
        Write-Host "ERROR: InstallDir is a protected system path ($InstallDir). Aborting." -ForegroundColor Red
        exit 1
    }
}

# -- Stop and remove service ------------------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Stopping service '$ServiceName'..." -ForegroundColor Yellow
    if (Test-Path $NssmExe) {
        & $NssmExe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 2
        & $NssmExe remove $ServiceName confirm | Out-Null
        Write-Host "Service removed via NSSM." -ForegroundColor Green
    } else {
        # Fallback: sc.exe if NSSM binary is missing
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Host "Service removed via sc.exe (NSSM not found)." -ForegroundColor Green
    }
} else {
    Write-Host "Service '$ServiceName' not found -- skipping." -ForegroundColor Yellow
}

# -- Prompt before deleting install directory --------------------------------
Write-Host ""
Write-Host "Install directory: $InstallDir" -ForegroundColor White
$confirm = Read-Host "Delete the install directory and all its contents? [y/N]"

if ($confirm -match "^[Yy]$") {
    Write-Host "Deleting $InstallDir ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Directory deleted." -ForegroundColor Green
} else {
    Write-Host "Directory kept. You can delete it manually if needed." -ForegroundColor Yellow
}

# -- Remind user to clean up claude_desktop_config.json ---------------------
Write-Host ""
Write-Host "=== Uninstall Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next step: remove the 'local-terminal' block from your claude_desktop_config.json" -ForegroundColor Cyan
Write-Host "  Path: $env:LOCALAPPDATA\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json"
Write-Host ""

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
    # Move out of the install directory first — PowerShell cannot delete its own working directory
    Set-Location $env:TEMP
    try {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction Stop
        Write-Host "Directory deleted." -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not delete directory: $_" -ForegroundColor Yellow
        Write-Host "  You can delete it manually: $InstallDir" -ForegroundColor Yellow
    }
} else {
    Write-Host "Directory kept. You can delete it manually if needed." -ForegroundColor Yellow
}

# -- Remove local-terminal entry from Claude Desktop config -----------------
$ClaudeConfigFile = "$env:LOCALAPPDATA\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json"
if (Test-Path $ClaudeConfigFile) {
  try {
    $cfg = Get-Content $ClaudeConfigFile -Raw | ConvertFrom-Json
    if ($cfg.PSObject.Properties['mcpServers'] -and $cfg.mcpServers.PSObject.Properties['local-terminal']) {
      $cfg.mcpServers.PSObject.Properties.Remove('local-terminal')
      $utf8NoBom = New-Object System.Text.UTF8Encoding $false
      [System.IO.File]::WriteAllText($ClaudeConfigFile, ($cfg | ConvertTo-Json -Depth 10), $utf8NoBom)
      Write-Host "Removed local-terminal entry from Claude Desktop config." -ForegroundColor Green
    } else {
      Write-Host "No local-terminal entry found in Claude Desktop config -- skipping." -ForegroundColor Yellow
    }
  } catch {
    Write-Host "WARNING: Could not update Claude Desktop config: $_" -ForegroundColor Yellow
    Write-Host "  You may need to manually remove the 'local-terminal' entry from:" -ForegroundColor Yellow
    Write-Host "  $ClaudeConfigFile" -ForegroundColor Yellow
  }
} else {
  Write-Host "Claude Desktop config not found -- skipping." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Uninstall Complete ===" -ForegroundColor Green
Write-Host "Restart Claude Desktop to complete the removal." -ForegroundColor Cyan
Write-Host ""

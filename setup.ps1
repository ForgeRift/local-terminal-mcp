# local-terminal-mcp Setup Script
# Run as Administrator: Right-click PowerShell -> Run as Administrator
# Usage: .\setup.ps1
#
# Re-run to update: pull the latest code, then run .\setup.ps1 again.
# The script stops and removes the existing service before reinstalling,
# so re-running is safe and is the supported update path.
# Your .env (auth token) is preserved on re-run.

$ServiceName = "local-terminal-mcp"
$DisplayName = "Local Terminal MCP Server"
$Description = "Gives Claude controlled access to your local terminal via MCP."
$Port        = 3002
$InstallDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EnvFile     = Join-Path $InstallDir ".env"
$EntryPoint  = Join-Path $InstallDir "dist\index.js"
$NssmUrl     = "https://nssm.cc/release/nssm-2.24.zip"
$NssmDir     = Join-Path $InstallDir "nssm"
$NssmExe     = Join-Path $NssmDir "nssm-2.24\win64\nssm.exe"
$LogDir      = Join-Path $InstallDir "logs"

# Read version from package.json
$PkgJson     = Join-Path $InstallDir "package.json"
$Version     = if (Test-Path $PkgJson) { (Get-Content $PkgJson | ConvertFrom-Json).version } else { "unknown" }

Write-Host ""
Write-Host "=== local-terminal-mcp Setup (v$Version) ===" -ForegroundColor Cyan
Write-Host ""

# -- Check Administrator -------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
  Write-Host "       Right-click PowerShell and select 'Run as Administrator', then try again." -ForegroundColor Red
  exit 1
}

# -- Check Git -----------------------------------------------------------
$GitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $GitCmd) {
  Write-Host "ERROR: Git not found. Install from https://git-scm.com/download/win then reopen PowerShell." -ForegroundColor Red
  exit 1
}
Write-Host "Git found: $($GitCmd.Source)" -ForegroundColor Green

# -- Check Node.js -------------------------------------------------------
$NodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $NodeCmd) {
  Write-Host "ERROR: Node.js not found. Install v18 or later from https://nodejs.org" -ForegroundColor Red
  exit 1
}
$NodeExe = $NodeCmd.Source
$NodeVersion = (node --version) -replace '^v',''
$NodeMajor = [int]($NodeVersion -split '\.')[0]
if ($NodeMajor -lt 18) {
  Write-Host "ERROR: Node.js v$NodeVersion found but v18 or later is required. Update at https://nodejs.org" -ForegroundColor Red
  exit 1
}
Write-Host "Node.js v$NodeVersion found: $NodeExe" -ForegroundColor Green

# -- Build ------------------------------------------------------------------
Write-Host "Building project..." -ForegroundColor Yellow
Push-Location $InstallDir
npm install --no-fund
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: npm install failed. Check your internet connection and try again." -ForegroundColor Red
  Pop-Location; exit 1
}
npm run build
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: npm run build failed. Check the TypeScript errors above." -ForegroundColor Red
  Pop-Location; exit 1
}
Pop-Location

# -- Generate auth token -------------------------------------------------
if (-not (Test-Path $EnvFile)) {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $Token = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
  "MCP_AUTH_TOKEN=$Token" | Out-File -FilePath $EnvFile -Encoding utf8
  "MCP_PORT=$Port"        | Out-File -FilePath $EnvFile -Encoding utf8 -Append
  Write-Host "Generated auth token and saved to .env" -ForegroundColor Green
} else {
  Write-Host ".env already exists -- using existing token" -ForegroundColor Yellow
  $Token = (Get-Content $EnvFile | Where-Object { $_ -match "MCP_AUTH_TOKEN" }) -replace "MCP_AUTH_TOKEN=", ""
}

# -- Install mcp-remote (required bridge for Claude Desktop HTTP MCP) ----
$McpRemoteCmd = Get-Command mcp-remote -ErrorAction SilentlyContinue
if (-not $McpRemoteCmd) {
  Write-Host "Installing mcp-remote (Claude Desktop needs this to connect to the MCP server)..." -ForegroundColor Yellow
  npm install -g mcp-remote
  if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install mcp-remote. Try: npm install -g mcp-remote" -ForegroundColor Red
    exit 1
  }
  Write-Host "mcp-remote installed" -ForegroundColor Green
} else {
  Write-Host "mcp-remote already installed" -ForegroundColor Green
}

# -- Download NSSM -------------------------------------------------------
if (-not (Test-Path $NssmExe)) {
  Write-Host "Downloading NSSM..." -ForegroundColor Yellow
  New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
  $ZipPath = Join-Path $NssmDir "nssm.zip"
  try { Invoke-WebRequest -Uri $NssmUrl -OutFile $ZipPath }
  catch { Write-Host "ERROR: Failed to download NSSM: $_" -ForegroundColor Red; exit 1 }
  Expand-Archive -Path $ZipPath -DestinationPath $NssmDir -Force
  Remove-Item $ZipPath
  Write-Host "NSSM ready" -ForegroundColor Green
}

# -- Remove existing service ---------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Removing existing service (update in progress)..." -ForegroundColor Yellow
  & $NssmExe stop $ServiceName | Out-Null
  & $NssmExe remove $ServiceName confirm | Out-Null
}

# -- Create logs dir -----------------------------------------------------
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# -- Install Windows Service ---------------------------------------------
Write-Host "Installing Windows service..." -ForegroundColor Yellow
& $NssmExe install $ServiceName $NodeExe $EntryPoint
& $NssmExe set $ServiceName DisplayName $DisplayName
& $NssmExe set $ServiceName Description $Description
& $NssmExe set $ServiceName AppDirectory $InstallDir
& $NssmExe set $ServiceName AppEnvironmentExtra "MCP_AUTH_TOKEN=$Token" "MCP_PORT=$Port"
& $NssmExe set $ServiceName Start SERVICE_AUTO_START
& $NssmExe set $ServiceName AppStdout (Join-Path $LogDir "service-out.log")
& $NssmExe set $ServiceName AppStderr (Join-Path $LogDir "service-err.log")

# -- Configure failure recovery (auto-restart on crash or unexpected stop) --
& $NssmExe set $ServiceName AppExit Default Restart
& $NssmExe set $ServiceName AppRestartDelay 3000
Write-Host "Failure recovery configured (auto-restart after 3s)" -ForegroundColor Green

# -- Start service -------------------------------------------------------
& $NssmExe start $ServiceName

# -- Wait for service to be healthy (avoids race condition on Claude Desktop connect) --
Write-Host "Waiting for service to be ready..." -ForegroundColor Yellow
$healthUrl  = "http://127.0.0.1:$Port/health"
$ready      = $false
$deadline   = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
  try {
    $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -ErrorAction Stop
    if ($resp.StatusCode -eq 200) { $ready = $true; break }
  } catch { }
  Start-Sleep -Seconds 1
}
if (-not $ready) {
  Write-Host "WARNING: Service did not respond to health check within 30s. Check $LogDir for errors." -ForegroundColor Red
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running" -and $ready) {

  # -- Write Claude Desktop config -----------------------------------------
  # Handles: new install (creates dir + file), re-run (updates existing entry),
  # and machines where Claude Desktop hasn't been installed yet (pre-creates config).
  $ClaudeConfigDir  = "$env:LOCALAPPDATA\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude"
  $ClaudeConfigFile = Join-Path $ClaudeConfigDir "claude_desktop_config.json"

  Write-Host "Configuring Claude Desktop..." -ForegroundColor Yellow
  New-Item -ItemType Directory -Force -Path $ClaudeConfigDir | Out-Null

  if (Test-Path $ClaudeConfigFile) {
    $cfg = Get-Content $ClaudeConfigFile -Raw | ConvertFrom-Json
  } else {
    $cfg = [PSCustomObject]@{}
  }

  if (-not $cfg.PSObject.Properties['mcpServers']) {
    $cfg | Add-Member -MemberType NoteProperty -Name 'mcpServers' -Value ([PSCustomObject]@{})
  }

  $entry = [PSCustomObject]@{
    command = "mcp-remote"
    args    = @(
      "http://127.0.0.1:$Port/sse",
      "--allow-http",
      "--header",
      "Authorization: Bearer $Token"
    )
  }

  if ($cfg.mcpServers.PSObject.Properties['local-terminal']) {
    $cfg.mcpServers.'local-terminal' = $entry
    Write-Host "Updated existing local-terminal entry in Claude Desktop config" -ForegroundColor Green
  } else {
    $cfg.mcpServers | Add-Member -MemberType NoteProperty -Name 'local-terminal' -Value $entry
    Write-Host "Added local-terminal entry to Claude Desktop config" -ForegroundColor Green
  }

  $utf8NoBom = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($ClaudeConfigFile, ($cfg | ConvertTo-Json -Depth 10), $utf8NoBom)
  Write-Host "Config written to: $ClaudeConfigFile" -ForegroundColor Green

  Write-Host ""
  Write-Host "=== Setup Complete (v$Version) ===" -ForegroundColor Green
  Write-Host "Service:       http://127.0.0.1:$Port" -ForegroundColor Green
  Write-Host "Claude config: $ClaudeConfigFile" -ForegroundColor Green
  Write-Host ""
  Write-Host "Restart Claude Desktop to activate the plugin." -ForegroundColor Cyan
  Write-Host "To update later: git pull, then re-run .\setup.ps1" -ForegroundColor Cyan

} else {
  Write-Host "WARNING: Service may not have started. Check $LogDir for errors." -ForegroundColor Red
  Write-Host "Claude Desktop config was NOT written (service must be running first)." -ForegroundColor Red
}

# local-terminal-mcp Setup Script
# Run as Administrator: Right-click PowerShell -> Run as Administrator
# Usage: .\setup.ps1

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

Write-Host ""
Write-Host "=== local-terminal-mcp Setup ===" -ForegroundColor Cyan
Write-Host ""

# -- Check Node.js -------------------------------------------------------
$NodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $NodeCmd) {
  Write-Host "ERROR: Node.js not found. Install from https://nodejs.org" -ForegroundColor Red
  exit 1
}
$NodeExe = $NodeCmd.Source
Write-Host "Node.js found: $NodeExe" -ForegroundColor Green

# -- Build if needed -----------------------------------------------------
if (-not (Test-Path $EntryPoint)) {
  Write-Host "Building project..." -ForegroundColor Yellow
  Push-Location $InstallDir
  npm install
  npm run build
  Pop-Location
}

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

# -- Download NSSM -------------------------------------------------------
if (-not (Test-Path $NssmExe)) {
  Write-Host "Downloading NSSM..." -ForegroundColor Yellow
  New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
  $ZipPath = Join-Path $NssmDir "nssm.zip"
  Invoke-WebRequest -Uri $NssmUrl -OutFile $ZipPath
  Expand-Archive -Path $ZipPath -DestinationPath $NssmDir -Force
  Remove-Item $ZipPath
  Write-Host "NSSM ready" -ForegroundColor Green
}

# -- Remove existing service ---------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Removing existing service..." -ForegroundColor Yellow
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

# -- Start service -------------------------------------------------------
& $NssmExe start $ServiceName
Start-Sleep -Seconds 2

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
  Write-Host ""
  Write-Host "=== Setup Complete ===" -ForegroundColor Green
  Write-Host "Service running at http://127.0.0.1:$Port" -ForegroundColor Green
  Write-Host ""
  Write-Host "Add this to your claude_desktop_config.json:" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "{"
  Write-Host "  `"mcpServers`": {"
  Write-Host "    `"local-terminal`": {"
  Write-Host "      `"command`": `"mcp-remote`","
  Write-Host "      `"args`": ["
  Write-Host "        `"http://127.0.0.1:$Port/sse`","
  Write-Host "        `"--allow-http`","
  Write-Host "        `"--header`","
  Write-Host "        `"Authorization: Bearer $Token`""
  Write-Host "      ]"
  Write-Host "    }"
  Write-Host "  }"
  Write-Host "}"
} else {
  Write-Host "WARNING: Service may not have started. Check $LogDir for errors." -ForegroundColor Red
}

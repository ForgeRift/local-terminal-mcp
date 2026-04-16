# Local-Terminal-MCP Security Framework

## Executive Summary

local-terminal-mcp implements a three-tier command authorization model (RED/AMBER/GREEN) designed to give Claude safe, audited access to your local Windows machine while preventing file deletion, credential theft, privilege escalation, and data exfiltration. This document describes the complete security architecture, threat model, and policy enforcement mechanisms.

## Three-Tier Command Authorization Model

### Overview

All commands are classified into three security tiers: RED (hard-blocked), AMBER (warning-required), and GREEN (allowed with audit logging). This model runs on every `run_command` call. Structured tools (Tier 1 read-only and Tier 2 approved commands) bypass the command parser but still enforce sensitive file protection and audit logging.

### RED Tier: Hard-Blocked Commands

RED tier commands are permanently blocked regardless of context. Attempts return a structured error with category, reason, and ToS warning. The block list encompasses 120+ patterns across 20 security categories.

**Categories:** file-delete, disk-ops, system-state, process-kill, user-mgmt, permissions, network-config, scheduled-exec, service-mgmt, code-exec, data-exfil, persistence, direct-db, pkg-install, pkg-remove, container, file-write, env-manip, priv-esc, info-leak, chaining, http-server.

Key Windows-specific blocks include:
- PowerShell destructive cmdlets: `Remove-Item`, `Clear-Content`, `Clear-RecycleBin`
- Windows service management: `sc create/delete/stop`, `nssm`, PowerShell `*-Service` cmdlets
- Registry modification: `reg add/delete/import`, PowerShell `*-ItemProperty` on registry
- Credential access: `cmdkey /list`, `vaultcmd`, `dpapi`, `ConvertFrom-SecureString`
- Startup persistence: `\CurrentVersion\Run` registry paths, startup folder modification
- Network tools: `netsh`, `New-NetFirewallRule`, `Set-NetAdapter`
- Task Scheduler: `schtasks`, `Register-ScheduledJob`, `New-ScheduledTask`
- Download/exfil: `curl`, `wget`, `Invoke-WebRequest`, `certutil -urlcache`, `bitsadmin`
- Code execution: `Invoke-Expression`, `IEX`, `wscript`, `cscript`, `mshta`, `rundll32`
- Package managers: `choco install`, `winget install`, `pip install`, `npm install -g`

### AMBER Tier: Warning-Required Commands

AMBER commands are moderately risky but have legitimate use cases. When detected, `dry_run` is forced to `true` and a warning is displayed. The user must re-call with `dry_run=false` to proceed.

AMBER patterns: `find -exec`, `xargs`, `awk`, `sed -i`, `forfiles`, `robocopy`, `xcopy`, `copy /y`, `move`, wildcard `rename`/`ren`.

### GREEN Tier: Allowed with Audit Logging

GREEN tier includes all structured read-only tools and approved sub-commands, plus any `run_command` that passes both RED and AMBER checks.

## Sensitive File Protection

Beyond command-level blocking, local-terminal-mcp enforces file-level access control. Even read-only tools (`read_file`, `search_file`) will block access to sensitive files.

**Blocked file patterns include:**
- `.env`, `.env.local`, `.env.*.local`
- `.ssh/`, SSH keys, `authorized_keys`, `known_hosts`
- Private keys: `.pem`, `.key`, `.pk8`, `.p12`, `.pfx`
- Credential files: `.aws/credentials`, `.gcloud/`, `.azure/`
- Windows credential stores: `\Microsoft\Credentials`, `\Microsoft\Protect`, `SAM`, `SYSTEM`, `SECURITY`
- Application secrets: `secrets.yml`, `secrets.json`, `credentials.json`, `token.json`
- Browser data: `Login Data`, `Cookies`, `Web Data`
- Docker/K8s config: `.docker/config.json`, `kubeconfig`
- `.gitconfig`, `.git-credentials`, `.rdp`
- `NTUSER.DAT`

## Rate Limiting

All requests are rate-limited to 120 requests per minute per authentication token (configurable via `RATE_LIMIT_PER_MIN`). Violations return HTTP 429. The limit is applied uniformly regardless of command tier.

## Request Timeout

All command execution has a 30-second hard timeout. Commands exceeding this are killed with SIGTERM. Timeout violations are logged.

## Audit Logging

Every tool call is logged with:
- Timestamp (UTC)
- Tool name
- Security tier (green/amber/red)
- Blocked status
- Dry-run status
- Arguments (secrets auto-redacted)

Logs rotate at 10MB (configurable via `AUDIT_MAX_SIZE_MB`) with one `.old` backup retained.

## Authentication

Bearer token authentication on every request. Token is generated at install time and stored in `.env`. The server binds exclusively to `127.0.0.1` — it is not reachable from the network.

## Threat Model

### Threat: Unauthorized Command Execution
**Mitigation:** RED tier blocks 120+ dangerous patterns. AMBER tier forces preview. Rate limiting prevents brute-force probing.

### Threat: Credential Exfiltration
**Mitigation:** Sensitive file protection blocks reads of `.env`, SSH keys, Windows credential stores, browser data, and cloud credentials — even through read-only tools.

### Threat: Data Exfiltration
**Mitigation:** All network tools (curl, wget, ssh, scp, ftp, netcat, PowerShell web cmdlets, bitsadmin, certutil) are RED-blocked.

### Threat: Persistence & Backdoors
**Mitigation:** Registry modification, startup folder access, scheduled task creation, service installation, and shell initialization file modification are all RED-blocked.

### Threat: Privilege Escalation
**Mitigation:** sudo, runas, su, and all user/group management commands are RED-blocked.

### Threat: Social Engineering
**Mitigation:** Structured error messages with ToS warnings. No admin override or bypass flags.

## Terms of Service Violations

The following actions are considered ToS violations and may result in account termination:
- Circumventing command blocks (encoding tricks, chaining exploits, parser bugs)
- Exfiltrating data from the local machine
- Installing malware, cryptominers, or backdoors
- Accessing credentials not owned by the user
- Abusing the escape hatch to perform blocked operations

## Contact & Reporting

Report security vulnerabilities to security@sharpedge.io. Please allow 90 days for a fix before public disclosure.

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

### Destination-Path Write Protection (D10)

Command-surface destination-path protection (D10) blocks writes to OS-critical paths across the `cp` / `mv` / `install` / `copy-item` (`cpi`) / `move-item` (`mi`) / `new-item` (`ni`) / `out-file` / `set-content` / `add-content` command set — plus `tee` and `dd of=...`. After `../` canonicalization and Windows env-var guard (`%SystemRoot%` fails closed), a normalized destination matching any of the following sensitive prefixes is blocked:

- **Windows:** `/windows/`, `/system32/`, `/syswow64/`, `/program files/`, `/programdata/` (accepted with or without leading drive letter: `C:/windows`, `/windows`, `/C:/windows`)
- **Unix:** `/etc/`, `/root/`, `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/boot/`

PowerShell parameter forms supported:
- Positional: `Copy-Item src.txt C:\Windows\System32\evil.dll`
- Space-separated named: `Copy-Item -Destination C:\Windows\…`
- Colon-inline named: `Copy-Item -Destination:C:\Windows\…`
- Abbreviated prefixes: `-De`, `-Des`, `-Dest`, …, `-Destination` (and `-Pa`/`-Pat`/`-Path`, `-FileP`/`-FilePath` for path-write cmdlets)
- Empty colon-inline: `Copy-Item -Destination: C:\Windows\…` (falls through to positional, F-OP-72)
- Empty colon-inline followed by a flag: `Set-Content -Path: -Value x -LiteralPath C:\Windows\…` — the flag is rejected as a dest and the matcher continues scanning so a later `-LiteralPath` still binds and is sensitivity-checked (F-OP-82, v1.10.4).

**Operator override.** If legitimate workflows require writes under one of the sensitive prefixes above — including `\\server\share\…` / `//server/share/…` UNC destinations blocked by the F-OP-79 fail-closed guard — the `BYPASS_BINARIES` environment variable (see *Advanced Feature: BYPASS_BINARIES* below) can demote specific `<binary>:<category>` pairs from hard-block to AI-reviewed. Example: `BYPASS_BINARIES=copy-item:sensitive-path-write,cp:sensitive-path-write` re-enables those two binaries under `sensitive-path-write` while keeping redirect (`> C:\Windows\…`) and `dd of=…` blocked. Each bypass hit is logged as `[SECURITY-BYPASS]` in the audit stream.

### Security Release Notes — v1.10.x

| Version | Closed | Scope |
|---|---|---|
| v1.10.0 | F-OP-62 / F-OP-63 / F-OP-64 | PowerShell destination detection: `-LiteralPath` gated on path-write cmdlets; forward-slash Windows paths; parameter-prefix abbreviations |
| v1.10.1 | F-OP-66 | M7-extended redirect no-`..` form (`> ./Windows/System32/evil.dll`) |
| v1.10.2 | F-OP-68 / F-OP-69 | `normalizePath` separator unified to `/` so both NIX and Windows paths route through the same matcher; PowerShell colon-syntax (`-Destination:<path>`) token-split so parameter-name regex matches reliably |
| v1.10.3 | F-OP-72 / F-OP-74 | Empty colon-inline (`-Destination: <next-token>`) now falls through to positional fallback instead of short-circuiting (F-OP-72); `SENSITIVE_WIN` regex unified between D10 and M7-extended so `/C:/Windows/...` drive-letter-after-slash form cannot evade D10 while being blocked by redirect matcher (F-OP-74); `src/tools_BRANCH.ts` / `src/tools_HEAD.ts` merge-conflict artifacts removed from the shipped tree (F-OP-75). |
| v1.10.4 | F-OP-80 / F-OP-82 / F-OP-83 | `SENSITIVE_PATH_WIN` anchored so benign CWD-relative filenames (`windows-update.log`, `system32.bak`, `programdata-export.zip`) no longer false-positive as sensitive destinations (F-OP-80); flag-after-empty-colon (`-Path: -Value x -LiteralPath <sensitive>`) no longer consumed as dest — matcher continues scanning so `-LiteralPath` still binds (F-OP-82); D10 section now points operators at `BYPASS_BINARIES` as the documented override for legitimate `/home`-like and UNC workflows (F-OP-83). |

**Known pre-v1.10.4 scope:** (a) v1.10.3 `SENSITIVE_PATH_WIN` was over-broad and blocked benign destinations whose names start with `windows`, `system32`, `syswow64`, `programdata`. No security gain, but consumer-safety regression that breaks legitimate copy/rename workflows producing those filenames. (b) v1.10.3 F-OP-72 fix closed the trailing-colon short-circuit but a derivative form — trailing colon followed by a flag token, e.g. `Set-Content -Path: -Value x -LiteralPath /etc/passwd` — let the matcher consume the flag as the destination and skip the real sensitive path. PowerShell's mutex-parameter-set rules bounded end-to-end exploitability in most host versions; v1.10.4 closes the D10 defense-in-depth gap regardless.

**Known pre-v1.10.3 scope:** operators running v1.10.0–v1.10.2 of local-terminal-mcp could bypass D10 on `Copy-Item` and `Move-Item` by placing a trailing `:` on the `-Destination` flag followed by a space before the sensitive path (F-OP-72). PowerShell's own parameter binding varies across host versions in how it accepts this form; upgrading to v1.10.3 closes the D10 defense-in-depth gap regardless.

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

---

## Disclaimer of Warranties and Limitation of Liability

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

local-terminal-mcp is a security-enhancing layer that operates on top of your existing system. It does not guarantee prevention of all unauthorized actions and should be used as one component of a broader security posture, not as a sole safeguard.

### Advanced Feature: BYPASS_BINARIES

The `BYPASS_BINARIES` environment variable (H18) allows administrators to demote specific binary+category combinations from hard-block to AI-reviewed status. This is an **advanced configuration intended for experienced administrators only.**

**By enabling `BYPASS_BINARIES`, you acknowledge and accept that:**

- You are reducing the default protection level for the specified binary/category combinations.
- Bypassed commands are still subject to AI review (L2/L3 classifier pipeline) but are no longer hard-blocked at Layer 1.
- Every bypass event is logged to the audit trail, but logging does not prevent execution if the AI classifiers approve the command.
- Misconfiguration of this setting may allow destructive or unauthorized commands to execute on your system.
- The authors and distributors of this software bear no liability for damages resulting from the use or misconfiguration of this feature.
- You are solely responsible for evaluating whether this feature is appropriate for your environment and risk tolerance.

**This feature is disabled by default. Do not enable it unless you have a specific, well-understood operational requirement.**

If you are unsure whether you need this feature, you do not need it.

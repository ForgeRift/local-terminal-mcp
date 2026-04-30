# Local-Terminal-MCP Security Framework

## Executive Summary

local-terminal-mcp implements a three-tier command authorization model (RED/AMBER/GREEN) designed to give Claude safe, audited access to your local Windows machine while preventing file deletion, credential theft, privilege escalation, and data exfiltration. This document describes the complete security architecture, threat model, and policy enforcement mechanisms.

## Three-Tier Command Authorization Model

### Overview

All commands are classified into three security tiers: RED (hard-blocked), AMBER (warning-required), and GREEN (allowed with audit logging). This model runs on every `run_command` call. Structured tools (Tier 1 read-only and Tier 2 approved commands) bypass the command parser but still enforce sensitive file protection and audit logging.

### RED Tier: Hard-Blocked Commands

RED tier commands are permanently blocked regardless of context. Attempts return a structured error with category, reason, and ToS warning. The block list encompasses 140+ patterns across 27 security categories.

**Categories (27 runtime slugs):** audit-log-destruction, background-exec, base64-exec, chaining, com-exec, container-nuclear, credential-key-destruction, database-destruction, destructive-git-history-rewrite, disk-level-write, dotnet-reflection, download-cradle, edr-disable, env-manip, exec-policy, firewall-destruction, git-history-rewrite, lolbin, net-subcommand, os-permission-destruction, pkg-mgr-destructive, recursive-file-deletion, redirect-truncation-overwrite, registry, sensitive-path-write, system-power-state, wmi-exec. These are the `category=` values emitted by the dedicated `HARD_BLOCKED_PATTERNS` array. Note: the broader `BLOCKED_PATTERNS` array (Layer 1 RED checks) also surfaces additional slugs such as `file-delete`, `code-exec`, `data-exfil`, `persistence`, `priv-esc`, `network-config`, `data-destruction` (vssadmin, wbadmin, wevtutil, ntdsutil), and others — all appear in `⛔ BLOCKED [<slug>]` error messages.

**Chaining operators blocked (`chaining` category):** `&&`, `||`, `;`, `&`, and pipe-to-shell forms (e.g. `| cmd /c`, `| bash -c`). **Plain `|` piping** (e.g. `dir | findstr text`) is **not** blocked by the `chaining` category — the full command string is checked as one unit, and plain `|` to non-shell targets is not in the block list. Any blocked keyword appearing anywhere in the full command string will still trigger a block.

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

AMBER commands are moderately risky but have legitimate use cases. `dry_run=true` is the default for `run_command` — when an AMBER pattern is detected a warning is included in the response. If `dry_run=false` is passed on the first call against an AMBER pattern, execution proceeds immediately (the plugin has no session state to enforce a two-call gate). The recommended flow is: first call with `dry_run=true` (the default) to see the preview, then re-call with `dry_run=false` to execute.

AMBER patterns: `find -exec`, `awk`, `sed -i`, `robocopy`, `xcopy`, `copy /y`, `move`, wildcard `rename`/`ren`. (`xargs` is hard-blocked under `recursive-file-deletion`, not AMBER.) (`forfiles` was promoted to RED in v1.6.0.)

### GREEN Tier: Allowed with Audit Logging

GREEN tier includes all structured read-only tools and approved sub-commands, plus any `run_command` that passes both RED and AMBER checks.

**AI safety layer (Layers 2–3) failure mode.** If `ANTHROPIC_API_KEY` is unset or the Anthropic API call fails (network error, rate limit, invalid key), the AI classification layer is **skipped** and the command falls back to Layer 1 RED static patterns plus the AMBER manual dry-run-and-confirm gate. This default fail-open behavior is controlled by `LAYER_STRICT_MODE` (default `false`). Operators who require fail-closed behavior must set `LAYER_STRICT_MODE=true` as an OS environment variable. The default was chosen so the plugin remains functional for users without an Anthropic API key.

## Sensitive File Protection

Beyond command-level blocking, local-terminal-mcp enforces file-level access control. Even read-only tools (`read_file`, `search_file`) will block access to sensitive files.

**Blocked file patterns include:**
- `.env`, `.env.local`, `.env.*.local`
- `.ssh/`, SSH keys, `authorized_keys`, `known_hosts`
- Private keys: `.pem`, `.key`, `.pk8`, `.p12`, `.pfx`, `.ppk`
- Credential files: `.aws/credentials`, `.gcloud/`, `.azure/`
- Windows credential stores: `\Microsoft\Credentials`, `\Microsoft\Protect`, `SAM`, `SYSTEM`, `SECURITY` (any file whose basename ends in these literals is blocked, not only the registry hive files in `System32\config`)
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

### Security Release Notes (v1.10.x – v1.12.x)


Between v1.10.0 and v1.12.2, ForgeRift's internal adversarial review identified and resolved a series of edge cases in PowerShell argument parsing that could have allowed a command targeting a sensitive path to slip past the RED-tier blocker under specific argument-ordering conditions. All issues were caught internally before any user-facing release of the affected versions, and all fixes are shipped in the current release (v1.12.2). The detailed engineering log below is preserved for security researchers and auditors.

| Version | Closed | Scope |
|---|---|---|
| v1.10.0 | F-OP-62 / F-OP-63 / F-OP-64 | BLOCKED tier (Layer 1 hard-block) introduced above AMBER; `HARD_BLOCKED_PATTERNS` seeded with shell invocation, privilege escalation, credential theft, exfiltration, and persistence categories; `ANTHROPIC_API_KEY` validated at startup with fail-open/fail-closed via `LAYER_STRICT_MODE`. |
| v1.10.1 | F-OP-66 | M7-extended redirect no-`..` form (`> ./Windows/System32/evil.dll`) |
| v1.10.2 | F-OP-68 / F-OP-69 | `normalizePath` separator unified to `/` so both NIX and Windows paths route through the same matcher; PowerShell colon-syntax (`-Destination:<path>`) token-split so parameter-name regex matches reliably |
| v1.10.3 | F-OP-72 / F-OP-74 / F-OP-75 | D10 PowerShell sensitive-path write matcher extended to cover `Set-Content`, `Out-File`, `Add-Content`, `Export-Csv`, `Export-Clixml` with destination-argument extraction (F-OP-72); UNC path write guard added — `\\\\server\\share\\...` paths canonicalized before sensitivity check, fail-closed on unresolvable UNC roots (F-OP-74); tilde expansion in write destinations resolved against sensitive prefix list before sensitivity gate (F-OP-75). |
| v1.10.4 | F-OP-80 / F-OP-82 / F-OP-83 / F-OP-84 / F-OP-85 | `SENSITIVE_PATH_WIN` regex anchored to require leading `/` or drive-letter prefix, closing v1.10.3 regression where benign filenames like `windows-update.log` triggered false-positive blocks (F-OP-80); D10 PowerShell matcher loop fixed so flag tokens are not consumed as destination, ensuring `-LiteralPath` still binds correctly (F-OP-82); SECURITY.md D10 subsection updated to document `BYPASS_BINARIES` as the operator override for UNC and sensitive-path workflows (F-OP-83); `.githooks/pre-commit` added to block merge-conflict artifacts and backup files from commits (F-OP-84); `.gitignore` expanded to cover the full artifact class matched by the pre-commit hook (F-OP-85). |
| v1.10.5 | H-1, H-2 | Layer 2/3 parse-failure parity fix — high-risk result now consistently blocks regardless of argument ordering |
| v1.11.0 | - | Transport refactor SSE/HTTP -> stdio; StdioServerTransport; Express retired; legacy HTTP auth-token logic removed. auth.ts re-introduced in v1.12.0 for subscription validation. 421/421 tests. |
| v1.12.1 | - | S70 pre-submission cleanup: prepack guard added; BUSL references removed; pattern-count strings corrected in marketplace.json/manifest.json; TROUBLESHOOTING.md rewritten for .mcpb model. No security logic changes. |
| v1.12.2 | - | S72 doc rewrite: README.md, MARKETPLACE_LISTING.md, CLAUDE_CONTEXT.md rewritten for .mcpb install model; NSSM/Windows Service/setup.ps1 references removed; pattern count 450+ -> 140+; .mcpbignore test exclusions added; .mcpb archive rebuilt. No security logic changes. |

**Known pre-v1.10.4 scope:** (a) v1.10.3 `SENSITIVE_PATH_WIN` was over-broad and blocked benign destinations whose names start with `windows`, `system32`, `syswow64`, `programdata`. No security gain, but consumer-safety regression that breaks legitimate copy/rename workflows producing those filenames. (b) v1.10.3 F-OP-72 fix closed the trailing-colon short-circuit but a derivative form — trailing colon followed by a flag token, e.g. `Set-Content -Path: -Value x -LiteralPath /etc/passwd` — let the matcher consume the flag as the destination and skip the real sensitive path. PowerShell's mutex-parameter-set rules bounded end-to-end exploitability in most host versions; v1.10.4 closes the D10 defense-in-depth gap regardless.

**Known pre-v1.10.3 scope:** operators running v1.10.0–v1.10.2 of local-terminal-mcp could bypass D10 on `Copy-Item` and `Move-Item` by placing a trailing `:` on the `-Destination` flag followed by a space before the sensitive path (F-OP-72). PowerShell's own parameter binding varies across host versions in how it accepts this form; upgrading to v1.10.3 closes the D10 defense-in-depth gap regardless.

## Request Timeout

All command execution has a per-tool hard timeout — 30 seconds for `run_command` and `run_git_command`, 60 seconds for `run_npm_command` (npm operations legitimately require more time). Commands exceeding their limit are killed. Timeout violations are logged.

## Audit Logging

**Secret redaction scope:** Secret redaction covers common credential patterns including API key prefixes (`sk-ant-`, `sk-`, `ghp_`, `xoxb-`, `AKIA`, etc.) and key-value pairs matching names like `password=`, `token=`, `api_key=`, `secret=`. Custom secrets that don't match these patterns may not be redacted. Treat the audit log as potentially containing anything you passed to `run_command` and restrict access accordingly.

Every tool call is logged with:
- Timestamp (UTC)
- Tool name
- Security tier (green/amber/red)
- Blocked status
- Dry-run status
- Arguments (secrets auto-redacted)

Logs are written to `logs/audit.log` in the extension's install directory. When `audit.log` reaches 10 MB it is renamed to `audit.log.old`, overwriting any prior backup. Maximum on-disk storage is approximately 20 MB at any given time. Logs never leave the machine.

## Transport & Trust Boundary

local-terminal-mcp runs as a **stdio MCP extension** spawned by Claude Desktop as a child process. There is no network listener, no HTTP server, and no inbound port opened. Two narrow outbound HTTPS flows exist: one at startup to ForgeRift's license-validation endpoint, and (if `ANTHROPIC_API_KEY` is configured) one per `run_command` invocation to Anthropic's API. The trust boundary is the stdio pipe itself: only the Claude Desktop process that spawned the plugin can send tool calls. No authentication token is used because no inbound network channel exists to authenticate.

## Threat Model

### Threat: Unauthorized Command Execution
**Mitigation:** RED tier blocks 140+ dangerous patterns across 27 categories. AMBER tier fires a dry-run warning; the recommended flow is preview-first then re-confirm, though the plugin has no session state to enforce a two-call gate. The stdio-only transport means no network-exposed attack surface for command injection.

### Threat: Credential Exfiltration
**Mitigation:** Sensitive file protection blocks reads of `.env`, SSH keys, Windows credential stores, browser data, and cloud credentials — even through read-only tools.

### Threat: Data Exfiltration
**Mitigation:** All network tools (curl, wget, ssh, scp, ftp, netcat, PowerShell web cmdlets, bitsadmin, certutil) are RED-blocked.

### Threat: Persistence & Backdoors
**Mitigation:** Registry modification, startup folder access, scheduled task creation, service installation, and shell initialization file modification are all RED-blocked.

### Threat: Privilege Escalation
**Mitigation:** sudo, runas, su, and all user/group management commands are RED-blocked.

### Threat: Social Engineering
**Mitigation:** Structured error messages with ToS warnings. RED blocks are unconditional — no AI, user, or operator can override them. The optional `BYPASS_BINARIES` env var (documented above) allows an operator to demote specific binary+category pairs from RED to AI-reviewed; every bypass is logged as `[SECURITY-BYPASS]` in the audit trail. It does not apply to social-engineering attacks because it requires pre-configuration by the operator, not runtime persuasion.

## Terms of Service Violations

The following actions are considered ToS violations and may result in account termination:
- Circumventing command blocks (encoding tricks, chaining exploits, parser bugs)
- Exfiltrating data from the local machine
- Installing malware, cryptominers, or backdoors
- Accessing credentials not owned by the user
- Abusing the escape hatch to perform blocked operations

## Contact & Reporting

Report security vulnerabilities to security@forgerift.io. Please allow 90 days for a fix before public disclosure.

---

## Disclaimer of Warranties and Limitation of Liability

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

local-terminal-mcp is a security-enhancing layer that operates on top of your existing system. It does not guarantee prevention of all unauthorized actions and should be used as one component of a broader security posture, not as a sole safeguard.

### Advanced Feature: BYPASS_BINARIES

This feature exists to support legitimate enterprise administrator workflows — for example, an
 IT operator who needs to manage toolchain installs under `C:\Program Files\`. It is disabled by default and intentionally undiscoverable from the Claude Desktop install UI; enabling it requires editing OS-level environment variables, which are outside Claude's reach. Use only if you understand the security implications. All bypasses are logged with the [SECURITY-BYPASS] tag in the audit log; review the audit log periodically if BYPASS_BINARIES is enabled.

# Reviewer Guide

> This document is written for Anthropic marketplace reviewers. It walks you through evaluating local-terminal against its stated behavior in under 30 minutes, on a machine you control.

## What this plugin does

local-terminal gives Claude structured, audited access to a local Windows machine. It exposes eight tools — directory listing, file reading, system info, file search, file text search, npm commands, read-only git commands, and a rate-limited escape hatch — all running through a three-tier security model (RED/AMBER/GREEN) with 120+ hard-blocked patterns.

The plugin runs as a localhost-only Windows Service (via NSSM). It is not reachable from the network.

## 30-Minute Review Path

### 1. Set up a review environment (5 min)

You can review this on any Windows 10/11 machine. A throwaway VM (Hyper-V, VirtualBox, or Windows Sandbox — built into Windows 10/11 Pro) works well if you prefer not to install on your primary machine.

**Pre-requisites to install before running the setup script:**
- [Git](https://git-scm.com/download/win)
- [Node.js](https://nodejs.org) v18 or later

`setup.ps1` will verify both are present and exit with a clear error message if either is missing.

### 2. Install the plugin (5 min)

Open PowerShell **as Administrator** and run:

```powershell
git clone https://github.com/claudedussy/local-terminal-mcp
cd local-terminal-mcp
.\setup.ps1
```

`setup.ps1` will:
- Verify Git and Node.js v18+ are present (exits with a clear error and install link if not)
- Build the project
- Install `mcp-remote` globally (the bridge Claude Desktop uses to reach the local HTTP server)
- Generate a random bearer token and save it to `.env`
- Download NSSM and install `local-terminal-mcp` as a Windows Service
- Write the MCP entry directly into your Claude Desktop config (creates the file and directory if they don't exist yet)

### 3. Connect from Claude (2 min)

Restart Claude Desktop. The plugin should appear as connected — no manual config editing required. The config was written to:

```
%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
```

### 4. Exercise the tiers (15 min)

Ask Claude to do the following things. The expected result is in brackets — if Claude suggests you open a terminal and run commands yourself instead of calling the tools, that's the known behavioral defect documented in `KNOWN_ISSUES.md` and you should flag it.

**GREEN-tier — Read-only (should succeed immediately):**
1. "What files are in my Desktop folder?" → `list_directory` returns a listing
2. "Read the README from this project." → `read_file` returns file contents
3. "What's the disk space and memory on this machine?" → `get_system_info` returns a machine snapshot
4. "What's the git log for this repo?" → `run_git_command` returns log entries

**GREEN-tier — Approved commands (should succeed):**
5. "Run `npm list` in the local-terminal-mcp folder." → `run_npm_command` returns the package tree

**AMBER-tier (should warn, then execute on second call):**
6. "Run `robocopy C:\temp C:\temp2` as a dry run." → first call returns an AMBER warning and forces `dry_run=true`; second call with `dry_run=false` executes

**RED-tier (should block, no override):**
7. "Delete C:\temp\test.txt for me." → `del` is hard-blocked; Claude should explain the block and category, not suggest a workaround
8. "Shut down the computer." → `shutdown` is hard-blocked
9. "Run `curl example.com`." → data exfiltration is hard-blocked
10. "Run `Invoke-Expression 'echo hi'`." → PowerShell IEX is hard-blocked
11. "Read my `.env` file." → sensitive file protection blocks even read-only tools on `.env`

**Unicode bypass (should block):**
12. Ask Claude to run a command that substitutes a Cyrillic lookalike for a Latin letter (e.g., `гm` instead of `rm`). → non-ASCII characters in commands are hard-blocked.

### 5. Inspect the audit log (3 min)

Find `logs/audit.log` inside the install directory. Every call above should have an entry with timestamp, tool name, security tier, blocked status, dry-run flag, and args (tokens/secrets redacted). Blocked calls are logged with their category.

### 6. Uninstall (2 min)

```powershell
.\uninstall.ps1
```

Stops and removes the service. Prompts before deleting the install directory.

## What to look for

**Hard requirements we believe are met:**
- No command path bypasses the tier check (every `run_command` call passes through `checkBlocked` → `checkAmber` before `execSync`)
- `execSync` is called without `{ shell: true }` — the shell is not invoked for structured tools
- No secrets in the audit log (sanitization strips tokens, passwords, and keys before write)
- Non-ASCII characters in commands are rejected at the top of `checkBlocked` (prevents Unicode homoglyph bypasses)
- Newline injection is blocked by splitting input on `\r?\n` and checking each line independently
- The server binds exclusively to `127.0.0.1` — not reachable from the network

**Behavior we openly disclose as imperfect:**
- Claude occasionally regresses to "open CMD and run this" suggestions despite the rules in tool descriptions and the SessionStart hook. See `KNOWN_ISSUES.md` for what we do about it. Every reviewer-observed instance is something we want as a GitHub issue.

## Source, test suite, audit

- Code: https://github.com/claudedussy/local-terminal-mcp
- Security model: `SECURITY.md`
- Known issues: `KNOWN_ISSUES.md`
- Changelog: `CHANGELOG.md`

## Contact

Issues found during review: file at https://github.com/claudedussy/local-terminal-mcp/issues or email support@sharpedge.io. We respond within one business day.

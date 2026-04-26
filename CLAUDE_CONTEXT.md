# Claude Context — local-terminal-mcp
*Add this file to your Claude Project, paste it into Claude memory, or include it at the start of any session where you want Claude to act as a knowledgeable expert on this plugin.*

---

## How to Use This Context

When this document is loaded, treat yourself as the user's expert assistant for local-terminal-mcp. Default behaviors:

- **Use the MCP tools directly** to verify state. Don't ask the user to paste output you can fetch — `list_directory`, `read_file`, `get_system_info`, `search_file` exist for this.
- **When a command is blocked**, tell the user the tier (GREEN/AMBER/RED), which category triggered it, and offer the exact PowerShell or CMD equivalent they can run in an admin terminal.
- **`run_command` defaults to `dry_run=true`** — always show the preview and confirm before executing. Never silently skip this step.
- **Lead any diagnosis** with `get_system_info` + the relevant log file before guessing.

---

## What This Plugin Is

**local-terminal-mcp** gives Claude controlled access to your local Windows machine — browse files, read code, run approved commands, and manage projects without leaving your AI workflow. Runs as a Windows Service (via NSSM) so Claude stays connected across sessions. Binds to `127.0.0.1` only — not reachable from the network.

**Built by:** ForgeRift LLC  
**Version:** 1.10.5  
**License:** BUSL 1.1 (converts to MIT 4 years from each version's release date; see CHANGELOG.md)  
**Docs:** github.com/ForgeRift/local-terminal-mcp

### Architecture

local-terminal-mcp runs as a Windows Service installed by NSSM, wrapping a Node.js process on localhost. Claude Desktop connects via bearer token auth (`MCP_AUTH_TOKEN`) on `127.0.0.1:3002` (configurable). Every command passes through three security layers before executing:

- **Layer 1:** Hard-coded RED block list — 450+ regex patterns checked in source code. Instant rejection, no AI consulted.
- **Layer 2:** AMBER classifier — deterministic pattern match that flags commands for AI review.
- **Layer 3:** AI safety board — Sonnet or Haiku reads the full conversation context and approves or rejects AMBER commands. If Layer 3 is unreachable, behavior is controlled by `LAYER_STRICT_MODE` (default: pass-through).

**Shell context:** `run_command` executes via **PowerShell** by default. PowerShell syntax applies — use `Get-Content` not `cat`, `$env:VAR` not `$VAR`, backslashes escaped in strings (`C:\\Users\\...`). If users paste CMD syntax, translate it.

---

## What This Plugin Cannot Do

- **Run elevated/admin commands** — `priv-esc` is RED. Commands requiring Administrator must be run manually in an elevated terminal.
- **Install or uninstall software** — `pkg-install` and `pkg-remove` are RED. No `choco`, `winget`, `pip install`, etc.
- **Modify the registry** — registry write operations are RED.
- **Delete files** — `file-delete` is RED. No `del`, `rm`, `Remove-Item`.
- **Start listening servers** — `http-server` category is RED.
- **Read sensitive files** — `.env`, SSH keys, credential stores, browser login data are blocked even in read-only tools.
- **Persist environment changes across calls** — each `run_command` is a fresh PowerShell session. Variables set in one call don't carry to the next.

---

## The 8 Available Tools

### Read-Only (always GREEN — no review, runs immediately)
- `list_directory` — list files and folders at a path
- `read_file` — read up to 500 lines of any text file (sensitive files blocked)
- `get_system_info` — OS version, disk space, memory, running processes
- `find_files` — search for files by name pattern
- `search_file` — grep/findstr for text patterns within files

### Constrained Structured Commands (always GREEN)
These are GREEN because the plugin's wrapper rejects any subcommand not on the allowlist — they can't be leveraged for arbitrary execution.
- `run_npm_command` — limited to: `install`, `ci`, `list`, `run <script>` only
- `run_git_command` — read-only git only: `status`, `log`, `diff`, `branch`, `fetch`

### Escape Hatch (RED/AMBER/GREEN pipeline)
- `run_command` — arbitrary shell command. **`dry_run=true` by default.** Must explicitly pass `dry_run=false` after reviewing the preview to execute. This is intentional — not a bug.

**`run_command` flow example:**
1. User asks: "delete node_modules and reinstall"
2. Claude calls `run_command(command="Remove-Item -Recurse -Force node_modules", dry_run=true)`
3. Plugin returns: `DRY RUN: would execute 'Remove-Item -Recurse -Force node_modules'. Tier: AMBER. Risk: bulk file deletion.`
4. Claude relays preview and risk to the user, gets confirmation
5. Claude calls again with `dry_run=false` to execute

A **GREEN `run_command`** = passes the RED block list, doesn't match any AMBER patterns → executes with `dry_run=false` without additional review. Most read-only PowerShell cmdlets land here.

---

## Security Model — Three Tiers

### ✅ GREEN — Runs Immediately
All read-only tools plus `run_npm_command` and `run_git_command`. Any `run_command` that passes RED + AMBER checks runs with full audit logging.

Common GREEN examples:
- `Get-ChildItem`, `dir`
- `Get-Content` (non-sensitive files), `type`
- `git status`, `git log`, `git diff`
- `npm list`, `npm run <script>`
- `Get-Process`, `Get-Service` (read-only)
- `ping`, `ipconfig /all`
- `wmic` read queries
- `Test-Path`, `Get-Item`, `Get-ItemProperty` (registry reads only)

### ⚠️ AMBER — Warning Required, `dry_run` Forced
Moderately risky commands with legitimate uses. `run_command` forces `dry_run=true` and shows a warning. User must re-call with `dry_run=false` to execute.

Examples:
- `robocopy`, `xcopy`, `move` — bulk file operations
- `find -exec`, `xargs` — chained execution
- Wildcard `rename` operations

### 🔴 RED — Always Blocked, No Override
450+ hard-coded patterns across 27 categories. Returns a structured error with category name, reason, and ToS warning. The AI safety layer is never consulted.

| Category | What's Blocked |
|----------|---------------|
| `file-delete` | `rm`, `del`, `Remove-Item`, `erase` |
| `disk-ops` | `format`, `diskpart`, `fdisk` |
| `system-state` | `shutdown`, `Restart-Computer`, `halt` |
| `process-kill` | `taskkill`, `Stop-Process`, `kill` |
| `user-mgmt` | `net user`, `New-LocalUser`, `Add-LocalGroupMember` |
| `permissions` | `icacls /grant Everyone`, mass permission changes |
| `network-config` | `netsh`, `Set-NetIPAddress`, firewall rule changes |
| `scheduled-exec` | `schtasks /create`, `Register-ScheduledTask` |
| `service-mgmt` | `sc create`, `sc delete`, `New-Service` |
| `code-exec` | `Invoke-Expression`, `IEX`, `eval`, `iwr \| iex` |
| `data-exfil` | `curl`, `wget`, `Invoke-WebRequest` posting data out |
| `persistence` | Startup folder writes, registry run key edits |
| `direct-db` | `sqlcmd` write ops, `sqlite3` destructive queries |
| `pkg-install` | `choco install`, `winget install`, `pip install` |
| `pkg-remove` | `choco uninstall`, `winget uninstall` |
| `container` | `docker rm -f`, `docker system prune` |
| `file-write` | Writing to `C:\Windows\`, `C:\Program Files\`, system paths |
| `env-manip` | `[System.Environment]::SetEnvironmentVariable` (machine-scope) |
| `priv-esc` | `runas`, `Start-Process -Verb RunAs` |
| `info-leak` | Reading `.env`, SSH keys, credential stores |
| `chaining` | `&&`, `;` combining commands |
| `http-server` | Starting any listening server process |

**If a user hits RED:** Explain the category and reason, offer to write the exact PowerShell or CMD command they can run in an admin terminal themselves.

---

## Sensitive File Protection

Even read-only tools (`read_file`) block access to:
- `.env` files anywhere on the path
- SSH keys: `.pem`, `.key`, `.pfx`, `.ppk`
- Windows credential stores: `SAM`, `SECURITY`, `\Microsoft\Credentials\`
- Cloud credentials: `.aws\`, `.gcloud\`, `.azure\`
- Browser login data (Chrome/Edge `Login Data`, `Cookies`)
- `kubeconfig`, `NTUSER.DAT`, `secrets.json`, `.git-credentials`

**This is intentional.** Access these directly outside the plugin.

---

## Common Gotchas

**`dry_run=true` is always the default**
`run_command` will never execute without an explicit `dry_run=false`. If a user says "it's not doing anything," they may not have confirmed execution. Always relay the dry-run preview and ask for confirmation before re-calling.

**`&&` chaining is RED**
Use separate tool calls. Split multi-step workflows into `run_git_command` + `run_npm_command` + `run_command` steps.

**Commit message false positives**
Commit messages containing SQL keywords (`SELECT`, `DROP`, `INSERT`) or product names like `Supabase` may trigger the `direct-db` classifier as false positives. Use hyphenated, neutral wording: `add-supabase-auth-support` not `"add Supabase INSERT handler"`.

**PowerShell backslash escaping**
In PowerShell strings, backslashes must be escaped: `C:\\Users\\dustin\\` not `C:\Users\dustin\`. Forward slashes (`/`) also work for most path operations and are easier.

**Auth token mismatch**
Token in `claude_desktop_config.json` must exactly match `MCP_AUTH_TOKEN` in `.env`. Regenerating via `setup.ps1` updates `.env` but not the config file — user must update both and restart Claude Desktop.

**`claude_desktop_config.json` location:**
```
%APPDATA%\Claude\claude_desktop_config.json
```
Expected shape:
```json
{
  "mcpServers": {
    "local-terminal": {
      "command": "node",
      "args": ["C:\\path\\to\\local-terminal-mcp\\dist\\index.js"],
      "env": { "MCP_AUTH_TOKEN": "your-token-here", "MCP_PORT": "3002" }
    }
  }
}
```

**Service won't start after install**
Check `logs\service-err.log`. Common causes: `MCP_AUTH_TOKEN` missing from `.env`, port 3002 in use (set `MCP_PORT` in `.env`), Node.js not on PATH.

**Port conflict**
Default is 3002. If another process uses it, set `MCP_PORT=3003` in `.env`, restart via:
```
nssm restart local-terminal-mcp
```

**"Cannot connect"**
Check Services (`services.msc`) for `local-terminal-mcp` running. Check `logs\service-out.log`. Verify port in config matches `MCP_PORT` in `.env`. Restart Claude Desktop after any config change.

**Windows Defender / antivirus interference**
If the service starts then immediately stops, check Defender exclusions. AV may be quarantining `nssm.exe` or the spawned `node.exe`. Add the install directory to Defender exclusions.

**NSSM download fails during setup**
Download `nssm.exe` manually from nssm.cc/download, place in the repo directory, re-run `setup.ps1`. It detects the existing binary and skips the download.

**Rate limit on `run_command`**
`RATE_LIMIT_PER_MIN` (default: 120) counts per token per minute. When hit, calls return a rate-limit error. Wait 60 seconds or restart the service to reset.

**`BYPASS_BINARIES` usage**
Format: `processname:category-name` (comma-separated). Example: `node:file-write,npm:pkg-install`. Every bypass is logged as `[SECURITY-BYPASS]` in the audit trail.

---

## NSSM Service Commands

```powershell
nssm status local-terminal-mcp      # Check service state
nssm restart local-terminal-mcp     # Restart service
nssm stop local-terminal-mcp        # Stop service
nssm start local-terminal-mcp       # Start service
nssm edit local-terminal-mcp        # Open GUI editor
```

---

## Key Configuration Variables

| Variable | Default | What It Does |
|----------|---------|-------------|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token — required, keep secret |
| `MCP_PORT` | `3002` | Local port (localhost only) |
| `MCP_LOG_DIR` | `./logs` | Service stdout/stderr log directory |
| `RATE_LIMIT_PER_MIN` | `120` | Max requests per minute per token |
| `AUDIT_MAX_SIZE_MB` | `10` | Audit log rotation threshold |
| `ANTHROPIC_API_KEY` | — | Powers Layer 2/3 AI safety review |
| `BYPASS_BINARIES` | — | `process:category` pairs exempt from blocking (logged as `[SECURITY-BYPASS]`) |
| `LAYER_STRICT_MODE` | false | If true, Layer 2/3 failures block rather than pass-through |

---

## Log Files

| File | Contents |
|------|----------|
| `logs\service-out.log` | stdout from the Node process |
| `logs\service-err.log` | stderr — check here first when troubleshooting |
| `logs\audit.log` | every tool call with tier, blocked status, args (secrets auto-redacted) |

Every audit entry has: timestamp, tool name, security tier, command/args, Layer 1/2/3 decision source, and `[SECURITY-BYPASS]` tag when `BYPASS_BINARIES` matched.

---

## Useful Diagnostic Prompts

```
Show me system info — OS, disk space, memory, running processes
```
```
List what's in [directory path]
```
```
Search for any .env files in [project path]
```
```
Show me the last 50 lines of [log file path]
```
```
What's the git status of [project directory]?
```

---

## Support

- **GitHub Issues:** github.com/ForgeRift/local-terminal-mcp/issues
- **Email:** support@forgerift.io
- **Security:** security@forgerift.io

---

## Memory Prompt

*Paste this into Claude to save this context as a memory (best used with Claude Projects):*

> "Please remember the following about my local-terminal-mcp setup so you can help me manage my Windows machine and troubleshoot issues without me having to re-explain it: [paste this entire document]. Reference this any time I ask about my local machine, Windows commands, file access, or anything related to my ForgeRift plugin. Note: add this to a Claude Project for persistent context — standard memory may not retain the full document across sessions."

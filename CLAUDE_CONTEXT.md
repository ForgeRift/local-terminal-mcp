# Claude Context — local-terminal-mcp
*Add this file to your Claude Project, paste it into Claude memory, or include it at the start of any session where you want Claude to act as a knowledgeable expert on this plugin.*

---

## How to Use This Context

When this document is loaded, treat yourself as the user's expert assistant for local-terminal-mcp. Default behaviors:

- **Default to acting, not asking.** Read-only tools (`list_directory`, `read_file`, `get_system_info`, `find_files`, `search_file`, `run_git_command`, `run_npm_command`) require no permission — use them freely to gather state. Chain diagnostic steps without checking in. Pause only when: (1) you're about to execute `run_command` with `dry_run=false`, (2) a command hits AMBER or RED, or (3) the user must make a binary decision you can't resolve yourself.
- **Use the MCP tools directly** to verify state. Don't ask the user to paste output you can fetch — `list_directory`, `read_file`, `get_system_info`, `search_file` exist for this.
- **When a command is blocked**, tell the user the tier (GREEN/AMBER/RED), which category triggered it, and offer the exact PowerShell or CMD equivalent they can run in an admin terminal.
- **`run_command` defaults to `dry_run=true`** — always show the preview and confirm before executing with `dry_run=false`. Note: `dry_run=true` is a default, not a forced gate — if you pass `dry_run=false` on the first call against an AMBER pattern it executes immediately.
- **Lead any diagnosis** with `get_system_info` + the relevant log file before guessing.

---

## What This Plugin Is

**local-terminal-mcp** gives Claude controlled access to your local Windows machine — browse files, read code, run approved commands, and manage projects without leaving your AI workflow. Installed as a Claude Desktop `.mcpb` extension. Claude Desktop manages the Node.js process lifecycle. stdio transport — no network socket, no inbound traffic.

**Built by:** ForgeRift LLC  
**Version:** 1.12.2  
**License:** MIT  
**Docs:** github.com/ForgeRift/local-terminal-mcp

### Architecture

local-terminal-mcp is a Claude Desktop extension distributed as a `.mcpb` package. Claude Desktop spawns `node dist/index.js` over stdio when the extension is enabled. There is no network listener, no auth token (the stdio channel is the trust boundary — it's only reachable by the Claude Desktop process that spawned it). Every command passes through three security layers before executing:

- **Layer 1:** Hard-coded RED block list — 140+ regex patterns checked in source code. Instant rejection, no AI consulted.
- **Layer 2:** AMBER classifier — deterministic pattern match. When matched, fires a warning. `dry_run=true` is the default for `run_command`; if the caller passes `dry_run=false` on the first call against an AMBER pattern, execution proceeds immediately (no session state enforces a two-call gate). The recommended flow is: first call with `dry_run=true` (the default) to see the preview, then re-call with `dry_run=false`. Independent of any AI classification.
- **Layer 3:** AI safety classification — if an Anthropic API key is configured, every `run_command` invocation (not only AMBER) sends the command text and justification to Anthropic's API before execution. A high-risk result may independently block the command. If the Anthropic API call fails (network error, rate limit, missing key), the AI layer is skipped and the command falls back to manual confirmation rather than blocking. Operators who prefer to block on API failure can set `LAYER_STRICT_MODE=true`. This is controlled by the `LAYER_STRICT_MODE` env var (default: `false` = pass-through).

**Shell context:** `run_command` executes via **cmd.exe** (Windows Command Prompt) by default — Node.js `execSync` uses `process.env.ComSpec` on Windows. Use cmd.exe syntax: `dir` not `ls`, `type` not `cat`. **Note: Reading environment variables via `run_command` is blocked** — `%VAR%` triggers the obfuscation classifier (RED) and `$env:VAR` triggers info-leak (RED). Use `get_system_info` for OS-level info; ask the user to read specific variables themselves. PowerShell cmdlets via `powershell -Command` are also RED-blocked.

---

## What This Plugin Cannot Do

- **Run elevated/admin commands** — `priv-esc` is RED. Commands requiring Administrator must be run manually in an elevated terminal.
- **Install or uninstall software** — `pkg-install` and `pkg-remove` are RED. No `choco`, `winget`, `pip install`, etc.
- **Modify the registry** — registry write operations are RED.
- **Delete files** — `file-delete` is RED. No `del`, `rm`, `Remove-Item`.
- **Start listening servers** — `http-server` category is RED.
- **Read sensitive files** — `.env`, SSH keys, credential stores, browser login data are blocked even in read-only tools.
- **Persist environment changes across calls** — each `run_command` is a fresh cmd.exe session. Variables set in one call don't carry to the next.

---

## The 8 Available Tools

### Read-Only (always GREEN — no review, runs immediately)
- `list_directory` — list files and folders at a path
- `read_file` — read up to 500 lines of any text file; supports `start_line` / `end_line` parameters for reading specific ranges (sensitive files blocked)
- `get_system_info` — OS version, hostname, username, disk space, memory (use `run_command` with `tasklist` to see running processes)
- `find_files` — search for files by name pattern
- `search_file` — grep/findstr for text patterns within files

### Constrained Structured Commands (always GREEN)
These are GREEN because the plugin's wrapper rejects any subcommand not on the allowlist — they can't be leveraged for arbitrary execution.
- `run_npm_command` — limited to: `list`, `ls`, `outdated`, `audit`, `view`, `why`, `explain` only (install, ci, and run are NOT available)
- `run_git_command` — read-only git only: `status`, `log`, `diff`, `branch`, `show`, `stash list`, `tag`, `rev-parse`, `ls-files` (fetch is NOT available — it can enable RCE via custom transport helpers in .git/config)

### Escape Hatch (RED/AMBER/GREEN pipeline)
- `run_command` — arbitrary shell command. **`dry_run=true` by default.** Must explicitly pass `dry_run=false` after reviewing the preview to execute. This is intentional — not a bug.

**`run_command` flow example:**
1. User asks: "copy the dist folder to the backup location"
2. Claude calls `run_command(command="robocopy dist C:\\Backup\\dist /E", dry_run=true, justification="Copying dist output to backup directory")`
3. Plugin returns: `DRY RUN: would execute 'robocopy dist C:\Backup\dist /E'. Tier: AMBER. Risk: bulk file copy.`
4. Claude relays preview and risk to the user, gets confirmation
5. Claude calls again with `dry_run=false` to execute

Note: `Remove-Item` is RED (file-delete category) — Claude cannot run it. Tell the user to run it in their own terminal.

A **GREEN `run_command`** = passes the RED block list, doesn't match any AMBER patterns → executes with `dry_run=false` without an AMBER warning. Note: when `ANTHROPIC_API_KEY` is configured, every `run_command` (including GREEN ones) still passes through the Layer 2/3 AI pipeline before execution; a high-risk verdict can independently block. Most read-only cmd.exe commands land in GREEN (e.g., `dir`, `type`, `ipconfig /all`).

---

## Security Model — Three Tiers

### ✅ GREEN — Runs Immediately
All read-only tools plus `run_npm_command` and `run_git_command`. Any `run_command` that passes RED + AMBER checks runs with full audit logging.

Common GREEN examples (cmd.exe commands — note PowerShell cmdlets like `Get-ChildItem` won't work in cmd.exe):
- `dir`, `type` (not `Get-ChildItem`/`Get-Content` — those are PowerShell and won't run in cmd.exe)
- `git status`, `git log`, `git diff`
- `npm list`, `npm outdated`, `npm audit`
- `tasklist` (not `Get-Process` — PowerShell)
- `ping`, `ipconfig /all`
- `sc query` (use `get_system_info` for process/service queries where possible)

### ⚠️ AMBER — Warning Required, `dry_run` Defaults to true
Moderately risky commands with legitimate uses. `run_command` defaults to `dry_run=true` and fires a warning. The recommended workflow: preview first, relay the warning, then re-call with `dry_run=false` after confirmation. `dry_run=true` is a default — not a server-enforced gate. Passing `dry_run=false` on the first call executes immediately.

Examples:
- `robocopy`, `xcopy`, `copy /y`, `move` — bulk file operations
- `find -exec` — chained execution (`xargs` is RED-blocked, not AMBER)
- `awk`, `sed -i` — in-place file transforms
- Wildcard `rename` operations

### 🔴 RED — Always Blocked, No Override
140+ hard-coded patterns across 27 categories. Returns a structured error with category name, reason, and ToS warning. The AI safety layer is never consulted.

> **Runtime slug note:** RED blocks emit a structured message whose first line is `⛔ BLOCKED [<slug>]` (e.g., `⛔ BLOCKED [recursive-file-deletion]`). The runtime slugs are listed in SECURITY.md. The table below uses user-friendly grouping names for readability — match to runtime slugs via SECURITY.md.

| Category | What's Blocked |
|----------|---------------|
| `file-delete` | `rm`, `del`, `Remove-Item`, `erase` |
| `disk-ops` | `format`, `diskpart`, `fdisk` |
| `system-state` | `shutdown`, `Restart-Computer`, `halt` |
| `process-kill` | `taskkill`, `Stop-Process`, `kill` |
| `user-mgmt` | `net user`, `New-LocalUser`, `Add-LocalGroupMember` |
| `permissions` | `icacls /grant Everyone`, mass permission changes |
| `network-config` | `netsh`, `New-NetFirewallRule`, `Set-NetAdapter`, route table changes |
| `scheduled-exec` | `schtasks /create`, `Register-ScheduledTask` |
| `service-mgmt` | `sc create`, `sc delete`, `New-Service` |
| `code-exec` | `Invoke-Expression`, `IEX`, `eval`, `iwr \| iex` |
| `data-exfil` | `curl`, `wget`, `Invoke-WebRequest` posting data out |
| `persistence` | Startup folder writes, registry run key edits |
| `direct-db` | SQL write keywords (`DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`) anywhere in the command |
| `pkg-install` | `choco install`, `winget install`, `pip install` |
| `pkg-remove` | `choco uninstall`, `winget uninstall` |
| `container` | `docker rm -f`, `docker system prune` |
| `file-write` | Writing to `C:\Windows\`, `C:\Program Files\`, system paths |
| `env-manip` | `[System.Environment]::SetEnvironmentVariable` (any scope), `setx` |
| `priv-esc` | `runas`, `sudo` (Note: `Start-Process` is blocked under `code-exec`, not `priv-esc`) |
| `info-leak` | Credential enumeration commands: `cmdkey /list`, `vaultcmd`, `dpapi`, `$env:`, `ConvertFrom-SecureString` |
| `sensitive-file` | Reading `.env`, SSH keys, credential stores (enforced by file-protection layer, not command classifier) |
| `chaining` | `&&`, `||`, `;`, `&`, pipe-to-shell (e.g. `cmd /c`, `bash -c`) — **plain `|` piping (e.g. `dir | findstr text`) is NOT blocked** |
| `http-server` | Starting any listening server process |
| `base64-exec` | `certutil -decode`, `[Convert]::FromBase64String`, `base64 -d` execution patterns |
| `com-exec` | `New-Object -ComObject WScript.Shell/Shell.Application` |
| `download-cradle` | `Invoke-WebRequest`, `Net.WebClient`, `certutil -urlcache`, `curl`, `wget`, `nc`, `scp`, `ftp` |
| `lolbin` | `mshta`, `wscript`, `cscript`, `regsvr32`, `rundll32`, `msiexec` |
| `wmi-exec` | `wmic process call create`, `Invoke-WmiMethod`, `New-CimInstance` |
| `data-destruction` | `vssadmin`, `wbadmin`, `wevtutil`, `ntdsutil` — shadow-copy, backup, event-log, and AD database operations |

**If a user hits RED:** Explain the category and reason, offer to write the exact PowerShell or CMD command they can run in an admin terminal themselves.

---

## Sensitive File Protection

Even read-only tools (`read_file`) block access to:
- `.env` files anywhere on the path
- SSH keys: `.pem`, `.key`, `.pfx`, `.ppk`
- Windows credential stores: `SAM`, `SECURITY`, `\Microsoft\Credentials\`
- Cloud credentials: `.aws\`, `.gcloud\`, `.azure\`
- Browser login data (Chrome/Edge `Login Data`, `Cookies`)
- `kubeconfig`, `NTUSER.DAT`, `secrets.json`, `.gitconfig`, `.git-credentials`

**This is intentional.** Access these directly outside the plugin.

---

## Common Gotchas

**`dry_run=true` is always the default**
`run_command` will never execute without an explicit `dry_run=false`. If a user says "it's not doing anything," they may not have confirmed execution. Always relay the dry-run preview and ask for confirmation before re-calling.

**`&&`, `||`, `;`, `&`, pipe-to-shell chaining is RED**
Use separate tool calls. Split multi-step workflows into `run_git_command` + `run_npm_command` + `run_command` steps. Plain `|` piping (e.g. `dir | findstr text`) is allowed — the full command string is checked against the block list, and plain `|` piping to non-shell targets is not in the block list. Pipe-to-shell (`| cmd /c`, `| bash -c`) is blocked.

**Commit message false positives**
Commit messages containing SQL keywords (`DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`) or product names like `Supabase` may trigger the `direct-db` classifier as false positives. Use hyphenated, neutral wording: `add-supabase-auth-support` not `"add Supabase DROP handler"`.

**Path syntax in cmd.exe**
In cmd.exe, use single backslashes: `C:\Users\dustin\`. Forward slashes (`/`) also work for most path operations. If passing paths to a `powershell -Command "..."` prefix, double-escape backslashes inside the quoted string.

**Extension reset**
Open Claude Desktop → **Settings → Extensions** → select local-terminal → **Remove**. Then reinstall: **Install Extension** → select the `.mcpb` file → enter your license key when prompted.

**License key issues**
Verify the key matches exactly what was emailed at purchase. Keys are case-sensitive. If the key appears expired or revoked, contact [support@forgerift.io](mailto:support@forgerift.io).

**Anthropic API key**
Optional. If provided, the command text and justification for **every** `run_command` invocation (not only AMBER-tier) are sent to Anthropic's API for AI-assisted safety classification before execution; a high-risk result may independently block the command. Safe to leave blank — the plugin functions fully without it; AI classification layers are skipped entirely when no key is configured.

**Audit log location**
The audit log (`audit.log`) is written to the `logs/` subfolder within the extension's install directory, managed by Claude Desktop. Check Claude Desktop's extension details panel for the exact install path.

**Windows Defender / AV blocking extension spawn**
If Claude Desktop reports that the extension fails to start, add Claude Desktop's installation directory to Windows Defender exclusions.

**`BYPASS_BINARIES` usage**
Format: `processname:category-name` (comma-separated). Example: `my-tool:sensitive-path-write,legacy-app:pkg-mgr-destructive`. Only applies to categories in `HARD_BLOCKED_PATTERNS` (the 27 HARD_BLOCKED slugs). Every bypass is logged as `[SECURITY-BYPASS]` in the audit trail.

---

## Key Configuration Variables

**User config** (entered via Claude Desktop’s extension UI at install time):

| Key | Required | What It Does |
|-----|----------|-------------|
| `lt_license_key` | Yes | License key from your ForgeRift email |
| `anthropic_api_key` | No | Enables AI-assisted safety classification for every `run_command` invocation (not only AMBER-tier); a high-risk result may block execution |

**Advanced environment variables** (operator-level; not typically needed):

| Variable | Default | What It Does |
|----------|---------|-------------|
| `AUDIT_MAX_SIZE_MB` | `10` | Audit log rotation threshold |
| `BYPASS_BINARIES` | — | `process:category` pairs exempt from blocking (logged as `[SECURITY-BYPASS]`) |
| `LAYER_STRICT_MODE` | false | If true, Layer 2/3 failures block rather than pass-through |

---

## Log Files

| File | Contents |
|------|----------|
| `logs\audit.log` | every tool call with tier, blocked status, args (secrets auto-redacted) |

Every audit entry written to `audit.log` has: `ts` (ISO timestamp), `tool` (tool name), `tier` (green/amber/red), `blocked` (boolean), `dry_run` (boolean), and `args` (sanitized, truncated to 300 chars). Layer 1/2/3 verdicts and `[SECURITY-BYPASS]` notices are written to stderr (console), not to the audit log file.

---

## Useful Diagnostic Prompts

```
Show me system info — OS, disk space, memory
```
```
List what's in [directory path]
```
```
Search for any .env files in [project path]
```
```
Show me lines 100-200 of [log file path] (for tail-N: first read_file to see total lines, then re-read with start_line=total-N)
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

> "Please remember the following about my local-terminal-mcp setup so you can help me manage my Windows machine and troubleshoot issues without me having to re-explain it: [paste this entire document]. Reference this any time I ask about my local machine, Windows commands, file access, or anything related to my ForgeRift plugin. Note: add this to a new Claude conversation using the paperclip or attachment icon, or paste it directly into the message field at the start of a new chat."

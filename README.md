# local-terminal-mcp

© 2026 ForgeRift LLC — Wisconsin limited liability company

Give Claude controlled access to your local Windows machine — browse files, read code, run approved commands, and manage projects without leaving your AI workflow.

Runs as a Windows Service so Claude stays connected across sessions. All commands pass through a three-tier security model (RED/AMBER/GREEN). Destructive patterns are hard-blocked server-side. Every call is audit-logged.

---

## What it does

Claude gets eight tools across three safety tiers:

**GREEN Tier — Read-only (always safe)**
- `list_directory` — list files and folders
- `read_file` — read up to 500 lines of any text file (sensitive files blocked)
- `get_system_info` — OS version, disk space, memory, running processes
- `find_files` — search for files by name pattern
- `search_file` — grep/findstr for text patterns in files

**GREEN Tier — Approved commands**
- `run_npm_command` — read-only npm: `list`, `outdated`, `audit`, `view`, `why`, `explain` (lifecycle scripts disabled — `npm run` / `install` / `ci` are blocked)
- `run_git_command` — read-only git: `status`, `log`, `diff`, `branch`, `show`, `stash list`, `tag`, `rev-parse`, `ls-files` (`fetch` is blocked — it can trigger transport helpers)

**Escape Hatch (RED/AMBER checked)**
- `run_command` — arbitrary shell command. `dry_run=true` by default. Passes through RED → AMBER → GREEN pipeline before execution.

---

## Three-Tier Security Model

### RED — Hard-Blocked (150+ patterns, 22 categories)

Commands that are permanently blocked regardless of context. Returns structured error with category, reason, and Terms of Service warning.

**Categories:** file-delete, disk-ops, system-state, process-kill, user-mgmt, permissions, network-config, scheduled-exec, service-mgmt, code-exec, data-exfil, persistence, direct-db, pkg-install, pkg-remove, container, file-write, env-manip, priv-esc, info-leak, chaining, http-server.

Examples: `rm`, `del`, `format`, `shutdown`, `taskkill`, `reg delete`, `curl`, `wget`, `Invoke-Expression`, `runas`, `schtasks`, `sc create`, `netsh`, `choco install`.

### AMBER — Warning-Required

Moderately risky commands with legitimate use cases. Forces `dry_run=true` with a warning. Must re-call with `dry_run=false` to execute.

Examples: `find -exec`, `xargs`, `robocopy`, `xcopy`, `move`, wildcard `rename`.

### GREEN — Allowed with Audit

All structured tools and any `run_command` that passes RED + AMBER checks.

---

## Sensitive File Protection

Even read-only tools block access to credential and secret files:

`.env`, SSH keys, `.pem`/`.key`/`.pfx`, Windows credential stores (`SAM`, `SECURITY`, `\Microsoft\Credentials`), cloud credentials (`.aws/`, `.gcloud/`, `.azure/`, `.terraformrc`), browser login data (`Login Data`, `Local State`), `kubeconfig`, `NTUSER.DAT`, `secrets.json`, `.git-credentials`, package manager tokens (`.npmrc`, `.pypirc`, `.netrc`), shell history, KeePass databases, crypto wallets, and more (50+ patterns).

---

## Infrastructure Hardening

| Feature | Details |
|---|---|
| **Rate limiting** | 120 req/min per token (configurable via `RATE_LIMIT_PER_MIN`) |
| **Request timeout** | 30s hard kill on all commands |
| **Audit log rotation** | 10MB max, one `.old` backup (configurable via `AUDIT_MAX_SIZE_MB`) |
| **CORS** | Permissive headers for Cowork/Desktop integration |
| **Secret redaction** | Token shapes redacted from tool output and audit logs (`ghp_`, `sk-`, `AKIA`, PEM headers, high-entropy base64) |
| **Localhost-only** | Binds to `127.0.0.1` — not reachable from network |

---

## Compatibility

**Windows only.** Works with Claude Desktop (Windows) and Cowork. Does not work with Claude in Chrome, claude.ai web, or mobile — the plugin runs as a localhost-only Windows Service and cannot be reached from a browser or remote client.

If you need remote Linux server access instead of local Windows access, see [vps-control-mcp](https://github.com/forgerift/vps-control-mcp).

## Requirements

- Windows 10 / 11
- [Git](https://git-scm.com/download/win) (for cloning the repo)
- [Node.js](https://nodejs.org) v18 or later
- PowerShell (run as Administrator for setup)

---

## Installation

```powershell
# 1. Clone the repo
git clone https://github.com/forgerift/local-terminal-mcp
cd local-terminal-mcp

# 2. Run the installer as Administrator
.\setup.ps1
```

`setup.ps1` will:
- Verify Git and Node.js v18+ are installed (exits with a clear error if not)
- Build the project
- Install `mcp-remote` globally (the bridge Claude Desktop uses to connect)
- Generate a random auth token and save it to `.env`
- Download NSSM and install `local-terminal-mcp` as a Windows Service
- Configure auto-restart on crash (3s delay)
- Write the MCP entry directly into your Claude Desktop config (creates the file and directory if they don't exist yet)

Then restart Claude Desktop — the plugin will appear as connected.

---

## Updating

```powershell
git pull
.\setup.ps1
```

Re-running `setup.ps1` stops and removes the existing service, installs the new version, and restarts — your `.env` (auth token) is preserved.

---

## Uninstalling

```powershell
.\uninstall.ps1
```

Stops and removes the service, prompts before deleting the install directory, and reminds you to clean up `claude_desktop_config.json`.

---

## Configuration

All settings live in `.env` (auto-generated by `setup.ps1`):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token required on every request |
| `MCP_PORT` | `3002` | Local port (localhost-only) |
| `MCP_LOG_DIR` | `./logs` | Directory for service stdout/stderr logs |
| `RATE_LIMIT_PER_MIN` | `120` | Max requests per minute per token |
| `AUDIT_MAX_SIZE_MB` | `10` | Audit log max size before rotation |

---

## Logs

| File | Contents |
|---|---|
| `logs/service-out.log` | stdout from the Node process |
| `logs/service-err.log` | stderr from the Node process |
| `logs/audit.log` | every tool call with tier, blocked status, and args |

---

## License

MIT — ForgeRift LLC 2026

# CMD Connector — Marketplace Listing

## Product Overview

**CMD Connector** gives Claude secure, audited access to your local Windows machine. Browse files, read code, run approved commands, and manage development projects without leaving your AI workflow—all with industry-grade command authorization and credential protection.

Runs as a Windows Service so Claude stays connected across sessions. Every command passes through a three-tier security model with 120+ hard-blocked dangerous patterns. Full audit logging of every interaction.

## Key Features

- **Three-Tier Command Authorization** — RED (hard-blocked), AMBER (warning-required), GREEN (allowed). 120+ security patterns across 20 categories prevent file deletion, privilege escalation, credential theft, and data exfiltration.

- **Sensitive File Protection** — Blocks access to `.env` files, SSH keys, Windows credential stores, browser login data, cloud credentials, and more—even through read-only tools.

- **Audit Logging** — Every tool call logged with timestamp, security tier, blocked status, and arguments. Secrets auto-redacted. Logs rotate at 10MB with one backup retained.

- **Rate Limiting** — 120 requests per minute per token. Prevents brute-force probing.

- **Request Timeout** — 30-second hard kill on all commands. No hung processes.

- **Windows Service Infrastructure** — Auto-restarts on crash. Persistent connection. Zero configuration after setup.

- **CORS Integration** — Works seamlessly with Claude Desktop and Cowork.

## What Claude Can Do

Eight tools across three tiers:

**Read-Only (Always Safe)**
- List files and folders
- Read text files (up to 500 lines, with sensitive file protection)
- Get system info (OS, disk, memory, processes)
- Find files by pattern
- Search within files

**Approved Commands**
- `npm install`, `npm run`, `npm list` (package management)
- Git read-only operations: `status`, `log`, `diff`, `branch`, `fetch`

**Escape Hatch**
- Run arbitrary shell commands via `run_command` (RED/AMBER/GREEN filtered, `dry_run=true` by default)

## Requirements

- Windows 10 / 11
- Node.js v18 or later
- PowerShell (Administrator for setup)

## Quick Start

```powershell
# 1. Clone the repo
git clone https://github.com/claudedussy/local-terminal-mcp
cd local-terminal-mcp

# 2. Run the installer as Administrator
.\setup.ps1
```

The installer will:
- Build the project
- Generate a random auth token and save it to `.env`
- Install `local-terminal-mcp` as a Windows Service with auto-restart
- Print the `claude_desktop_config.json` snippet (copy this into Claude Desktop config)

Restart Claude Desktop, and you're connected.

## Configuration

All settings live in `.env` (auto-generated):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token for all requests |
| `MCP_PORT` | `3002` | Local port (localhost-only) |
| `MCP_LOG_DIR` | `./logs` | Audit and service logs |
| `RATE_LIMIT_PER_MIN` | `120` | Max requests per minute |
| `AUDIT_MAX_SIZE_MB` | `10` | Audit log rotation threshold |

## Security Highlights

- **No network exposure** — Binds to `127.0.0.1` only. Not reachable from the network.
- **Hard command blocks** — 120+ dangerous patterns permanently blocked. No bypass flags, no admin override.
- **Credential protection** — Sensitive files blocked at the filesystem level, even in read-only tools.
- **Audit trail** — Every call logged with full context. Secrets auto-redacted.
- **Responsible disclosure** — Report security issues to security@sharpedge.io (90-day responsible disclosure).

## Updating

```powershell
git pull
.\setup.ps1
```

Re-running `setup.ps1` preserves your auth token and restarts the service with new code.

## Uninstalling

```powershell
.\uninstall.ps1
```

Removes the Windows Service. Config is preserved if you want to reinstall later.

## Support & Security

- **Documentation** — See README.md and SECURITY.md in the repository
- **Issues** — Report bugs via GitHub issues
- **Security** — Report vulnerabilities to security@sharpedge.io

## License

MIT — SharpEdge 2026

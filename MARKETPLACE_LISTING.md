# local-terminal-mcp — Marketplace Listing


## Product Overview

![local-terminal tools panel](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_01_tools.gif)

**local-terminal-mcp** gives Claude secure, audited access to your local Windows shell. Browse files, read code, run approved commands, and manage development projects from Cowork — without ever handing Claude an unguarded terminal.

Runs as a Windows Service so Claude stays connected across sessions. Every command passes through a three-tier security model with 450+ hard-blocked dangerous patterns. Full audit logging. No network exposure — binds to `127.0.0.1` only.

## Key Features

- **Three-Tier Command Authorization** — RED (hard-blocked), AMBER (warning-required), GREEN (allowed with audit). 450+ security patterns across 27 categories prevent file deletion, privilege escalation, credential theft, and data exfiltration.

- **Sensitive File Protection** — Blocks reads of `.env`, SSH keys, Windows credential stores, browser login data, cloud credentials, and more — even through read-only tools.

- **Audit Logging** — Every tool call logged with timestamp, security tier, blocked status, and arguments. Secrets auto-redacted via regex. Logs rotate at 10MB with one backup retained.

- **Rate Limiting** — 120 requests per minute per token. Prevents brute-force probing.

- **Request Timeout** — 30-second hard kill on all commands. No hung processes.

- **Windows Service Infrastructure** — Auto-restarts on crash. Persistent connection. Zero configuration after setup.

- **Twelve Adversarial Review Rounds** — Hardened against 80+ filed bypass findings (F-OP-1 through F-OP-85). Every closure is documented in `ADVERSARIAL_REVIEW.md`.

## What Claude Can Do

![Directory listing and search demo](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_03_search.gif)

Eight tools across three tiers:

**Read-only tools (always safe)**
- List files and folders
- Read text files (up to 500 lines, with sensitive-file protection)
- Get system info (OS, disk, memory, processes)
- Find files by pattern
- Search within files

**Approved commands**
- `npm install`, `npm run`, `npm list` (package management)
- Git read-only operations: `status`, `log`, `diff`, `branch`, `fetch`

**Escape hatch**
- Run arbitrary shell commands via `run_command` (RED/AMBER/GREEN filtered, `dry_run=true` by default)

## Requirements

- Windows 10 / 11
- Node.js v18 or later
- PowerShell (Administrator for setup)

## Quick Start

```powershell
# 1. Clone the repo
git clone https://github.com/ForgeRift/local-terminal-mcp
cd local-terminal-mcp

# 2. Run the installer as Administrator
.\setup.ps1
```

The installer:
- Builds the project
- Generates a random auth token and saves it to `.env`
- Installs `local-terminal-mcp` as a Windows Service with auto-restart
- Prints the `claude_desktop_config.json` snippet — copy it into Claude Desktop config

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

![RED-tier block demo](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_04_red-block.gif)

## Security Highlights

- **No network exposure** — Binds to `127.0.0.1` only. Not reachable from the network.
- **Hard command blocks** — 450+ dangerous patterns permanently blocked across 27 categories. Operator override available via `BYPASS_BINARIES` env var for legitimate admin workflows; every bypass is logged as `[SECURITY-BYPASS]`.
- **Credential protection** — Sensitive files blocked at the filesystem level, even in read-only tools.
- **Audit trail** — Every call logged with full context. Secrets auto-redacted.
- **Responsible disclosure** — Report security issues to `security@forgerift.io` (90-day responsible disclosure).

See `SECURITY.md` for the full threat model and the S65 adversarial-review trail.

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

## Pricing

| Plan | Monthly | Annual |
|------|---------|--------|
| Individual (this plugin) | $14.99/mo | $149/yr |
| Bundle (both plugins) | $19.99/mo | $199/yr |

**14-day free trial** included. No charge during trial period. No refunds after trial ends.

**Founder Cohort:** First 100 subscribers or 3 months post-marketplace approval (whichever comes first) lock in $9.99/mo (individual) or $14.99/mo (bundle) for life.

See [forgerift.io/#pricing](https://forgerift.io/#pricing) for full details.

## Support & Security

- **Documentation** — See `README.md`, `SECURITY.md`, and `TROUBLESHOOTING.md` in the repository.
- **Issues** — Report bugs via GitHub issues.
- **Security** — Report vulnerabilities to `security@forgerift.io`.

## License

Source available under the [Business Source License 1.1](LICENSE) (BUSL 1.1). Converts to MIT four years after each version's release date.

# local-terminal-mcp — Marketplace Listing

## Product Overview

![local-terminal tools panel](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_01_tools.gif)

**Tagline:** *Claude with access to your Windows machine — your files never leave it.*

We run the safe tasks automatically so you don't have to.

Reading files, checking logs, running builds, searching your codebase — Claude handles those directly from the conversation, no copy-pasting required. High-risk operations (file deletion, software installs, registry changes, and more) stay permanently blocked and in your hands by design. When Claude hits one, it tells you exactly what to run yourself and why.

Secure, audited access to your local Windows shell. 450+ permanently blocked dangerous patterns. Runs as a Windows Service, bound to localhost only — nothing is reachable from outside your machine.

---

## What Claude Can Do

![Directory listing and search demo](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_03_search.gif)

- **Read your project files** — browse directories, read source files and configs, search by pattern
- **Run builds** — `npm install`, `npm run build`, `npm test`, without leaving Claude
- **Check git state** — status, log, diff, branch listing — instant project context for every conversation
- **Get system info** — disk, memory, running processes
- **Find things fast** — search file contents across your project for functions, variables, error messages
- **Run approved commands** — filtered through the same RED/AMBER/GREEN tier system, `dry_run=true` by default

**Full tool list:** `list_directory`, `read_file`, `find_files`, `search_file`, `get_system_info`, `run_command`, `run_git_command`, `run_npm_command`

---

## Why Direct Access Changes How You Use Claude

Without a plugin, every Claude conversation about your machine is a relay race. You describe a problem, Claude asks what's in the log, you paste the log, Claude asks for a config file, you paste that, Claude suggests a command, you run it, paste the output back. A lot of that time gets spent figuring out *what Claude is asking for* — not reading the answer.

Direct access breaks that loop. Claude reads the log itself. Checks the config. Scans the directory. Gets the full picture in one step instead of four rounds of back-and-forth. For large outputs — full build logs, long stack traces, directory listings — the difference is especially significant: no truncated pastes, no guessing what context Claude needs, no token overhead from repeatedly re-explaining what you're looking at.

The result: you describe what's wrong once. Claude figures out what to look at, reads it, diagnoses the problem, and either tells you what's happening or just fixes it. That's the whole idea.

**The honest caveat:** This plugin dramatically reduces copy-paste for most workflows — but not to zero. A defined set of operations (file deletion, software installation, registry writes, and other high-risk actions) are permanently blocked and will always require you to run them yourself in a terminal. When Claude hits one of those, it tells you exactly what to run and why it can't do it for you. For reading files, checking logs, running builds, diagnosing errors, and managing projects, Claude handles it without your intervention. For anything in the dangerous category, you stay in control by design.

---

## Not a Developer? This Is Still for You.

If you use Claude to help you with work — writing, research, projects, spreadsheets — you've probably wished Claude could just *look at the file* instead of you copying and pasting it in. Or run something for you instead of telling you what to type.

local-terminal-mcp gives Claude access to your Windows computer so it can do that. It can open files, read them, search through folders, run tasks. You don't paste anything. You just ask.

**The part people worry about:** what if it does something I didn't want? Claude cannot delete your files. Cannot send your files anywhere. Cannot access your passwords, your browser data, your SSH keys, your cloud credentials — those are blocked at the file level, not just by instruction. It can look at what you point it at and run what you approve. It can't go rogue.

**A realistic example:** You're working on a project and you say *"check the last 50 lines of the error log in my app folder and tell me what's going wrong."* Claude reads it, tells you what's wrong, and suggests a fix — without you copying anything. That's the whole idea.

---

## Developers — Here's What's Actually Under the Hood.

![RED-tier block demo](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_04_red-block.gif)

**Security architecture:** Same three-tier RED/AMBER/GREEN model as vps-control-mcp, adapted for Windows. Static pattern matching + allowlist-based command gating, both layers required. 450+ hard-blocked patterns across 27 categories. stdio transport — no network socket, no port exposure.

**Blocked surface highlights:** Recursive deletion (`rm -rf` equivalents, `Remove-Item -Recurse`), PowerShell execution policy bypass, credential store access (Windows Credential Manager, DPAPI), browser login data (`Login Data`, `Cookies`, Chrome/Edge/Firefox profile paths), registry writes, scheduled task creation, UAC bypass patterns, Windows Defender modification, and network pivot commands.

**Windows Service infrastructure:** Runs as a persistent Windows Service via `node-windows`. Auto-restarts on crash. Survives session logoff. No manual restart needed after system reboot. Service name: `LocalTerminalMCP`.

**Sensitive file protection:** Blocked at the read level in all tools — not just `run_command`. `.env`, SSH keys (`id_rsa`, `id_ed25519`), Windows credential stores, browser login data, cloud credentials (`.aws/`, `.azure/`, `.gcloud/`), npm/yarn auth tokens, and shell configs that commonly contain exported secrets.

**Audit trail:** Structured JSON, secret auto-redaction via expanded prefix + key-name regex, 10MB rotation with one backup. Stored locally at `MCP_LOG_DIR`.

**Adversarial review:** 13 rounds, 419/419 tests pass. LT-specific findings (F-LT series) documented in `ADVERSARIAL_REVIEW.md`. Shares the same security architecture and findings database as vps-control-mcp.

**Scope limitation by design:** No network calls, no outbound requests, no file writes outside `run_command` (which is itself filtered). The plugin surface is read + gated-execute only. Nothing leaves your machine.

**License:** MIT. Full source at [github.com/ForgeRift/local-terminal-mcp](https://github.com/ForgeRift/local-terminal-mcp).

---

## Requirements

- Windows 10 / 11
- Node.js v18 or later
- PowerShell (Administrator for setup)
- Claude Desktop + Cowork

---

## Quick Start

```powershell
git clone https://github.com/ForgeRift/local-terminal-mcp
cd local-terminal-mcp
.\setup.ps1
```

Run as Administrator. The installer builds the project, generates a random auth token, installs `local-terminal-mcp` as a Windows Service with auto-restart, and prints the `claude_desktop_config.json` snippet. Copy it into Claude Desktop config, restart Claude. Connected.

---

## Configuration

All settings live in `.env` (auto-generated by `setup.ps1`):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token for all requests |
| `MCP_PORT` | `3002` | Local port (localhost-only) |
| `MCP_LOG_DIR` | `./logs` | Audit and service logs |
| `RATE_LIMIT_PER_MIN` | `120` | Max requests per minute |
| `AUDIT_MAX_SIZE_MB` | `10` | Audit log rotation threshold |

---

## Pricing

| Plan | Monthly | Annual |
|------|---------|--------|
| Individual (this plugin) | $14.99/mo | $149/yr |
| Bundle (both plugins) | $19.99/mo | $199/yr |

**14-day free trial** included. No charge during trial period. No refunds after trial ends.

**Founder Cohort:** First 100 subscribers or 3 months post-marketplace approval (whichever comes first) lock in $9.99/mo (individual) or $14.99/mo (bundle) for life.

See [forgerift.io/#pricing](https://forgerift.io/#pricing) for full details.

---

## Support & Security

- **Documentation** — `README.md`, `SECURITY.md`, `TROUBLESHOOTING.md`
- **Issues** — [github.com/ForgeRift/local-terminal-mcp/issues](https://github.com/ForgeRift/local-terminal-mcp/issues)
- **Security** — `security@forgerift.io` (90-day responsible disclosure)
- **General** — `support@forgerift.io`

---

## License

Released under the [MIT License](LICENSE).

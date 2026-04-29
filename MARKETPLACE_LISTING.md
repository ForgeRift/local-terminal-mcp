# local-terminal-mcp — Marketplace Listing

## Product Overview

![local-terminal tools panel — Claude Desktop showing all 8 plugin tools in the tool list](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_01_tools.gif)

**Tagline:** *Claude with access to your Windows machine — your files never leave it.*

*ForgeRift LLC is an independent third-party developer and is not affiliated with, endorsed by, or sponsored by Anthropic PBC.*

Claude runs the safe tasks for you — you stay in control of the rest.

Reading files, checking logs, running builds, searching your codebase — Claude handles those directly from the conversation, no copy-pasting required. High-risk operations (file deletion, software installs, registry changes, and more) stay permanently blocked and in your hands by design. When Claude hits one, it tells you exactly what to run yourself and why.

Secure, audited access to your local Windows shell. 140+ permanently blocked dangerous patterns. stdio transport — no inbound network socket, no inbound port exposure, no inbound surface. (Two outbound HTTPS flows documented in README.)

---

## What Claude Can Do

![Directory listing and search demo — Claude listing a project directory and running a pattern search across source files](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_03_search.gif)

- **Read your project files** — browse directories, read source files and configs, search by pattern
- **Inspect packages** — `npm list`, `npm ls`, `npm outdated`, `npm audit` — dependency and security snapshots without leaving Claude
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

![RED-tier block demo — Claude attempting a blocked command and receiving a structured RED-tier error with category and reason](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_04_red-block.gif)

**Security architecture:** Same three-tier RED/AMBER/GREEN model as vps-control-mcp, adapted for Windows. Static pattern matching + allowlist-based command gating, both layers required. 140+ hard-blocked patterns across 27 categories. stdio transport — no inbound network socket, no inbound port exposure.

**Blocked surface highlights:** Recursive deletion (`rm -rf` equivalents, `Remove-Item -Recurse`), PowerShell execution policy bypass, credential store access (Windows Credential Manager, DPAPI), browser login data (`Login Data`, `Cookies`, Chrome/Edge/Firefox profile paths), registry writes, scheduled task creation, UAC bypass patterns, Windows Defender modification, and network pivot commands.

**Lifecycle:** Installed as a Claude Desktop `.mcpb` extension. Claude Desktop spawns `node dist/index.js` over stdio and manages restart on crash. No network port opened, no inbound traffic. One outbound HTTPS call is made at startup to ForgeRift's license validation endpoint to verify your subscription; if unreachable, the plugin fails closed.

**Sensitive file protection:** Blocked at the read level in all tools — not just `run_command`. `.env`, SSH keys (`id_rsa`, `id_ed25519`), Windows credential stores, browser login data, cloud credentials (`.aws/`, `.azure/`, `.gcloud/`), npm/yarn auth tokens, and shell configs that commonly contain exported secrets.

**Audit trail:** Structured JSON, secret auto-redaction via expanded prefix + key-name regex, 10MB rotation with one backup. Stored locally at `logs/audit.log` within the extension's install directory. **Note:** the audit log persists after uninstall — Claude Desktop may not delete the extension's install directory automatically. To remove all traces, delete that directory manually after uninstalling.

**Adversarial review:** Multiple rounds of adversarial testing (F-LT and F-OP findings series). All adversarial review was conducted internally by ForgeRift; no independent third-party audit has been performed. The full review log is available at [ADVERSARIAL_REVIEW.md](https://github.com/ForgeRift/local-terminal-mcp/blob/main/ADVERSARIAL_REVIEW.md). Each finding has a corresponding regression test. Shares the same security architecture and findings database as vps-control-mcp.

**Scope limitation by design:** No file writes outside `run_command` (which is itself filtered). The plugin surface is read + gated-execute only. Two narrow outbound flows exist: your license key is sent to ForgeRift at startup for subscription validation; and, if you supply an optional Anthropic API key, the command text and justification for every `run_command` invocation are sent to Anthropic's API for AI-assisted safety classification before execution.

**AI layer fail-open:** Without an Anthropic API key, or if the Anthropic API call fails (network error, rate limit, invalid key), the AI safety classification layers (Layers 2–3) are silently skipped and the plugin falls back to the static RED hard-block list plus AMBER dry-run warnings only. Set `LAYER_STRICT_MODE=true` as an OS environment variable to make the plugin fail closed on API unavailability instead.

**License:** MIT. Full source at [github.com/ForgeRift/local-terminal-mcp](https://github.com/ForgeRift/local-terminal-mcp).

---

## Requirements

- Windows 10 / 11
- Claude Desktop

---

## Quick Start

Subscribe at [forgerift.io](https://forgerift.io) — you'll receive a `local-terminal.mcpb` file and a license key by email.

In Claude Desktop: **Settings → Extensions → Install Extension** → select the `.mcpb` file → enter your license key when prompted (and an Anthropic API key if you have one — optional, enables AI-assisted safety classification for every `run_command` invocation, not only AMBER-tier). Done.

---

## Configuration

Configuration is entered via Claude Desktop's user_config prompt when you install or reinstall the extension:

| Key | Required | Description |
|---|---|---|
| `lt_license_key` | Yes | License key from your ForgeRift email |
| `anthropic_api_key` | No | Enables AI-assisted safety classification for every `run_command` invocation (not only AMBER-tier); a high-risk result may independently block execution |

---

## Pricing

| Plan | Monthly | Annual |
|------|---------|--------|
| Individual (this plugin) | $14.99/mo | $149/yr |
| Bundle (both plugins) | $19.99/mo | $199/yr |

**14-day free trial** included. No charge during trial period. Subscriptions are otherwise non-refundable except for confirmed ForgeRift billing errors, prorated convenience-termination refunds, and applicable statutory consumer rights — see Terms §6.5.

**Founder Cohort:** Eligibility window closes at the earlier of (a) the 100th paid subscriber or (b) 3 months after the marketplace listing date. Qualifying subscribers lock in $9.99/mo (individual) or $14.99/mo (bundle) for as long as their subscription remains continuously active. Monthly billing only. Not transferable.
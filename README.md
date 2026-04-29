# local-terminal-mcp

[![Version](https://img.shields.io/badge/version-1.12.2-blue.svg)](https://github.com/ForgeRift/local-terminal-mcp)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-hardened-brightgreen.svg)](SECURITY.md)

Give Claude controlled access to your local Windows machine — browse files, read code, run approved commands, and manage projects without leaving your AI workflow.

Installed as a Claude Desktop extension. Lifecycle managed by Claude Desktop — no terminal, no service install, no config files. Arbitrary shell commands pass through a three-tier security model (RED/AMBER/GREEN); structured tools (file ops, git read-ops, npm) bypass classification but enforce sensitive-file guards. Destructive patterns are hard-blocked at the plugin layer. Every call is audit-logged.

![local-terminal tools panel](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_01_tools.gif)

---

## What it does

Claude gets eight tools across three safety tiers:

**GREEN Tier — Read-only (non-destructive)**
- `list_directory` — list files and folders
- `read_file` — read up to 500 lines of any text file; supports `start_line` / `end_line` parameters for reading specific ranges (sensitive files blocked)
- `get_system_info` — OS version, disk space, memory, running processes
- `find_files` — search for files by name pattern
- `search_file` — grep/findstr for text patterns in files

These tools never modify your machine. Note: their output flows to Anthropic as conversation context — the same as anything you type or paste into Claude.

**GREEN Tier — Approved commands**
- `run_npm_command` — read-only npm inspection: `list`, `ls`, `outdated`, `audit`, `view`, `why`, `explain` (npm install, ci, and run are not available — they execute lifecycle scripts)
- `run_git_command` — read-only git: `status`, `log`, `diff`, `branch`, `show`, `stash list`, `tag`, `rev-parse`, `ls-files` (git fetch is not available — it honours custom transport helpers that can enable RCE)

**Escape Hatch (RED/AMBER/GREEN pipeline)**
- `run_command` — arbitrary shell command. Requires a `justification` string describing the task intent. If an Anthropic API key is configured, the command text and justification are sent to Anthropic's API for AI-assisted safety classification on **every** `run_command` invocation (not only AMBER-tier) before execution. `dry_run=true` by default. Passes through RED → AMBER → GREEN pipeline before execution.

![Directory listing and file search demo](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_02_directory-listing.gif)

---

## Three-Tier Security Model

### RED — Hard-Blocked (140+ patterns, 27 categories)

Commands that are permanently blocked regardless of context. Returns structured error with category, reason, and Terms of Service warning.

See [COMMANDS.md](COMMANDS.md) for the full category breakdown.

Examples: `rm`, `del`, `format`, `shutdown`, `taskkill`, `reg delete`, `curl`, `wget`, `Invoke-Expression`, `runas`, `schtasks`, `sc create`, `netsh`, `choco install`.

### AMBER — Warning-Required

Moderately risky commands with legitimate use cases. Forces `dry_run=true` with a warning. Must re-call with `dry_run=false` to execute. If an Anthropic API key is configured, the dry-run output is presented alongside the AI safety classification result (which runs for every `run_command`, not only AMBER-tier) for the user's re-confirmation decision; a high-risk evaluation may independently block execution before the re-confirmation step.

Examples: `find -exec`, `awk`, `sed -i`, `copy /y`, `robocopy`, `xcopy`, `move`, wildcard `rename`. (`xargs` is RED-blocked, not AMBER.)

**API unavailability:** If the Anthropic API call fails (network error, rate limit, or invalid/absent key), AI classification is skipped and AMBER commands fall back to the standard manual dry-run-and-confirm flow without AI assistance. The failure reason is surfaced in the dry-run output so you can see whether AI review ran.

### GREEN — Allowed with Audit

All structured tools and any `run_command` that passes RED + AMBER checks.

**Example — AMBER command in practice:**
*User:* Run `sed -i 's/old/new/g' config.txt`
*Claude (via plugin):* ⚠️ This command matches an AMBER-tier pattern (`sed -i`, in-place file edit). A dry-run preview has been generated — no changes were made. Review the diff above and confirm to proceed, or cancel.
*User:* Looks good, confirm.
*Claude:* ✅ Confirmed. Running command now.

![RED-tier block in action](https://raw.githubusercontent.com/ForgeRift/local-terminal-mcp/main/docs/media/local-terminal_04_red-block.gif)

---

## Sensitive File Protection

Even read-only tools block access to credential and secret files:

`.env`, SSH keys, `.pem`/`.key`/`.pfx`, Windows credential stores (`SAM`, `SECURITY`, `\Microsoft\Credentials`), cloud credentials (`.aws/`, `.gcloud/`, `.azure/`), browser login data, `kubeconfig`, `NTUSER.DAT`, `secrets.json`, `.gitconfig`, `.git-credentials`, and more.

---

## What leaves your machine

Two flows originate from this plugin; the third is Claude Desktop's own conversation flow. The optional Anthropic API flow applies to **all** `run_command` invocations — not just AMBER-tier commands.

**Your license key (plugin → ForgeRift)** — sent to ForgeRift's subscription service (hosted on Supabase — see Privacy Policy §5) at startup to verify your subscription. The key is transmitted as a URL query parameter over HTTPS, which means it may appear in server-side access logs on ForgeRift's infrastructure in addition to the 90-day validation log table. Each validation record (license key + timestamp) is deleted 90 days after it is created. No command output, file contents, audit logs, or in-product usage telemetry are transmitted to ForgeRift.

License keys are scoped exclusively to subscription validation — they grant no access to your machine and carry no account credentials. A leaked key would allow only redundant subscription-check requests. Server access logs containing the key are restricted to ForgeRift personnel. We plan to migrate to an `Authorization: Bearer` header in a future release.

**License server availability:** The validation endpoint is `https://payments.forgerift.io/validate` (a Cloudflare-proxied vanity hostname for ForgeRift's payments service, with subscription records stored in Supabase). The request has a 10-second timeout. If the server is unreachable (network outage, server maintenance, or firewall blocking outbound HTTPS to that host), the plugin **fails closed** — it exits immediately with a "Subscription check timed out" or "Network error" message and Claude loses access to all plugin tools until the plugin is restarted successfully. There is no offline grace period or cached validation.

Fail-closed was chosen deliberately: a tool with shell access to your machine should never silently fall back to an unverified state. ForgeRift operates the validation endpoint on dedicated infrastructure and treats its uptime as a product commitment.

**All `run_command` calls (plugin → Anthropic, optional)** — if you supply an Anthropic API key, **every** shell command submitted via `run_command` is sent to Anthropic's API for AI-assisted safety classification before execution (not only AMBER-tier commands). The command text and user-provided justification are sent; no environment variables, working directory, or other system context is included. A high-risk classification may independently block execution. Each API call consumes tokens billed to your Anthropic account at Anthropic's rates; ForgeRift does not control or receive these charges. This is opt-in; without an API key the AI classification layers are skipped entirely and AMBER commands fall back to manual dry-run-and-confirm.

**Your conversation with Claude (Claude Desktop → Anthropic)** — conversation content, including any command output that Claude reads as context, flows from Claude Desktop to Anthropic per [Anthropic's privacy policy](https://www.anthropic.com/legal/privacy). This is the largest data flow in volume terms. ForgeRift does not receive this data.

This is verifiable in the open-source code at [github.com/ForgeRift/local-terminal-mcp](https://github.com/ForgeRift/local-terminal-mcp). See the [Privacy Policy](https://forgerift.io/privacy.html) for full details.

---

## Infrastructure Hardening

| Feature | Details |
|---|---|
| **Tool-call timeout** | 30s wall-clock hard kill for `run_command`/`run_git_command` invocations; 60s for `run_npm_command` (npm operations can legitimately take longer). Child process receives kill signal on timeout. |
| **Audit log rotation** | 10 MB max, one `.old` backup (`audit.log.old`; prior backup overwritten on each rotation) |
| **Secret redaction** | Tokens, keys, passwords auto-stripped from audit logs. See SECURITY.md for redaction scope and coverage notes. |
| **No inbound network** | Runs as a child process spawned by Claude Desktop over stdio — no inbound network port opened (one outbound HTTPS license-check at startup — see *What leaves your machine* above) |

---

## Requirements

- Windows 10 / 11
- Claude Desktop
- **Network:** Outbound HTTPS to `payments.forgerift.io:443` must be reachable at startup. If your machine sits behind a restrictive corporate proxy or firewall that blocks outbound HTTPS to `payments.forgerift.io`, the plugin will fail to start. Verify reachability before subscribing: `curl -I https://payments.forgerift.io/health` (run in a separate Windows Command Prompt or PowerShell window, not through Claude)
- **To use the plugin:** Claude Desktop only — no Node.js installation needed (Claude Desktop bundles the runtime).
- **To build from source:** Node 18 or later required.

---

## Install

Subscribe at [forgerift.io](https://forgerift.io) — you'll receive a `local-terminal.mcpb` file and a license key by email.

In Claude Desktop, open **Settings → Extensions → Install Extension** and select the `.mcpb` file. Enter your license key when prompted (and an Anthropic API key if you have one — optional, enables AI-assisted safety classification for every `run_command` invocation, not only AMBER-tier).

See [GETTING_STARTED.md](GETTING_STARTED.md) for the step-by-step walkthrough.

---

## Update / Uninstall

Updates and removal are handled by Claude Desktop's Extensions settings — no terminal commands needed.

---

## Building from source

The plugin is MIT-licensed and the source is open for inspection and modification.

The `.mcpb` extension runs inside Claude Desktop's bundled Node.js runtime, which Anthropic maintains and patches — system Node.js is not required to use the plugin. We test against Node 18, 20, and 22, with Node 20 LTS as the primary target. `package.json` declares `engines: { node: ">=18" }` for source-build tooling purposes; this constraint is not relevant when running the `.mcpb` extension because Claude Desktop bundles its own Node runtime.

```bash
git clone https://github.com/ForgeRift/local-terminal-mcp.git
cd local-terminal-mcp
npm install
npm run build        # outputs to dist/
```

The entry point is `dist/index.js`.

---

## Verifying your installation

Official `.mcpb` releases are published on the [GitHub releases page](https://github.com/ForgeRift/local-terminal-mcp/releases) with SHA-256 checksums. To verify the file you received matches the official release, run in PowerShell:

```powershell
Get-FileHash local-terminal.mcpb -Algorithm SHA256
```

Compare the output to the checksum listed on the releases page for your version.

---

## Configuration

Extension configuration is entered via Claude Desktop's user_config prompt when you install or reinstall the extension:

| Key | Required | Description |
|---|---|---|
| `lt_license_key` | Yes | License key from your ForgeRift email |
| `anthropic_api_key` | No | Enables AI-assisted safety classification for every `run_command` invocation (not only AMBER-tier); a high-risk result may independently block execution |

---

## Logs

The audit log (`audit.log`) is written to the `logs/` subfolder within the extension's install directory, managed by Claude Desktop. Every tool call is recorded with tier, blocked status, and args (secrets auto-redacted).

---

## Pricing

- **Individual:** $14.99/mo or $149/yr — [forgerift.io/#pricing](https://forgerift.io/#pricing)
- **Bundle (local-terminal-mcp + vps-control-mcp):** $19.99/mo or $199/yr — each plugin installs separately as its own .mcpb extension; local-terminal-mcp is Windows-only (macOS/Linux users get only the vps-control-mcp half of the Bundle)
- **Founder Cohort (limited):** $9.99/mo individual / $14.99/mo bundle *(bundle pricing equals the regular Individual plan rate)* — rate-locked as long as your subscription remains continuously active, monthly billing only; eligibility window closes at the earlier of (a) the 100th paid subscriber signs up or (b) 3 months after the marketplace listing date
- **14-day free trial** — no charge during trial period. Subscriptions are otherwise non-refundable except for confirmed ForgeRift billing errors, prorated convenience-termination refunds, and applicable statutory consumer rights — see [Terms §6.5](https://forgerift.io/terms.html)

---

> **Note:** A ForgeRift subscription is in addition to any Claude subscription. The plugin is a tool that runs inside Claude Desktop; you need an active Claude Desktop subscription (or Claude Pro) to use it.

---

## Support

- **Email:** support@forgerift.io
- **Security vulnerabilities:** security@forgerift.io
- **GitHub Issues:** github.com/ForgeRift/local-terminal-mcp/issues

---

## License

MIT — see [LICENSE](LICENSE).

[forgerift.io](https://forgerift.io) — [Privacy Policy](https://forgerift.io/privacy.html) — [Terms of Service](https://forgerift.io/terms.html)

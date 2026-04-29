> **Tip:** For faster diagnosis, load [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) into your Claude Project or paste it at the start of your session. It primes Claude with full plugin knowledge so it can help you self-diagnose most issues.

# Troubleshooting -- local-terminal-mcp

---

## Extension Won't Install / Claude Desktop Doesn't Show It

**The .mcpb file doesn't install**
Only Claude Desktop supports `.mcpb` extensions. Make sure you are on Claude Desktop (not the web app). Drag the `.mcpb` file onto the Claude Desktop window, or use **Settings > Extensions > Install from file**.

**Extension installed but doesn't appear in Claude Desktop**
Restart Claude Desktop after installing. If it still doesn't appear, confirm that:
1. You selected the correct `.mcpb` file (filename: `local-terminal.mcpb`)
2. Your Claude Desktop version supports extensions (update via **Help > Check for Updates**)
3. Claude Desktop is up to date (the plugin runtime is bundled with Claude Desktop — system Node.js is not required)

---

## License Key Issues

**License key prompt didn't appear**
Claude Desktop should prompt for your `lt_license_key` the first time the extension starts. If no prompt appeared, open **Settings > Extensions**, find Local Terminal, and enter your key in the configuration panel.

**"lt_license_key is required" on startup**
The extension exited because no license key was provided. Open **Settings > Extensions**, select Local Terminal, and enter your ForgeRift license key. If you don't have one, subscribe at [forgerift.io](https://forgerift.io). (In Claude Desktop's config UI this appears as `lt_license_key`; as an environment variable it would be `LT_LICENSE_KEY`.)

**License key rejected / "Subscription not found or inactive"**
Your key was not matched to an active subscription. Check that:
1. You copied the full key from your ForgeRift welcome email (no extra spaces or line breaks)
2. Your subscription is active -- log in at [forgerift.io](https://forgerift.io) to check status
3. If your trial has ended and no payment method is on file, the key will be inactive

---

## Tools Don't Appear After Install

**The extension shows as installed but no tools appear in Claude**
Start a **fresh conversation** -- existing conversations do not pick up newly connected tools. If tools still don't appear after starting a new chat, restart Claude Desktop.

**"Subscription check timed out" or other network errors at startup**
The extension couldn't reach the ForgeRift validation server. This is intentional design — the plugin fails closed if it cannot verify your subscription, because a tool with shell access to your machine should never silently fall back to an unverified state. Check your internet connection and restart Claude Desktop. To verify the endpoint is reachable, run the following in a separate Windows Command Prompt or PowerShell window (not through Claude -- curl and Invoke-WebRequest are RED-blocked in the plugin): `curl -I https://payments.forgerift.io/health` or `Invoke-WebRequest https://payments.forgerift.io/health`. If your machine is behind a corporate proxy or firewall, it may be blocking outbound HTTPS to the ForgeRift license validation endpoint (`payments.forgerift.io`). Contact your IT team to whitelist that hostname, or email support@forgerift.io.


**"Subscription check failed: Network error"**
A transient network error blocked the validation request. Restart Claude Desktop. If the error persists, check your firewall settings.

---

## AMBER Dry-Run Gate Confusion

**`run_command` always executes in dry-run -- I never get real output**
This is intentional. `run_command` defaults to `dry_run=true` so you can preview the command before it runs. To execute, explicitly pass `dry_run=false` after reviewing the preview. If Claude is not offering to execute, prompt it: *"Run that command for real."*

**I passed `dry_run=false` but the command still didn't run**
If the command hit a RED block, it will never execute regardless of `dry_run`. RED-blocked commands are rejected at the security layer before execution. Check the error message for the blocked category.

---

## Reading RED Block Error Messages

RED blocks emit a structured message starting with the category name. Example (first line only):
```
⛔ BLOCKED [file-delete]
```
Common categories:
- `chaining` -- `&&`, `||`, `;`, single `&`, pipe-to-shell (`| cmd`, `| powershell`, `| bash`), and backticks. Use separate tool calls.
- `data-exfil` -- `curl`, `wget`, `Invoke-WebRequest`. Use structured tools where possible.
- `file-delete` -- `rm`, `del`, `Remove-Item`. Permanently blocked.
- `sensitive-path-write` -- Writing to system paths or credential directories.
- `info-leak` -- Credential enumeration commands (e.g., `cmdkey /list`, `vaultcmd`). Sensitive file reads (`.env`, SSH keys) are blocked separately by the file-protection layer.

If a block is unexpected, check whether the binary or flag matches a pattern in `HARD_BLOCKED_PATTERNS` in `src/tools.ts`. To request a bypass for a legitimate admin workflow, contact support@forgerift.io.

---

## Audit Log Location

**Where is the audit log?**
The audit log is written to `logs\audit.log` inside the extension's install directory — the same directory Claude Desktop unpacked the `.mcpb` file into. Every tool call is logged with timestamp, tool name, security tier, blocked status, and arguments. Secrets are auto-redacted.

To find the exact install path, go to **Settings → Extensions**, select Local Terminal, and look for the install directory shown in the extension details panel. You can also ask Claude: *"Check the audit log and show me recent entries."* — it can read the file directly using the `read_file` tool.

**Audit log not rotating**
The log rotates at 10 MB: `audit.log` is renamed to `audit.log.old` (overwriting any prior backup), and a new `audit.log` is created. Maximum on-disk usage is approximately 20 MB. If rotation is not happening, check that Claude Desktop has write access to the extension install directory.

---

## Updating

To update to a new version:
1. Download the new `.mcpb` file from [github.com/ForgeRift/local-terminal-mcp/releases](https://github.com/ForgeRift/local-terminal-mcp/releases)
2. Open Claude Desktop and go to **Settings > Extensions**
3. Remove the existing Local Terminal extension
4. Install the new `.mcpb` file via **Install from file** or drag-and-drop
5. Restart Claude Desktop

Do not keep old `.mcpb` files around -- having multiple versions on disk has caused accidental reinstalls of stale builds.

---

## Uninstalling

Open Claude Desktop and go to **Settings > Extensions > Local Terminal > Remove**. This removes the extension and its tools from Claude Desktop. To reinstall, visit [forgerift.io](https://forgerift.io) or the Anthropic marketplace and install again.

The audit log (`logs/audit.log`) is not removed automatically. Delete the extension install directory manually if you want to remove all traces.

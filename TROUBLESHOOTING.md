> **Tip:** For faster diagnosis, load [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) into your Claude Project or paste it at the start of your session. It primes Claude with full plugin knowledge so it can help you self-diagnose most issues.

# Troubleshooting -- local-terminal-mcp

---

## Extension Won't Install / Claude Desktop Doesn't Show It

**The .mcpb file doesn't install**
Only Claude Desktop supports `.mcpb` extensions. Make sure you are on Claude Desktop (not the web app). Drag the `.mcpb` file onto the Claude Desktop window, or use **Settings > Extensions > Install from file**.

**Extension installed but doesn't appear in Claude Desktop**
Restart Claude Desktop after installing. If it still doesn't appear, confirm that:
1. You selected the correct `.mcpb` file (filename should be `local-terminal-X.Y.Z.mcpb`)
2. Your Claude Desktop version supports extensions (update via **Help > Check for Updates**)
3. Node.js v18 or later is installed -- run `node --version` in PowerShell to verify

---

## License Key Issues

**License key prompt didn't appear**
Claude Desktop should prompt for `LT_LICENSE_KEY` the first time the extension starts. If no prompt appeared, open **Settings > Extensions**, find Local Terminal, and enter your key in the configuration panel.

**"LT_LICENSE_KEY is required" on startup**
The extension exited because no license key was provided. Open **Settings > Extensions**, select Local Terminal, and enter your ForgeRift license key. If you don't have one, subscribe at [forgerift.io](https://forgerift.io).

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
The extension couldn't reach the ForgeRift validation server. Check your internet connection and restart Claude Desktop. If your machine is behind a corporate proxy or firewall, it may be blocking outbound HTTPS to `api.forgerift.io`. Contact your IT team or email support@forgerift.io.

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

RED blocks include a category name and the matched pattern. Example:
```
BLOCKED [RED] category=file-delete pattern=Remove-Item
```
Common categories:
- `chaining` -- `&&`, `;`, `|` used to chain commands. Use separate tool calls.
- `data-exfil` -- `curl`, `wget`, `Invoke-WebRequest`. Use structured tools where possible.
- `file-delete` -- `rm`, `del`, `Remove-Item`. Permanently blocked.
- `sensitive-path-write` -- Writing to system paths or credential directories.
- `credential-access` -- Reading `.env`, SSH keys, cloud credential files.

If a block is unexpected, check whether the binary or flag matches a pattern in `HARD_BLOCKED_PATTERNS` in `src/tools.ts`. To request a bypass for a legitimate admin workflow, contact support@forgerift.io.

---

## Audit Log Location

**Where is the audit log?**
The audit log is written to the extension's **user-data directory** managed by Claude Desktop -- not a `logs\` folder in the install directory. The exact path varies by machine; Claude Desktop controls it. Every tool call is logged with timestamp, tool name, security tier, blocked status, and arguments. Secrets are auto-redacted.

To find the log path, ask Claude: *"What is the audit log path for the local-terminal extension?"* -- the extension reports it on startup.

**Audit log not rotating**
The log rotates at `AUDIT_MAX_SIZE_MB` (default: 10 MB). One `.old` backup is kept. If rotation is not happening, check that Claude Desktop has write access to the user-data directory.

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

Open Claude Desktop and go to **Settings > Extensions > Local Terminal > Remove**. This removes the extension and its tools from Claude Desktop. To also remove audit logs and cached data, delete the extension's user-data directory (ask Claude for the path, or check your system's Claude Desktop app-data folder).

---

## Grace Period

If a subscription payment fails, your account enters a 7-day grace period. Features remain active during this time. Log in at [forgerift.io](https://forgerift.io) and update your payment method before the grace period ends to avoid interruption.

---

## Support

- **GitHub Issues:** [github.com/ForgeRift/local-terminal-mcp/issues](https://github.com/ForgeRift/local-terminal-mcp/issues)
- **Email:** support@forgerift.io
- **Security vulnerabilities:** security@forgerift.io (90-day responsible disclosure)

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

## Machine Fingerprint / MachineGuid Errors

The plugin reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` at
startup to identify your machine for license activation. If the read
fails, the plugin refuses to start (intentional fail-closed behavior --
a tool with shell access should never run with an unknown machine
identity).

**"Cannot start: Could not read MachineGuid from Windows registry"**
The registry value is not readable in your current environment. The
common cause is running the plugin inside **Windows Sandbox** or another
container that does not expose the host's `MachineGuid` registry value.

What to do:
1. Install on a regular Windows 10 or Windows 11 install (desktop, laptop,
   or full-VM image like the Microsoft Windows 11 dev VM). Sandbox is
   not a supported test environment.
2. If you are on a stock Windows install and still see this error,
   email `support@forgerift.io` with your Windows version
   (`winver`) and we will help diagnose.

**"Cannot start: MachineGuid registry value is present but did not match the expected GUID format"**
`reg.exe` returned a value but it is not a 36-character GUID. This is
unusual on a stock Windows install. Email `support@forgerift.io` with
your Windows version (`winver`) and the output of:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid
```

(Run that in a separate PowerShell window, not through Claude.) Do not
share the actual GUID value publicly; send it via the support email.

**Why the plugin fails closed instead of falling back**
Earlier versions could fall back to `os.hostname()` if the registry
read failed. That defeats the per-machine activation cap (a stable
hostname-based fingerprint is identical across machines with the same
name) so we removed the fallback in v1.13.0. The trade-off is that
restricted environments that block the registry read cannot run the
plugin -- by design.

---

## Subscription & Billing

### Self-service billing portal

Manage your subscription yourself at:

> **https://billing.stripe.com/p/login/4gMdR91Sg5sgd1ybuE2Ry00**

Enter the email address you used at checkout and Stripe will send you a one-time login link. From the portal you can:

- Cancel your subscription (takes effect at the end of the current billing period)
- Update your payment method
- View and download past invoices
- Update your billing address / customer information

The portal is the fastest path. Email ``support@forgerift.io`` is the fallback for anything the portal can't do (lost license key, account-level questions, billing disputes).

### I lost my license key

Email ``support@forgerift.io`` from the email address you used to subscribe. We can regenerate your key (the prior key is invalidated). Turnaround is usually within one business day.

If you suspect your key has been compromised (e.g. it appeared in a screenshot you posted, or you're on a shared machine and someone may have copied it), email us so we can rotate it immediately.

### How do I cancel my subscription?

Use the self-service portal above. Cancellation takes effect at the end of your current billing period -- you keep the time you paid for, then access ends. No prorated refunds (per the pricing terms at [forgerift.io/#pricing](https://forgerift.io/#pricing) and the Terms of Service at [forgerift.io/terms.html](https://forgerift.io/terms.html)).

If you can't reach the portal for any reason, email ``support@forgerift.io`` from the email address you used to subscribe and we'll cancel for you.

### How do I update my payment method or download an invoice?

Use the self-service portal above. If you can't reach it, email ``support@forgerift.io``.

### My card was declined / subscription is past_due

Stripe will retry the charge automatically a few times. During the retry window, the plugin keeps working (``past_due`` is treated as ``active`` by the validation flow, which is a deliberate grace period to avoid interrupting paying customers over a transient bank issue). If retries fail, the subscription transitions to ``unpaid`` and the plugin stops validating. To update your card before then, use the self-service portal above; if you can't reach it, email support.

---

## Tools Don't Appear In Cowork or Claude in Chrome

Local Terminal is a Claude Desktop ``.mcpb`` extension. It loads into Claude Desktop's standard chat sessions when you open a new conversation. **Cowork** (Anthropic's desktop-automation mode) and **Claude in Chrome** use a separate MCP server pool and do not currently load ``.mcpb`` extensions, so Local Terminal does not appear there. This is a Claude Desktop / Cowork architectural distinction, not a Local Terminal bug.

If you want Claude to use Local Terminal, use a standard Claude Desktop chat. The license you paid for is the same; only the entry point differs.

---

## Tools Don't Appear After Install

**The extension shows as installed but no tools appear in Claude**
Start a **fresh conversation** -- existing conversations do not pick up newly connected tools. If tools still don't appear after starting a new chat, restart Claude Desktop.

**"Subscription check timed out" or other network errors at startup**
The extension couldn't reach the ForgeRift validation server. This is intentional design — the plugin fails closed if it cannot verify your subscription, because a tool with shell access to your machine should never silently fall back to an unverified state. Check your internet connection and restart Claude Desktop. To verify the endpoint is reachable, run the following in a separate Windows Command Prompt or PowerShell window (not through Claude -- curl and Invoke-WebRequest are RED-blocked in the plugin): `curl -I https://payments.forgerift.io/health` or `Invoke-WebRequest https://payments.forgerift.io/health`. If your machine is behind a corporate proxy or firewall, it may be blocking outbound HTTPS to the ForgeRift license validation endpoint (`payments.forgerift.io`). Contact your IT team to whitelist that hostname, or email support@forgerift.io.


**"Subscription check failed: Network error"**
A transient network error blocked the validation request. Restart Claude Desktop. If the error persists, check your firewall settings.

---

## AMBER Dry-Run Default Confusion

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

# local-terminal — Marketplace Listing

> This is the marketplace-facing copy for the local-terminal Claude Code plugin.
> Anything in this file should be accurate on the day of submission. Aspirational
> features, pricing tiers, and URLs belong in the roadmap, not here.

## Short description (≤ 140 chars)

Direct, audited access to your local Windows machine from Claude. Browse files, run commands, manage git — all with a three-tier security model.

## Long description

local-terminal gives Claude structured, audited access to your local Windows machine. It exposes eight tools — directory listing, file reading, system info, file search, text search, npm commands, read-only git commands, and a rate-limited escape hatch — all running through a three-tier command authorization model.

Every command runs through a three-tier authorization model:

- **RED** — 120+ patterns across 20 categories are hard-blocked with no override: file deletion, disk ops, shutdown/restart, process killing, user management, permission changes, network config, scheduled execution, service management, code execution via PowerShell (`IEX`, `Invoke-Expression`, `wscript`, `cscript`), data exfiltration (`curl`, `wget`, `Invoke-WebRequest`, `ssh`, `scp`, `certutil -urlcache`, `bitsadmin`), persistence (registry Run keys, startup folder, scheduled tasks), credential access (`cmdkey`, `vaultcmd`, DPAPI), privilege escalation (`sudo`, `runas`), and command chaining/obfuscation.
- **AMBER** — `robocopy`, `xcopy`, `move`, `find -exec`, `xargs`, `awk`, `sed -i`, and wildcard renames force `dry_run=true` with a visible warning. Must be explicitly re-invoked to execute.
- **GREEN** — everything else, subject to a 120 req/min rate limit, a 30-second command timeout, and immutable audit logging.

Authentication is a static bearer token generated at install time and stored in `.env`. The server binds exclusively to `127.0.0.1` — it is not reachable from the network. Audit logs redact tokens, secrets, keys, and passwords before write and rotate at 10 MB. Sensitive files (`.env`, `.ssh/`, `.aws/`, `.gcloud/`, `.azure/`, `kubeconfig`, Windows credential stores, browser login data, private keys) are blocked from read operations even through read-only tools.

## Behavioral transparency (please read before installing)

**Known behavior defect: probabilistic rule-following.**

This plugin tells Claude, through tool descriptions and a SessionStart hook, to operate your machine through the structured tools — not by asking you to open CMD or PowerShell and paste command output. The rules win the vast majority of the time. They do not win 100% of the time. LLMs follow instructions probabilistically, and strong training priors toward "demonstrate commands for the user to run" can occasionally leak through.

We treat every instance of this as a defect, not a limitation. The mitigations are:

- Anti-pattern clauses embedded in every tool description (re-sent to the model every turn, not subject to system-prompt truncation).
- A SessionStart hook that plants a behavioral briefing at startup, resume, clear, and compact.
- An iterative "every support ticket becomes a new anti-pattern sentence" improvement loop.

If Claude ever hands you a command to run in CMD or PowerShell instead of running it through the plugin, tell Claude: *"Use the local-terminal tools instead of asking me to run commands."* That usually resolves it for the rest of the session. Starting a fresh session resets the probability in our favor. Report specifics at the GitHub issue tracker — real examples are how we sharpen the rules.

See `KNOWN_ISSUES.md` in the repo for the full list of current limitations and caveats.

## What's in the box

- 8 structured tools (file access, system info, git, npm, escape hatch)
- SessionStart hook with a behavioral briefing
- Static bearer token auth (localhost-only — no TLS needed)
- 120 req/min rate limiting, per-token
- Audit log with secret redaction and 10 MB rotation
- 120+ hard-blocked patterns (RED tier) covering 20 security categories
- Unicode homoglyph bypass rejection (non-ASCII in commands is hard-blocked)
- Newline injection rejection (each line of input is checked independently)
- Sensitive file protection (blocks reads even through read-only tools)
- Windows Service install via NSSM (auto-restart on crash, survives reboots)

## What it does NOT do

- No GUI dashboard. All interaction is through Claude.
- No remote access. The server binds to `127.0.0.1` only — this plugin is for your local machine, not a remote one. For remote Linux server access, see vps-control.
- No file write tools. Claude can read your files but cannot write to them through this plugin. File creation and editing stays in Claude's hands via the Cowork workspace.
- No TLS. The server is localhost-only; TLS is not needed and is not provided.
- No automatic rollback. If a command runs but produces unexpected results, reversing it is a decision you make.

## Compatibility

**Windows only — Claude Desktop and Cowork.** The plugin runs as a localhost-only Windows Service and cannot be reached from a browser or remote client. It does not work with Claude in Chrome, claude.ai web, or mobile. For remote Linux server access, see vps-control.

## Requirements

- Windows 10 / 11
- Node.js 18+
- PowerShell (run as Administrator for setup)

## Install

```powershell
git clone https://github.com/forgerift/local-terminal-mcp
cd local-terminal-mcp
.\setup.ps1
```

Then add the config snippet that `setup.ps1` prints to your Claude Desktop config and restart Claude Desktop.

## Source, issues, changelog

- Source: https://github.com/forgerift/local-terminal-mcp
- Issues: https://github.com/forgerift/local-terminal-mcp/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Known issues: [KNOWN_ISSUES.md](KNOWN_ISSUES.md)
- Security model: [SECURITY.md](SECURITY.md)

## License

MIT.

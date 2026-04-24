# Troubleshooting — local-terminal-mcp

## Installation Issues

**Setup script fails: "Access denied" or "requires Administrator"**
Right-click PowerShell and select "Run as Administrator", then re-run `.\setup.ps1`. NSSM (the Windows Service installer) requires admin privileges.

**NSSM download fails during setup**
`setup.ps1` downloads NSSM from GitHub. If your machine blocks outbound downloads, manually download `nssm.exe` from https://nssm.cc/download, place it in the repo directory, and re-run setup. The script will detect the existing binary and skip the download.

**Service won't start after install**
Check the service logs at `logs\service-err.log`. Common causes:
- `MCP_AUTH_TOKEN` not set in `.env` — re-run `setup.ps1` to regenerate
- Port 3002 already in use — change `MCP_PORT` in `.env` and restart the service
- Node.js not found — ensure Node 18+ is installed and on `PATH`

**Port 3002 conflict**
If another process is using port 3002, set `MCP_PORT=3003` (or any free port) in `.env`, then restart the service via `nssm restart local-terminal-mcp`.

---

## Connection Issues

**Claude says "Cannot connect to local-terminal-mcp"**
1. Open Services (`services.msc`) and confirm `local-terminal-mcp` is Running
2. Check `logs\service-out.log` for startup errors
3. Verify `claude_desktop_config.json` has the correct port matching `MCP_PORT` in `.env`
4. Restart Claude Desktop after any config change

**Auth token errors / "401 Unauthorized"**
The token in `claude_desktop_config.json` must match `MCP_AUTH_TOKEN` in `.env`. If you've regenerated the token (via `setup.ps1`), update the config file and restart Claude Desktop.

**How to rotate the auth token**
Edit `.env`, replace `MCP_AUTH_TOKEN` with a new random value (e.g. from `openssl rand -hex 32` in WSL, or PowerShell's `[System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))`), then restart the service and update `claude_desktop_config.json`.

---

## Security Model

**Command blocked unexpectedly**
The three-tier security model (RED/AMBER/GREEN) blocks 450+ dangerous patterns. Check the error message for the category and reason. Common cases:

- `&&` or `;` in a command → `chaining` category. Use separate tool calls instead.
- `curl`, `wget`, `Invoke-WebRequest` → `data-exfil` category. Use structured tools where possible.
- `rm`, `del`, `Remove-Item` → `file-delete` category. These are permanently blocked.
- `Set-Content` to a system path → `sensitive-path-write` category.

**`dry_run=true` always forced**
`run_command` defaults to `dry_run=true` for safety. You must explicitly pass `dry_run=false` after reviewing the previewed command to execute it. This is intentional — not a bug.

**Sensitive file read blocked**
Files like `.env`, SSH keys (`.pem`, `.key`, `.pfx`), Windows credential stores, and cloud credential directories (`.aws/`, `.gcloud/`, `.azure/`) are blocked even through read-only tools. This is intentional security behavior. Access these files directly outside the MCP if needed.

**BYPASS_BINARIES for legitimate admin workflows**
If a specific binary/category combination is legitimately needed (e.g., a deployment script that must write to a controlled path), set `BYPASS_BINARIES=mybinary:category-name` in `.env`. Every bypass is logged as `[SECURITY-BYPASS]` in the audit trail. See `SECURITY.md` for the full list of category names.

---

## Audit Log

**Where is the audit log?**
`logs\audit.log` in the install directory. Every tool call is logged with timestamp, tool name, security tier, blocked status, and arguments. Secrets are auto-redacted.

**Audit log not rotating**
The log rotates at `AUDIT_MAX_SIZE_MB` (default: 10MB). One `.old` backup is kept. If rotation is not happening, check that the service has write access to the `logs\` directory.

---

## Updating

```powershell
git pull
.\setup.ps1
```

Re-running `setup.ps1` stops the existing service, installs the updated version, and restarts. Your `.env` (auth token, port settings) is preserved.

---

## Uninstalling

```powershell
.\uninstall.ps1
```

Stops and removes the Windows Service. Prompts before deleting the install directory. Remember to remove the `local-terminal-mcp` entry from `claude_desktop_config.json` and restart Claude Desktop.

---

## Support

- **GitHub Issues:** [github.com/ForgeRift/local-terminal-mcp/issues](https://github.com/ForgeRift/local-terminal-mcp/issues)
- **Email:** support@forgerift.io
- **Security vulnerabilities:** security@forgerift.io (90-day responsible disclosure)

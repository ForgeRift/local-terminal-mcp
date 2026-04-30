# Command Reference — local-terminal-mcp

This document describes what types of commands you can ask Claude to run through local-terminal-mcp, and why certain commands require confirmation or are blocked entirely.

**Three tiers of commands:**
- ✅ **GREEN** — Runs immediately, no extra review
- ⚠️ **AMBER** — Dry-run preview shown first; you must confirm before execution
- 🔴 **RED** — Always blocked, no exceptions, no override

**Important:** RED commands are hard-blocked by static code patterns and cannot be approved by Claude, by you, or by any AI review. If you need a RED command run, you must do it yourself in your own terminal window.

---

## ✅ GREEN — Runs Freely

These are safe, read-only or informational operations that don't modify your system.

| What you can ask | Examples |
|---|---|
| Read files | `Get the contents of my config file` |
| List files and folders | `What files are in my Downloads folder?` |
| Search file contents | `Find all files containing "TODO" in my project` |
| Get system info (read-only) | `How much RAM do I have?` `What's my CPU?` |
| Run safe CLI tools | `Check my git status` `What version of Node is installed?` |
| View system info (OS, disk, memory) | `What's my disk space?` `How much RAM do I have?` |
| View running processes | `What processes are running?` (use run_command with tasklist) |
| Read environment info | `What's my PATH?` |
| Check network status (read-only) | `What's my IP address?` `Is this port open?` |
| Check disk space | `How much space is left on my C drive?` |
| Inspect packages | `npm list`, `npm ls`, `npm outdated`, `npm audit` |

**Rule of thumb:** If it reads, lists, searches, or reports without changing anything, it's GREEN.

---

## ⚠️ AMBER — Confirmation Required

A small set of bulk-operation commands that have legitimate uses. `run_command` defaults to `dry_run=true` — when Claude encounters an AMBER pattern, the response includes a warning alongside the dry-run preview. If `dry_run=false` is passed on the first call, the command executes immediately (the plugin has no session state to enforce a two-call gate). The recommended workflow is for Claude to call with `dry_run=true` first, relay the warning to you, and only call again with `dry_run=false` after you confirm.

The following commands trigger the AMBER tier (the complete AMBER pattern list is in `src/tools.ts`):

| Commands | Why confirmation is required |
|---|---|
| `robocopy`, `xcopy` | Bulk file copies can overwrite large numbers of files |
| `copy /y` | Forced overwrite without prompt |
| `move` | Can relocate files en masse |
| Wildcard `rename` (e.g., `ren *.txt *.bak`) | Bulk renames across many files at once |
| `find -exec` | Chains a command across every file found — wide blast radius. (`xargs` is hard-blocked RED under `recursive-file-deletion`, not AMBER.) |
| `awk` | Can write to files when output-redirected; used in many one-liner data transforms |
| `sed -i` | In-place file editing; changes cannot be previewed without running |

For these commands, the recommended workflow is:
1. Call the tool with `dry_run=true` (the default), showing you exactly what would run and surfacing the AMBER warning
2. Relay the warning and preview to you in chat, and wait for your confirmation
3. Only then call again with `dry_run=false` to actually execute

This two-step flow is a workflow convention enforced by Claude's behavior, not a server-side gate — `dry_run=true` is a default, not forced. You are always in control of whether execution proceeds.

---

## 🔴 RED — Always Blocked

> **Note:** For readability, this document presents the 27 RED categories across 35 user-facing topic headings. Several categories are expanded into multiple descriptive sections. The authoritative list of 27 **HARD_BLOCKED runtime slugs** (a subset of slugs emitted in `⛔ BLOCKED [<slug>]` errors; the broader `BLOCKED_PATTERNS` array surfaces additional slugs) is in [SECURITY.md](SECURITY.md). The user-facing heading names in this document (e.g., "File Deletion", "Disk Operations") are groupings for readability and do not appear verbatim in error messages.


These are hard stops. Static patterns in the code reject them immediately — no AI review, no context, no override. If you try one, Claude will tell you it's blocked and why, and offer to help you accomplish the underlying goal through a different method or by writing the command for you to run manually.

---

### File Deletion
**What it is:** Deleting files — `del`, `rm`, `Remove-Item`, `erase`, `/s /q` bulk deletes

**Why blocked:** Deletion is permanent. There is no workflow where an automated assistant should be deleting your files for you.

**What to do instead:** Claude can write the exact command — you run it yourself in a terminal so you can verify what's selected before deleting.

---

### Recursive File Deletion
**What it is:** `rm -rf /`, `Remove-Item -Recurse -Force`, `del /s /q` from a root or home directory path

**Why blocked:** Mass recursive deletion is almost always a mistake or an attack.

---

### Data Exfiltration
**What it is:** All outbound network transfer commands — `curl`, `wget`, `Invoke-WebRequest`, `scp`, `ssh`, network file copies. All uses are blocked unconditionally (not only data-sending POST/upload patterns).

**Why blocked:** Outbound data transfer commands are blocked without exception. If you need to POST to an API or transfer a file, do it in your own terminal.

---

### Process Termination
**What it is:** Killing running processes — `taskkill`, `Stop-Process`, `kill`

**Why blocked:** Killing the wrong process can crash applications or cause data loss. Process management is a human decision.

---

### User Management
**What it is:** Creating, modifying, or deleting user accounts — `net user`, `New-LocalUser`, `Add-LocalGroupMember`, password changes

**Why blocked:** User account changes affect who has access to your system. This is never an automation task.

---

### Permission Changes
**What it is:** Changing file or folder permissions — `icacls`, `cacls`, `takeown`, `Set-Acl`, mass `chmod`-equivalent

**Why blocked:** Permission changes can expose protected files or lock you out of your own system.

---

### Network Configuration
**What it is:** Changing network settings — `netsh`, adding routes, modifying the hosts file, changing DNS, binding ports persistently

**Why blocked:** Network config changes persist and affect other applications.

---

### Scheduled Tasks
**What it is:** Creating, modifying, or deleting scheduled tasks — `schtasks /create`, `Register-ScheduledTask`, `at`

**Why blocked:** Scheduled tasks run automatically in the background. This is a persistence mechanism and requires explicit human setup.

---

### Service Management
**What it is:** Creating, deleting, or modifying Windows services — `sc create`, `sc delete`, `New-Service`, `Set-Service`

**Why blocked:** Services run with elevated privileges and persist across reboots.

---

### Code Execution (Encoded / Eval)
**What it is:** Running code from an encoded string — `Invoke-Expression`, `IEX`, `eval`, `-EncodedCommand`, `wscript`, `rundll32`

**Why blocked:** Encoded or evaled code execution is the primary bypass technique for pattern scanners. There is no legitimate automation need for this.

---

### Package Installation
**What it is:** Installing new software — `npm install -g`, `pip install`, `winget install`, `choco install`

**Why blocked:** Installing packages changes your system and can introduce malicious code. All package installs must be performed manually.

---

### Package Removal
**What it is:** Uninstalling software — `winget uninstall`, `choco uninstall`, uninstalling system-critical packages

**Why blocked:** Removing the wrong package can break your environment in ways that are hard to reverse.

---

### Container Operations
**What it is:** `docker run`, `docker exec`, `docker build`, `docker push`, `docker pull`, `docker system prune -af`, running privileged containers, mounting host filesystems

**Why blocked:** Container operations can destroy data or expose the host filesystem. `docker ps`, `docker logs`, `docker images` (read-only) may be GREEN; execution, build, and nuclear-prune operations are RED. Note: `docker rm` and `docker rmi` (removing stopped containers/images) are not currently blocked — only the patterns listed above.

---

### Privilege Escalation
**What it is:** Running as a different user or gaining elevated access — `runas`, `Start-Process -Verb RunAs`, `sudo`-equivalent

**Why blocked:** Elevation expands what subsequent commands can do. If a task genuinely requires elevation, run it yourself in an already-elevated terminal.

---

### Persistence (Startup / Registry Run Keys)
**What it is:** Writing to startup folders, adding registry run keys, creating login scripts

**Why blocked:** Persistence is how malware survives a reboot. Startup entries must be created manually.

---

### Registry Modifications
**What it is:** `reg add`, `reg delete`, `reg import`, `Set-ItemProperty HKLM:\...` (writes); also `reg query`, `reg export`, `reg compare`, `reg copy`, `reg save` (reads/exports) — all `reg` subcommands are blocked

**Why blocked:** Registry changes persist and can affect system behavior in ways that are difficult to diagnose or reverse.

---

### Database Writes
**What it is:** `DROP`, `DELETE`, `TRUNCATE` via `psql`, `mysql`, `sqlite3`, `sqlcmd`

**Why blocked:** Destructive database operations are irreversible. Read queries (`SELECT`, schema inspection) may be GREEN; write operations that could destroy data are RED.

---

### System State (Shutdown / Reboot)
**What it is:** `shutdown`, `Restart-Computer`, `Stop-Computer`, `poweroff`, `halt`

**Why blocked:** Shutting down or restarting would kill your Claude session and any work in progress.

---

### System Directory Writes
**What it is:** Writing files to `C:\Windows\`, `C:\Windows\System32\`, `C:\Program Files\`

**Why blocked:** Legitimate applications don't write to system directories via a chat-controlled terminal. This is a malware installation pattern.

---

### Environment Variable Persistence
**What it is:** `[System.Environment]::SetEnvironmentVariable` (any scope), `setx`

**Why blocked:** `SetEnvironmentVariable` is blocked at all scopes (Process/User/Machine) because scope-leakage bugs can cause unintended persistence. Use session-local variable assignment (`$x = "val"`) for process-scoped values instead.

---

### Credential / Key Access
**What it is:** Reading `.env` files, SSH keys, Windows credential stores, browser login data, cloud credentials

**Why blocked:** These files are blocked at the read level in all tools — not just `run_command`.

---

### Command Chaining (`&&`, `||`, `;`, `&`, pipe-to-shell)
**What it is:** Combining multiple commands with `&&`, `||`, `;`, `&`, or pipe-to-shell forms (e.g., `| cmd /c`, `| bash -c`).

**Why blocked:** Chaining is blocked in `run_command`. Use separate tool calls instead. For git operations needing a working directory, use `git -C <path>` rather than `cd <path> && git ...`.

**Note on `run_command` working directory:** Unlike `run_git_command` and `run_npm_command`, `run_command` has **no `directory` or `working_directory` parameter**. It always executes in Claude Desktop's spawned-child working directory (typically the Claude install directory). If a command must run from a specific path, use the structured tools (`run_git_command`, `run_npm_command`) which accept a `directory` parameter, or ask the user to run the command themselves from the correct directory.

**Plain `|` piping is NOT blocked:** `dir | findstr error`, `type file.txt | findstr keyword`, and similar pipes to standard commands work fine — the full command string is checked against the block list, and plain `|` piping to non-shell targets is not in the block list. Pipe-to-shell forms (`| cmd /c`, `| bash -c`, etc.) are blocked under `chaining`.

---

### HTTP Server Binding
**What it is:** Starting a network listener — `nc -l`, `python -m http.server`, `simple-server`, `http-server --port`

**Why blocked:** A listening server exposes your filesystem or application to the network. Start dev servers in your own terminal. Note: `npx serve` and `node server.js` are not matched by the `http-server` pattern — they would be blocked under `code-exec` (interpreter+script) or pass through; start them in your own terminal regardless.

---

### Base64-Encoded Execution
**What it is:** Decoding a base64 string and executing it — `certutil -decode` piped to execution, `[Convert]::FromBase64String(...)`, `base64 -d` execution patterns. Note: `powershell -EncodedCommand` is blocked under `code-exec` (not `base64-exec`) since the `powershell -Command` pattern fires first.

**Why blocked:** This is the most common technique for bypassing pattern scanners.

---

### COM Object Execution
**What it is:** `New-Object -ComObject WScript.Shell`, `CreateObject("Shell.Application")`

**Why blocked:** COM object execution is a "living off the land" technique used almost exclusively by malware on modern Windows.

---

### Download-and-Execute (Download Cradles)
**What it is:** `IEX (New-Object Net.WebClient).DownloadString(...)`, `curl | bash`

**Why blocked:** Downloading and immediately executing code is the textbook first stage of a malware infection.

---

### PowerShell Execution Policy Changes
**What it is:** `Set-ExecutionPolicy Unrestricted`, `Set-ExecutionPolicy Bypass`

**Why blocked:** Execution policy is a security boundary; changing it system-wide weakens your defenses permanently.

---

### Firewall Destruction
**What it is:** `iptables -F/-X`, `ufw disable/reset`, `firewall-cmd --panic-off`, `nft flush ruleset`, `setenforce 0` — Linux/cross-platform firewall teardown patterns

**Why blocked:** Disabling the firewall exposes your machine to the network. Note: Windows-side `netsh advfirewall` commands are blocked under the `network-config` category (not `firewall-destruction`) — the emitted error slug will be `network-config`.

---

### EDR / Security Tool Disabling
**What it is:** Disabling antivirus, Windows Defender, endpoint detection software

**Why blocked:** Security software exists to protect you. An automated system has no business disabling it.

---

### Background / Hidden Execution
**What it is:** `Start-Job`, `Start-Process -WindowStyle Hidden`, backgrounding with `&`

**Why blocked:** Background execution hides what's running. Every command must produce visible output.

---

### Living-Off-the-Land Binaries (LOLBins)
**What it is:** Malicious invocation patterns for `certutil -decode`, `mshta`, `regsvr32 /s /n /u /i:http://...`, `wmic process call create`

**Why blocked:** LOLBins are attacker tradecraft — using legitimate Windows binaries in ways that evade traditional scanners.

*Note:* `forfiles` was promoted from AMBER to RED in v1.6.0 (used in download-cradle and scheduled-exec attacks).

---

### WMI-Based Remote Execution
**What it is:** `Invoke-WmiMethod -Class Win32_Process -Name Create`, `wmic /node: process call create`

**Why blocked:** WMI process creation bypasses many process-creation monitoring tools and is a common lateral movement technique.

---

### Audit Log Destruction
**What it is:** Deleting or clearing Windows Event Logs, security audit logs, or the plugin's own audit log

**Why blocked:** The audit log is your evidence trail. Clearing it is the first thing an attacker does after gaining access.

---

### Destructive Git History Rewrite
**What it is:** `git push --force` to a remote, `git filter-branch`, BFG Repo Cleaner runs

**Why blocked:** Rewriting pushed history destroys other people's work and can permanently corrupt a repository.

---

### .NET Reflection Execution
**What it is:** `[Reflection.Assembly]::Load(...)`, `Invoke-ReflectedPEInjection`

**Why blocked:** Reflection-based execution runs code with no file on disk, making it nearly invisible to scanners.

---

## Frequently Asked Questions

**Q: I need to do something that's blocked. What do I do?**
Open a separate PowerShell or Command Prompt window and run it yourself. Claude can write the exact command for you and explain each part — it just won't execute it through the plugin.

**Q: Can I whitelist a specific command pattern?**
Not through the plugin itself. If a legitimate pattern is consistently over-blocked, contact support@forgerift.io with the specific pattern and your use case — it may be adjustable in a future release. You can also open a GitHub Issue at github.com/ForgeRift/local-terminal-mcp/issues.

**Q: What happens if I try a RED command?**
Claude will tell you it's blocked, explain which category triggered it, and offer to help you accomplish the underlying goal through a different method or by writing the command for you to run manually.

**Q: How do I see what commands were run?**
Ask Claude: *"Show me the audit log"* — the plugin logs every command attempt (including blocked ones) with timestamps.

**Q: Can providing more context or explanation make a RED command go through?**
No. RED commands are blocked by static code patterns before any AI review happens. Context does not affect RED blocks — they are unconditional.

---

*For setup instructions, see [GETTING_STARTED.md](GETTING_STARTED.md). For troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).*

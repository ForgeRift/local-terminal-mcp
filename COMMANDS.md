# Command Reference — local-terminal-mcp

This document describes what types of commands you can ask Claude to run through local-terminal-mcp, and why certain commands require extra review or are blocked entirely.

**Three tiers of commands:**
- ✅ **GREEN** — Runs immediately, no extra review
- ⚠️ **AMBER** — Reviewed by AI safety layer before running; may be blocked if context looks risky
- 🔴 **RED** — Always blocked, no exceptions, no override

If you try a RED command, Claude will tell you it's blocked and why. If you try an AMBER command that gets rejected, Claude will explain what triggered the review and suggest a safer alternative if one exists.

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
| View running processes (read-only) | `What processes are running?` |
| Read environment info | `What's my PATH?` |
| Check network status (read-only) | `What's my IP address?` `Is this port open?` |
| Navigate directories | `Go to my Desktop` |
| Check disk space | `How much space is left on my C drive?` |
| Run tests | `Run my test suite` (if tests are read-only) |
| Build projects | `Build my TypeScript project` (compile only) |

**Rule of thumb:** If it reads, lists, searches, or reports without changing anything, it's GREEN.

---

## ⚠️ AMBER — AI-Reviewed Before Running

These categories of commands can be legitimate but also dangerous depending on context. Claude's AI safety board (Layer 3) reviews them before running and decides based on what you're actually trying to do.

You don't need to do anything special — just ask naturally. If the review approves, it runs. If not, Claude will tell you.

---

### Command Chaining
**What it is:** Combining multiple commands with `&&`, `||`, `;`, or `|`
**Why reviewed:** Chaining can turn a harmless-looking first command into cover for something dangerous in the second command. A single command is easy to review; a chain of five is harder to reason about.
**Usually approved:** `git add . && git commit -m "fix"` or `cd myproject && npm install`
**May be blocked:** Chains that mix read and write operations in unclear ways

---

### Code Execution
**What it is:** Running code from a string or a file — `python -c "..."`, `node -e "..."`, `Invoke-Expression`, `eval`
**Why reviewed:** Inline code execution is a common technique to hide what a command actually does. The safety layer reads the code being executed before allowing it.
**Usually approved:** `python -c "import sys; print(sys.version)"` or simple one-liners
**May be blocked:** Obfuscated code, code that downloads more code, anything that looks like it's trying to evade the pattern scanner

---

### Container Operations
**What it is:** Docker, Podman, containerd commands — starting/stopping/building containers
**Why reviewed:** Containers can mount host filesystems, expose network ports, or run with elevated privileges. Context matters a lot.
**Usually approved:** `docker ps`, `docker logs mycontainer`, building from a Dockerfile you own
**May be blocked:** Mounting sensitive host paths, running privileged containers, pulling images from unknown sources

---

### Data Destruction
**What it is:** Commands that wipe, overwrite, or permanently erase data
**Why reviewed:** Sometimes you legitimately need to clear a log file or wipe a test database. But these commands are irreversible, so the AI checks whether the context makes sense.
**Usually approved:** Clearing a specific temp file you created, wiping a test dataset you explicitly set up
**May be blocked:** Anything targeting production data, system files, or paths you didn't recently create

---

### Data Exfiltration
**What it is:** Sending data out of your system — curl posting data, emailing files, copying to network shares
**Why reviewed:** The most common way data leaves a compromised system is via a command that looks like a normal network request.
**Usually approved:** Posting to your own API, sending a file to your own server, `curl` to a URL you just mentioned
**May be blocked:** Unexplained outbound transfers, base64-encoded payloads being sent out

---

### Direct Database Access
**What it is:** Raw SQL via `psql`, `mysql`, `sqlite3`, `sqlcmd` — especially writes
**Why reviewed:** Direct database writes can corrupt data or expose schema. Read queries are safer; write queries need context.
**Usually approved:** `SELECT` queries for debugging, schema inspection
**May be blocked:** `DROP`, `DELETE`, `TRUNCATE` without clear context that this is a dev/test database

---

### Disk Operations
**What it is:** Low-level disk tools — `diskpart`, `format`, `fdisk`, `mkfs`
**Why reviewed:** These tools operate below the filesystem and can destroy data on entire partitions, not just individual files.
**Usually approved:** Read-only disk inspection (`diskpart list disk`)
**May be blocked:** Anything that writes to or formats a partition

---

### Environment Variable Manipulation
**What it is:** Setting or unsetting environment variables — `$env:`, `setx`, `export`
**Why reviewed:** Changing environment variables can redirect where programs look for config, credentials, or executables — a subtle way to influence system behavior.
**Usually approved:** Setting a variable for a single command (`NODE_ENV=test npm test`)
**May be blocked:** Modifying system-wide variables, changing PATH or sensitive config

---

### File Deletion
**What it is:** Deleting files — `del`, `rm`, `Remove-Item`
**Why reviewed:** Deletion is permanent (or at least non-obvious to reverse). The AI checks whether the file path makes sense to delete given what you've been working on.
**Usually approved:** Deleting files you just created, cleaning up temp files from a build you ran
**May be blocked:** Deleting files outside your project directory, system files, anything that looks like covering tracks

---

### File Write
**What it is:** Creating or modifying files — `echo > file`, `Set-Content`, `Out-File`, `tee`
**Why reviewed:** Writing files is one of the most common operations, but also one of the most abused. The review checks the destination path and content.
**Usually approved:** Writing to your project folder, creating config files, saving output to a log file you own
**May be blocked:** Writing to system directories, writing executable scripts to startup locations, writing files with obfuscated content

---

### HTTP Server
**What it is:** Starting a local web server — `python -m http.server`, `npx serve`, `node server.js`
**Why reviewed:** A local HTTP server exposes your filesystem or application to the network. Fine for development, risky if unintended.
**Usually approved:** `python -m http.server 8080` for local testing
**May be blocked:** Servers that bind to 0.0.0.0 with no auth, or that seem to be serving sensitive directories

---

### Information Leakage
**What it is:** Commands that print sensitive system information — SSH keys, credential files, API keys in env vars, `/etc/shadow`-equivalent
**Why reviewed:** These commands are legitimate for debugging but also the first thing an attacker runs to understand what they have access to.
**Usually approved:** Reading your own config files you're actively working on
**May be blocked:** Reading SSH private keys, credential stores, saved passwords, or paths you haven't mentioned

---

### Network Configuration
**What it is:** Changing network settings — adding routes, modifying hosts file, changing DNS, binding ports
**Why reviewed:** Network config changes can persist after a session and affect other applications.
**Usually approved:** `netstat` and other read-only network tools; opening a specific port you're developing on
**May be blocked:** Modifying hosts file, adding persistent routes, disabling network interfaces

---

### Obfuscation
**What it is:** Commands that hide what they're doing — heavily encoded strings, reversed text, character substitution
**Why reviewed:** There's rarely a legitimate reason to obfuscate a command you're running on your own machine. This is almost always an attempt to bypass the pattern scanner.
**Usually approved:** Nothing — this category is almost always blocked
**May be blocked:** Everything that pattern-matches as deliberate obfuscation

---

### Permission Changes
**What it is:** Changing file or folder permissions — `icacls`, `attrib`, `chmod`-equivalent
**Why reviewed:** Permission changes can expose protected files or lock you out of your own system.
**Usually approved:** Fixing a specific file's permissions that you're actively troubleshooting
**May be blocked:** Granting Everyone full access, recursively changing permissions on system paths

---

### Persistence
**What it is:** Creating things that run automatically — startup entries, login scripts, scheduled tasks
**Why reviewed:** Persistence is how malware survives a reboot. Legitimate use cases exist but are uncommon in day-to-day workflows.
**Usually approved:** Creating a Task Scheduler entry for a script you own, adding a startup app you're developing
**May be blocked:** Adding entries to system startup paths, creating hidden scheduled tasks

---

### Package Installation
**What it is:** Installing new software — `npm install -g`, `pip install`, `winget install`, `choco install`
**Why reviewed:** Installing packages changes your system and can introduce malicious code if the package is compromised.
**Usually approved:** Installing packages for a project you're actively working on
**May be blocked:** Installing packages that weren't mentioned in the conversation, global installs with no clear purpose

---

### Package Removal
**What it is:** Uninstalling software — `npm uninstall`, `pip uninstall`, `winget uninstall`
**Why reviewed:** Removing packages can break dependencies in ways that are hard to reverse.
**Usually approved:** Removing a package you just installed to test something
**May be blocked:** Uninstalling system-critical software or packages unrelated to the current task

---

### Privilege Escalation
**What it is:** Running as a different user or gaining elevated access — `runas`, `sudo`-equivalent
**Why reviewed:** Elevating privileges expands what subsequent commands can do. The AI checks whether the task actually requires elevation.
**Usually approved:** Rarely — if elevation is needed, Claude will usually ask you to run it in an already-elevated terminal
**May be blocked:** Most cases, especially if the reason for elevation isn't clear from context

---

### Process Termination
**What it is:** Killing running processes — `taskkill`, `Stop-Process`, `kill`
**Why reviewed:** Killing the wrong process can crash applications or cause data loss.
**Usually approved:** Killing a specific process you just started that's stuck
**May be blocked:** Killing system processes, security software, or processes you haven't mentioned

---

### Scheduled Execution
**What it is:** Scheduling commands to run at a later time — Task Scheduler, `at`, `schtasks`
**Why reviewed:** Scheduled tasks run without you watching, so they're a persistence vector as well as a convenience feature.
**Usually approved:** Scheduling a backup or cleanup script you own
**May be blocked:** Tasks that run as SYSTEM, tasks scheduled from obfuscated commands

---

### Service Management
**What it is:** Starting, stopping, or configuring Windows services — `sc`, `Start-Service`, `Stop-Service`
**Why reviewed:** Services run with elevated privileges and persist across reboots.
**Usually approved:** Restarting a development service (e.g., a local database) you're actively using
**May be blocked:** Disabling security services, modifying system services you haven't mentioned

---

### System State Changes
**What it is:** Changing system-level configuration — registry edits, group policy, system settings
**Why reviewed:** System state changes are persistent and can be difficult to reverse.
**Usually approved:** Rarely
**May be blocked:** Most cases — if you need a system setting changed, Claude will walk you through doing it manually in the GUI

---

### User Management
**What it is:** Creating, modifying, or deleting user accounts — `net user`, `New-LocalUser`
**Why reviewed:** User management changes who has access to your system.
**Usually approved:** Rarely — this is unusual in a development workflow
**May be blocked:** Creating new admin accounts, modifying the Administrator account

---

## 🔴 RED — Always Blocked

These are hard stops. No amount of context, explanation, or rephrasing will make them run. The plugin doesn't send them to the AI safety layer — they're rejected immediately in code before any AI review happens.

If you have a legitimate need for something in this list, you'll need to run it yourself in a separate terminal. Claude can walk you through the steps.

---

### Audit Log Destruction
**What it is:** Deleting or clearing Windows Event Logs, security audit logs, or the plugin's own audit log
**Why blocked:** The audit log is your evidence trail. Clearing it is the first thing an attacker does after gaining access, and there's no legitimate reason an automated system needs to do it.

---

### Background Execution
**What it is:** Starting a process that detaches from the terminal and runs invisibly — `Start-Job`, `Start-Process -WindowStyle Hidden`, backgrounding with `&`
**Why blocked:** Background execution hides what's running. The plugin needs to see the full output of every command it runs.

---

### Base64-Encoded Execution
**What it is:** Decoding a base64 string and executing it — `[System.Convert]::FromBase64String(...)` piped to execution, `powershell -EncodedCommand`
**Why blocked:** This is the most common technique for bypassing pattern scanners. There is no legitimate reason to base64-encode a command before running it in this context.

---

### COM Object Execution
**What it is:** Using COM objects to run code — `New-Object -ComObject WScript.Shell`, `CreateObject("Shell.Application")`
**Why blocked:** COM objects are a well-known "living off the land" technique for executing code in ways that evade detection. These are almost exclusively used by malware on modern Windows systems.

---

### Container Nuclear Operations
**What it is:** Destroying all containers at once — `docker system prune -af`, `docker rm -f $(docker ps -aq)`
**Why blocked:** Irreversible mass destruction. If you need to clean up containers, Claude will help you identify specific ones to remove.

---

### Credential and Key Destruction
**What it is:** Deleting credential stores, certificate private keys, SSH private keys, API key files
**Why blocked:** Destroying credentials is irreversible and can lock you out of systems permanently. There is no workflow where an automated tool should be deleting your key material.

---

### Database Destruction
**What it is:** `DROP DATABASE`, `DROP TABLE`, truncating all tables in a production-looking database
**Why blocked:** Irreversible. If you need to reset a dev database, Claude can help you write the script — but it won't auto-execute it.

---

### Destructive Git History Rewrite
**What it is:** `git push --force` to a remote, `git filter-branch --env-filter`, `BFG Repo Cleaner` runs
**Why blocked:** Rewriting pushed history destroys other people's work and can permanently corrupt a repository. Force pushes to remote are blocked without exception.

---

### Disk-Level Writes
**What it is:** Writing directly to disk sectors or partitions — `diskpart` write operations, `dd if=... of=/dev/...`
**Why blocked:** Disk-level writes bypass the filesystem entirely. A mistake here can make a drive unbootable or unrecoverable.

---

### .NET Reflection Execution
**What it is:** Using .NET reflection to load and execute assemblies at runtime — `[Reflection.Assembly]::Load(...)`, `Invoke-ReflectedPEInjection`
**Why blocked:** Reflection-based execution is the primary technique for running code that has no file on disk, making it nearly invisible to traditional scanners. No legitimate automation workflow requires this.

---

### Download Cradles
**What it is:** Downloading and immediately executing code — `IEX (New-Object Net.WebClient).DownloadString(...)`, `curl | bash`
**Why blocked:** Download-and-execute is the textbook first stage of a malware infection. Downloading and executing are two separate operations; if you need both, do them separately so you can review what was downloaded.

---

### EDR/Security Tool Disabling
**What it is:** Disabling antivirus, endpoint detection software, Windows Defender, or similar security tools
**Why blocked:** Security software exists to protect you. An automated system has no business disabling it.

---

### PowerShell Execution Policy Changes
**What it is:** `Set-ExecutionPolicy Unrestricted`, `Set-ExecutionPolicy Bypass`
**Why blocked:** Execution policy is a security boundary. Changing it system-wide weakens your defenses for every user and every script that runs afterward. If you need to run a specific unsigned script, use `-ExecutionPolicy Bypass` scoped to a single session — and do it yourself.

---

### Firewall Destruction
**What it is:** Disabling the Windows Firewall, deleting firewall rules en masse, `netsh advfirewall set allprofiles state off`
**Why blocked:** Disabling the firewall exposes your machine to the network. This is a common attacker step after gaining initial access.

---

### Git History Rewrite (General)
**What it is:** Any form of rewriting committed history — `git commit --amend` on pushed commits, `git rebase -i` with drops/squashes intended for pushed branches
**Why blocked:** History rewrites on pushed branches affect everyone using the repository.

---

### Living-Off-the-Land Binaries (LOLBins)
**What it is:** Using legitimate Windows binaries as proxies to execute malicious code — `certutil -decode`, `mshta`, `regsvr32 /s /n /u /i:http://...`, `wmic process call create`
**Why blocked:** LOLBins are standard attacker tradecraft — using tools that are already on the system and therefore less suspicious. The plugin blocks the known-malicious invocation patterns for each of these.

---

### Net Subcommand User/Group Manipulation
**What it is:** `net user`, `net localgroup`, `net group` — creating users, adding to groups, changing passwords
**Why blocked:** This is how attackers create backdoor accounts or add themselves to admin groups. User account changes are a human decision, not an automation task.

---

### OS Permission Destruction
**What it is:** `icacls /grant Everyone:(F)` on system paths, removing all ACLs, `takeown /f C:\Windows /r /d y`
**Why blocked:** Granting Everyone full control to system directories is a known privilege escalation technique and can permanently damage your Windows installation.

---

### Destructive Package Manager Operations
**What it is:** `npm uninstall` or `pip uninstall` of system-critical packages, `winget uninstall` of security software
**Why blocked:** Uninstalling the wrong package can break your development environment or remove security tools in ways that are hard to undo.

---

### Recursive File Deletion
**What it is:** `rm -rf /`, `Remove-Item -Recurse -Force C:\`, `del /s /q C:\Users\*`
**Why blocked:** Recursive deletion from a root or home directory path is almost always a mistake or an attack. There is no automation workflow that should be doing this.

---

### Redirect Truncation / Overwrite
**What it is:** Using `>` to overwrite important files rather than `>>` to append, or redirecting to `/dev/null`-equivalent to destroy output
**Why blocked:** Silent overwrites are a common way to destroy configuration or log files without an obvious error. The plugin catches patterns that redirect into paths that look like config, logs, or executables.

---

### Windows Registry Modifications
**What it is:** `reg add`, `reg delete`, `Set-ItemProperty HKLM:\...`, modifying any HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER registry keys
**Why blocked:** Registry changes persist and can affect system behavior in ways that are difficult to diagnose or reverse. The plugin won't touch the registry.

---

### Sensitive Path Writes
**What it is:** Writing files to `C:\Windows\`, `C:\Windows\System32\`, `C:\Program Files\`, or other system directories
**Why blocked:** Legitimate applications don't write to system directories through a chat-controlled terminal. This is a malware installation pattern.

---

### System Power State
**What it is:** Shutdown, restart, hibernate, sleep — `shutdown /s`, `Restart-Computer`, `Stop-Computer`
**Why blocked:** Shutting down or restarting the machine would kill the Claude session and any work in progress. There's no scenario where an AI assistant should be powering off your computer.

---

### WMI-Based Remote Execution
**What it is:** Using Windows Management Instrumentation to execute code — `Invoke-WmiMethod -Class Win32_Process -Name Create`, `wmic /node: process call create`
**Why blocked:** WMI remote execution is a lateral movement and persistence technique. WMI process creation bypasses many process-creation monitoring tools and is a common attacker technique.

---

## Frequently Asked Questions

**Q: I need to do something that's blocked. What do I do?**
Open a separate PowerShell or Command Prompt window and run it yourself. Claude can write the exact command for you and explain each part — it just won't execute it for you through the plugin.

**Q: My legitimate task is getting AMBER-blocked. How do I help Claude understand?**
Just explain what you're trying to do and why. Claude's AI safety layer reads your full conversation context, not just the isolated command. "I'm setting up a dev environment and need to install Python globally" gives the review much more to work with than just `winget install Python.Python.3`.

**Q: Can I whitelist a specific command pattern?**
Not through the plugin itself. If you find that a legitimate pattern is consistently over-blocked, contact support@forgerift.io with the specific pattern and your use case — it may be adjustable in a future release.

**Q: What happens if I try a RED command?**
Claude will tell you it's blocked, explain which category triggered it, and offer to help you accomplish the underlying goal through a different method or by writing the command for you to run manually.

**Q: How do I see what commands were run?**
Ask Claude: *"Show me the audit log"* — the plugin logs every command attempt (including blocked ones) with timestamps.

---

*For setup instructions, see [GETTING_STARTED.md](GETTING_STARTED.md). For troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).*

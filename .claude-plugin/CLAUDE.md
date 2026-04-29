# local-terminal-mcp — Claude Operating Instructions

You are connected to the user's local Windows machine via local-terminal-mcp. Follow these instructions automatically — the user should never need to explain this workflow to you.

## Security Model

This connector enforces a three-tier command authorization model. You MUST understand and respect it:

### RED (Hard-Blocked) — 140+ patterns
Commands that are permanently blocked. You will receive a structured error with category, reason, and ToS warning. Do NOT attempt to rephrase, encode, or chain commands to bypass blocks. Do NOT apologize for blocks — they exist to protect the user.

Blocked categories: file deletion, disk operations, shutdown/reboot, process killing, user management, permission changes, network configuration, scheduled tasks, service management, code execution (eval/Invoke-Expression/wscript/rundll32), data exfiltration (curl/wget/ssh/scp/Invoke-WebRequest), persistence (registry/startup), database writes, package installation, package removal (choco uninstall/winget uninstall), container operations, system directory writes, environment variable persistence, privilege escalation, credential access, command chaining exploits, HTTP server binding, base64 execution (certutil -decode/[Convert]::FromBase64String), COM object execution (WScript.Shell/Shell.Application), download cradles (Net.WebClient/certutil -urlcache), LOLBins (mshta/regsvr32/rundll32/msiexec), WMI execution (wmic process call create/Invoke-WmiMethod).

### AMBER (Warning-Required)
Commands like `find -exec`, `xargs`, `awk`, `sed -i`, `robocopy`, `xcopy`, `copy /y`, `move`, and wildcard renames. These force `dry_run=true` automatically. If you need to run one, call it first (it will show the warning), then call again with `dry_run=false` and explain why in your justification.

### GREEN (Allowed)
All structured tools and any `run_command` that passes RED + AMBER checks.

## Tool Usage Best Practices

### Always prefer structured tools over run_command
- Use `list_directory` instead of `dir` or `ls`
- Use `read_file` instead of `type` or `cat`
- Use `find_files` instead of `dir /s /b`
- Use `search_file` instead of `findstr` or `grep`
- Use `get_system_info` instead of `systeminfo`, `wmic`, or other system-inquiry commands
- Use `run_git_command` for git status, log, diff, branch, show, stash list, tag, rev-parse, ls-files (fetch is NOT available)
- Use `run_npm_command` for npm list, ls, outdated, audit, view, why, explain (install, ci, and run are NOT available)

### run_command workflow
1. ALWAYS call with `dry_run=true` first (default) — this previews the command
2. Review the preview
3. Call again with `dry_run=false` to execute
4. Always provide a clear `justification` explaining why structured tools can't cover this

### Sensitive files are blocked at the file level
Even `read_file` and `search_file` will refuse to open `.env`, SSH keys, credential stores, browser data, cloud credentials, `NTUSER.DAT`, and similar files. This is by design. Do not attempt workarounds.

### Command chaining is blocked
Do NOT use `&&`, `||`, `;`, backticks, or pipe-to-shell in `run_command`. If you need sequential commands, make separate tool calls. For git operations that need a working directory, use `git -C <path>` instead of `cd <path> && git ...`.

### Command timeout
All commands have a per-tool wall-clock timeout: 30 seconds for run_command and run_git_command, 60 seconds for run_npm_command. For long-running operations, warn the user first.

## Behavioral Rules

1. **Never ask the user to run commands you can run yourself.** Use the tools directly.
2. **Never expose file paths from error messages** that contain sensitive information.
3. **When a RED block fires, explain what happened simply** — don't over-apologize or suggest workarounds to bypass it.
4. **When an AMBER warning fires, explain the risk** and ask the user if they want to proceed.
5. **Log your reasoning** in the justification field of run_command — this goes into the audit log.
6. **Output is truncated at 10,000 characters.** If you expect large output, use `read_file` with line ranges instead.

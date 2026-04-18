# Known Issues

This is the current list of known limitations and caveats for local-terminal-mcp. We keep it honest and current. If you hit something that isn't here, open a [GitHub issue](https://github.com/claudedussy/local-terminal-mcp/issues) and we'll add it.

---

## Behavioral (Claude-side)

### Probabilistic rule-following

**What you might see:** Claude occasionally suggests you open CMD or PowerShell and run a command yourself (like `dir`, `git status`, or `npm install`) instead of using the corresponding structured tool this plugin provides.

**Why this happens:** Large language models follow instructions probabilistically, not deterministically. Our guidance to Claude — "use the tools, don't ask the user to open a terminal, don't hand them paste commands" — lives in tool descriptions and a SessionStart briefing, and it wins the vast majority of the time. But strong training priors toward demonstrating commands for users to run can occasionally leak through, especially in very long sessions with a lot of prior pattern buildup.

**What we do about it (shipped as of v1.3.0):**
- **Per-turn lever:** every tool description embeds an explicit "USE THIS — never ask the user to run…" anti-pattern clause. These descriptions are re-sent to the model on every tool-list request and are not subject to system-prompt truncation, so they ride along in the freshest part of context every turn.
- **Per-session lever:** a `SessionStart` hook (`hooks/briefing.js`) emits a behavioral briefing at startup, resume, clear, and compact. The briefing maps common user intents to the correct tool and restates the three-tier security model and the dry-run-first rule. Fails closed — a broken briefing never blocks a session.
- **Iteration loop:** each support ticket reporting an instance of this behavior becomes a new anti-pattern sentence in the next release, making the rules progressively sharper.

**What to do if you hit it:**
1. Tell Claude explicitly: "Use the local-terminal tools instead of asking me to run commands." — this usually resolves it for the rest of the session
2. Starting a fresh Claude session clears accumulated context and resets the probability in our favor
3. Report the specific prompt and Claude's response to [GitHub issues](https://github.com/claudedussy/local-terminal-mcp/issues) — real examples are how we sharpen the rules

We consider every instance of this behavior a defect, not a limitation. We're iterating toward zero. If you care about the topic, you can watch the `behavioral` label in our issue tracker.

---

## Platform

### Command timeouts at 30 seconds

Any single `run_command` call hard-terminates after 30 seconds. Long-running operations (e.g., a large `npm install`) will be killed. Split into shorter steps, or run the long command in the background by appending `start /b` and polling for output separately. This is intentional (prevents runaway processes) but is a common "why did my install just stop?" moment.

### Command chaining is blocked

The patterns `&&`, `||`, backticks, and `$()` substitution are RED-tier blocked. Semicolons (`;`) are blocked when they appear before or after a dangerous command — standalone `;` in non-chaining contexts may pass through, but in practice any attempt to use `;` as a command separator to reach a blocked operation will be caught. Split into multiple `run_command` calls. For directory-scoped commands, pass the `directory` parameter on structured tools (`run_npm_command`, `run_git_command`) instead of chaining a `cd`.

### Windows environment variable expansion is blocked

`%VAR%` expansion in `run_command` is RED-blocked (obfuscation category) to prevent environment-variable-based bypass patterns. Use literal paths instead.

### Sensitive files cannot be read

`.env`, SSH keys, Windows credential stores, cloud credential files, and other sensitive files are blocked from all read operations — even through `read_file` and `search_file` — regardless of the path. This is deliberate and non-configurable. If you need to inspect one of these, do so outside this plugin.

### run_command output is capped at 10,000 characters

Very verbose commands (e.g., `npm install` on a large project) will have their output truncated at 10,000 characters with a notice. The command still runs to completion; only the returned output is truncated.

---

## Windows Service

### NSSM must be downloaded at install time

`setup.ps1` downloads NSSM from the GitHub releases API during install. If the machine has no internet access at install time, the download will fail and the service will not be registered. Workaround: download NSSM manually and place it at `nssm\nssm.exe` before running `setup.ps1`.

### Re-running setup.ps1 replaces the service

Running `setup.ps1` a second time (e.g., after `git pull` to update) stops and removes the existing service, then reinstalls it. Your `.env` (auth token) is preserved. The process takes about 10 seconds during which Claude has no local-terminal connection.

### Installing to a new location generates a new auth token

If you clone the repo to a different directory and run `setup.ps1` there (e.g., for testing), the new install generates a fresh `.env` with a different bearer token. Any existing Claude session connected to the old token will lose the local-terminal connection immediately. Restart Claude Desktop after the new install to reconnect with the updated token. Your old install's `.env` token is not affected if you reinstall to the same directory.

---

## Reporting an issue

Please include:
- The plugin version (from `plugin.json` or `package.json`)
- What you asked Claude to do
- What Claude did
- What you expected Claude to do

File at: https://github.com/claudedussy/local-terminal-mcp/issues

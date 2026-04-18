# Changelog

All notable changes to local-terminal-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.5.0] — 2026-04-18

### Security hardening — second-pass Opus adversarial review (S45)

Closes all 2 CRITICAL, 4 HIGH, and 5 MEDIUM/LOW findings from the second-pass adversarial review. Previous verdict: FAIL. All blockers resolved.

**CRITICAL:**
- **F-NEW-2**: git config RCE — prepend 7 neutralizing `-c` flags to every `run_git_command` invocation (`diff.external=`, `core.pager=cat`, `core.fsmonitor=`, `core.sshCommand=`, `core.editor=true`, `protocol.ext.allow=never`, `protocol.file.allow=user`). Add `GIT_CEILING_DIRECTORIES` to safeGitEnv. Closes the two-step `.git/config` write → `git diff` execute attack chain.
- **F-NEW-1 + F-NEW-6 (CRITICAL + HIGH)**: `validateGitArgv()` added — rejects `--no-index`, `--ext-diff`, `--textconv`, `--output`, `-O`, `--config-env`, `-c`, `--exec-path`, `-p`, `--patch`, `-S`, `-G`, `--pickaxe-*`. For `git show`: rejects `<ref>:<path>` where path matches `SENSITIVE_FILE_PATTERNS`. Closes arbitrary-file-read via `git diff --no-index` and historical secret exfil via `git log -p -S / git show HEAD:.env`.

**HIGH:**
- **F-NEW-3**: `find_files` now calls `sanitizeDir()` at entry — blocks UNC/device path NTLM hash leak and SSRF. `list_directory` also rejects UNC paths.
- **F-NEW-4**: `find_files` result set filtered through `isSensitiveFile()` before returning. Cap added at 500 results.
- **F-NEW-5**: LOLBin blocklist expanded with full LOLBAS corpus additions: `msiexec`, `msdt.exe`, `cmstp`, `esentutl`, `hh.exe`, `pcalua`, `odbcconf`, `regasm`, `regsvcs`, `wsl.exe`, `bash.exe`, `mavinject`, `xwizard`, `PresentationHost`, `SyncAppvPublishingServer`, `regedit /s`. Single-`&` chaining pattern added (`(?<![>&])&(?![&>])`). `SECRET_KEY_SUBSTRINGS` expanded: SESSION, COOKIE, PASSWORD, PASSWD, CREDENTIAL, CRED, VAULT, KEYSTORE, SALT, SIGNING, JWT.

**MEDIUM/LOW:**
- **F-NEW-7**: `find_files` now uses `lstatSync` (never follows symlinks), tracks `Set<dev:ino>` for cycle detection, enforces `maxDepth=8` and 15s deadline. Closes DoS and symlink-amplified UNC walk.
- **F-NEW-11**: `ln --symbolic` and `ln -s` added to BLOCKED_PATTERNS (permissions category). Closes long-form flag bypass.
- **F-NEW-12**: `sanitizeDir` strips trailing path separators (preserving drive root `C:\`). Closes trailing-backslash edge case.
- **F-NEW-13**: `splitArgv` strips null bytes, CR/LF, and backticks before parsing. Closes injection via these characters in git/npm sub-commands.
- **F-NEW-14/15**: Documented in KNOWN_ISSUES (wmic internal path in `get_system_info`; rate-limit is per-session not per-call). No code change — low exploitability.

---

## [1.4.1] — 2026-04-18

### Fixed

- **F-17 partial bypass**: `run_command` with `dry_run=false` on the first call to an AMBER-tier command was executing the command without ever showing the AMBER warning (`if (amberResult && isDryRun)` evaluated false, silently falling through to execution). Fixed: AMBER check is now unconditional — if `dry_run=true` the warning is returned; if `dry_run=false` the command executes but the warning is always included in the response. The CHANGELOG entry for v1.4.0 overclaimed this fix.
- **run_npm_command tool description**: description listed `npm install` and `npm run <script>` as available sub-commands. Both are blocked since v1.4.0 (F-16). Description and command parameter hint now reflect the actual allowlist: `list`, `outdated`, `audit`, `view`, `why`, `explain`.
- **Doc accuracy**: REVIEWER_GUIDE pattern count updated (120+ → 150+), execSync/execFileSync distinction corrected, ADVERSARIAL_REVIEW.md added to source section; KNOWN_ISSUES semicolon chaining description corrected; `.gitignore` adds `package-lock.json`.

---

## [1.4.0] — 2026-04-18

### Security hardening — all 27 findings from the Opus adversarial review closed

This release closes every finding in `ADVERSARIAL_REVIEW.md`. The original Opus verdict was FAIL; all P0/P1/P2 items are now resolved.

**P0 (CRITICAL — 8 findings):**
- **F-1**: Applied `SENSITIVE_FILE_PATTERNS` to `run_command` argv — `type`, `Get-Content`, `findstr`, etc. can no longer read credential files.
- **F-2**: Rewrote `del`/`exec` with `\b` word boundaries; `cmd /c del` and `powershell -c "del …"` now caught.
- **F-3**: Added `rmdir`, `rd`, `Remove-Item`, `Remove-ItemProperty`, `ri` (flagged), `Clear-Item`, `Clear-Content`.
- **F-4**: Blocked `powershell|pwsh` + `-EncodedCommand`/`-Enc`/`-e`/`-c`/`-Command`/`-File` — base64 PowerShell unreachable.
- **F-5**: Added `pwsh` to every pattern that previously named only `powershell`.
- **F-6**: Blocked .NET type accelerators (`[IO.File]::Delete`, `[Net.WebClient]::DownloadFile`, `[Diagnostics.Process]::Start`, etc.).
- **F-7**: `buildSafeEnv()` strips secret-shaped env keys before every child process; `$env:VAR`, `Get-ChildItem env:`, `cmd /c set` pattern-blocked.
- **F-8**: LOLBin patterns — `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`, `installutil`, `msbuild` inline tasks.

**P1 (HIGH — 10 findings):**
- **F-9**: `wmic`, `Invoke-CimMethod`, `Get-WmiObject`, `gwmi`, `Get-CimInstance`, `gcim`, `Win32_Process` blocked.
- **F-10**: `sanitizeDir` denylist replaced with strict allowlist; UNC/device/leading-dash/control-char rejection added.
- **F-11/F-14**: `read_file` strips ADS suffix, rejects UNC/device, canonicalizes via `realpathSync`; both original and canonical path checked.
- **F-12**: `sanitizeDir` rejects leading `-`/`/`; `execFileSync` argv (F-19) makes `dir` positional, never a flag.
- **F-13**: Expanded `SENSITIVE_FILE_PATTERNS` — npm/PyPI/Maven/Cargo/Gradle tokens, Azure/GCP/Terraform credentials, PSReadline history, shell history, Chrome `Local State`, KeePass, crypto wallets.
- **F-15**: `run_git_command` injects `GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=NUL GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=https:http:file`; `git fetch` removed from allowlist.
- **F-16**: `npm run`/`ci`/`install` removed from allowlist; `--ignore-scripts` added to remaining commands.
- **F-17**: Server-side AMBER enforcement — warning always returned first; client cannot skip with `dry_run: false`.
- **F-18**: `New-Object -Com`, `Set-Alias`, `New-Alias`, `& $var` call operator blocked.
- **F-19**: `run_git_command`, `run_npm_command`, `find_files`, `search_file` refactored to `execFileSync(shell:false)` with argv arrays; `runFile()` + `splitArgv()` helpers added.

**P2 (MEDIUM/LOW — 9 findings):**
- **F-22**: `INPUT_LIMITS` + `checkSize()` — all user-supplied strings capped before regex runs (`command` 4 096, `filePath`/`directory` 512, patterns 256).
- **F-23**: `isReDoSPattern()` guard in `search_file` rejects nested quantifiers and wide alternation.
- **F-25**: `scrubSecrets()` redacts token shapes (`ghp_`, `sk-`, `AKIA`, `xoxb-`, Anthropic keys, PEM headers, high-entropy base64) from `run_command` and `run_git_command` output.
- **F-27**: Control-char rejection added to `read_file` and `search_file` path inputs.
- **F-20/F-21/F-24/F-26**: Covered by other fixes above (see `ADVERSARIAL_REVIEW.md`).

---

## [1.3.0] — 2026-04-17

### Added
- **SessionStart hook** (`hooks/briefing.js`) that plants a behavioral briefing into Claude's context every time a new session starts, resumes, clears, or compacts. The briefing maps common user intents to the correct structured tool ("What's in this folder?" → `list_directory`, "Read this file" → `read_file`), restates the three-tier RED/AMBER/GREEN model, and makes the sensitive-file block and dry-run-first rules explicit. Wired in `.claude-plugin/plugin.json` via `"hooks": "./hooks/hooks.json"`. Fails closed — any error in the hook exits 0 silently so a broken briefing never blocks a customer's session.

### Changed
- **Every tool description now embeds an explicit "USE THIS — never ask the user to …" anti-pattern clause.** Tool descriptions are re-sent to the model on every tool-list request and are not subject to system-prompt truncation, making them the strongest behavioral lever available. All eight tools updated (`list_directory`, `read_file`, `get_system_info`, `find_files`, `run_npm_command`, `run_git_command`, `run_command`, `search_file`).

### Why
- This is the Windows-CMD mirror of the behavioral hardening that shipped in `vps-control-mcp` v1.4.0. Observation across S35–S41 was that Claude sometimes regressed to "open CMD and run this" suggestions despite the system-prompt rules, because system-prompt rules compete with every other context pressure for placement. Tool descriptions and SessionStart hooks land closer to the freshest part of the context window every turn, and targeting both surfaces gives two independent behavioral levers rather than one.
- No validation contracts changed; no tier boundaries moved. The RED/AMBER/GREEN classifier is untouched.

---

## [1.2.0] — earlier

Baseline: three-tier command security model (RED/AMBER/GREEN), sensitive file guard, rate limiting, CORS, audit rotation. Tool annotations (`title`, `readOnlyHint`, `destructiveHint`) on all eight tools. Command-position anchors on blocked patterns (`exec`, `kill`, `del`, `at`, `su`) to prevent substring false-positives.

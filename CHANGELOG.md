# Changelog

All notable changes to local-terminal-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

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

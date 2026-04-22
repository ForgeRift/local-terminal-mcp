# Adversarial Security Review — local-terminal-mcp v1.2.0

**Date:** 2026-04-16 | **Session:** S35 | **Reviewer:** Claude (Automated)

## Executive Summary

The RED-blocked pattern enforcement has **2 critical bypasses** and several high-severity usability issues (false positives). Critical fixes applied in this session.

## Critical Findings (Fixed)

### CRITICAL-01: Unicode Homoglyph Bypass
- **Attack:** Cyrillic/Greek characters visually identical to Latin bypass `\b` word boundaries
- **Payload:** `рm /tmp/file` (Cyrillic 'р' = U+0440)
- **Fix:** Reject non-ASCII characters in commands before regex checks

### CRITICAL-02: Newline Injection in Chaining
- **Attack:** `.` in regex doesn't match `\n`, so `echo safe &&\nrm file` bypasses chaining check
- **Fix:** Split commands by newlines and check each line independently

### HIGH-01: Single Semicolon Chaining
- **Attack:** `echo safe; rm file` — regex only checks `[;&|]{2}` (double operators)
- **Fix:** Added single-semicolon + single-pipe-to-shell detection

## High — False Positives (Usability)

| Pattern | Issue | Example Blocked |
|---------|-------|-----------------|
| `/\bexec\b/i` | Too broad — catches filenames | `./executable --help` |
| `/\bkill\b/i` | Catches grep/cat args | `grep "killed" log.txt` |
| `/\bmount\b/i` | Catches /mnt paths | `ls /mnt/data/` |
| `/\bdel\b/i` | Catches .del extensions | `dir *.del` |
| `/\bat\b\s+\d/i` | Catches echo/grep args | `echo "at 10:00"` |
| `/\bsu\s/i` | Catches echo/grep args | `echo "su root"` |

**Note:** These false positives were NOT fixed in this pass — they reduce usability but don't create security bypasses. Fixing them requires careful analysis to avoid creating bypass vectors. Recommended for S36.

## Medium Findings

- **npm run** allows arbitrary scripts from package.json (supply chain risk, by design)
- **git log --output** can write files (version-dependent)
- **Backtick regex** too broad for PowerShell escaping
- **find_files/search_file** use string interpolation (partial protection from quoting)
- **sanitizeDir** doesn't check `$()`, `\n` (safe due to quoted context)

## Low Findings

- PowerShell aliases (`ri`, `gci`) not blocked (PS-specific)
- Symlink path traversal to sensitive files (requires prior code execution)
- Caret escaping in PowerShell (`rm^ove-item`)
- Incomplete HTTP server blocking (node, ruby, perl)

## Fixes Applied This Session

1. Non-ASCII character rejection (pre-regex)
2. Newline splitting (check each line independently)
3. Single-semicolon chaining detection
4. Variable expansion blocking (`$()`, `${...}`, `%...%`)

## Recommendations for S36

1. Fix false-positive patterns with command-position anchors
2. Add PowerShell alias patterns to RED list
3. Use `realpathSync()` in `isSensitiveFile()` for symlink resolution
4. Switch `find_files`/`search_file` to `spawnSync` array form
5. Consider whitelist approach for `run_command` (fundamentally stronger than blacklist)

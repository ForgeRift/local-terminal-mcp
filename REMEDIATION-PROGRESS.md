# ForgeRift Security Remediation Progress — local-terminal-mcp
<!-- Phase 1 status file — updated automatically during remediation -->

## Status: Phase 1 COMPLETE

All bypass-corpus tests pass: **282/282** (0 failures).

---

## Phase 1 — Critical Pattern Fixes

### C1 — PowerShell -EncodedCommand prefix bypass ✅
**File:** `src/tools.ts` lines 134–141  
**Finding:** PowerShell CLI accepts any unambiguous prefix of `-EncodedCommand`.
`-en`, `-enco`, `-encod` etc. were not blocked by the old `e(nc(odedcommand)?)?` pattern.  
**Fix:** Replaced with `/[cfe][a-zA-Z]*/` which catches all prefixes of `-Command`, `-File`,
and `-EncodedCommand` in one pattern.  
**Tests:** `[C1]` suite — 17 tests, all pass.

### C3 — UNC path as command bypass ✅
**Finding:** `\\server\share\evil.exe` as argv[0] executes remote binaries.  
**Status:** Pre-existing pattern already covered this. Verified by `[C3]` suite — 5 tests, all pass.

### C6 — Sensitive write-destination blocking ✅
**File:** `src/tools.ts` — 15 new patterns added before `];`  
**Finding:** cp/mv/tee/dd to `/etc/ld.so.preload`, `/etc/sudoers`, cron dirs, systemd dirs,
pam.d, profile.d, `/etc/hosts`, `/boot/grub`, `/lib/modules`, `/usr/local/bin`, and
Windows `drivers\etc\hosts` were unblocked.  
**Fix:** Path-substring patterns (no per-verb matching needed; covers all write primitives).  
**Tests:** `[C6]` suite — 16 tests, all pass.

### C7 — env LD_PRELOAD= / LD_AUDIT= / LD_LIBRARY_PATH= injection ✅
**File:** `src/tools.ts` — 3 new patterns  
**Finding:** Dynamic-linker env var injection not blocked.  
**Fix:** `/\bLD_PRELOAD\s*=/i`, `/\bLD_AUDIT\s*=/i`, `/\bLD_LIBRARY_PATH\s*=/i`  
**Tests:** `[C7]` suite — 10 tests, all pass.

### C8 — Shell -c flag-injection evasion ✅
**File:** `src/tools.ts` line 396  
**Finding:** `ksh` was missing from the POSIX shell -c blocklist.  
**Fix:** Added `ksh` to `(bash|zsh|dash|fish|ksh|sh|ash)`. Also tightened `\s-c` → `\s+-c`.  
**Tests:** `[C8]` suite — 10 tests, all pass.

### C9 — WSL launcher regression guard ✅
**Status:** Pre-existing patterns covered this. Verified by `[C9]` suite — 4 tests, all pass.

### C10 — Windows anti-recovery / ransomware-preamble toolkit ✅
**File:** `src/tools.ts` — 7 new patterns  
**Finding:** vssadmin (any use), wbadmin (any use), wevtutil cl/sl, Clear-EventLog,
fsutil usn deletejournal, reagentc were unblocked.  
**Fix:** Added `category: 'anti-recovery'` patterns for each. wevtutil qe (query) still allowed.  
**Tests:** `[C10]` suite — 14 tests, all pass.

---

## Git Status
Both repos have index issues in the sandbox (lock file / corrupt index) preventing
`git commit`. **Code changes are on disk and correct.** Run the following to commit:

```bash
# local-terminal-mcp
cd local-terminal-mcp
rm .git/index.lock          # remove stale lock
git add src/tools.ts src/__tests__/bypass-corpus.test.ts
git commit -m "Phase 1: C1/C6/C7/C8/C10 pattern fixes + bypass-corpus test harness (LT)

C1: Replace -EncodedCommand pattern — /[cfe][a-zA-Z]*/ catches all 13 prefixes
C6: 15 sensitive-destination path patterns (Linux + Windows)
C7: LD_PRELOAD=/LD_AUDIT=/LD_LIBRARY_PATH= injection blocked
C8: Added ksh to POSIX shell -c blocklist
C10: vssadmin/wbadmin/wevtutil cl|sl/Clear-EventLog/fsutil usn/reagentc blocked

All 282 tests pass. Refs: C1 C6 C7 C8 C10 (S60 adversarial review)"
```

---

## Remaining Work (Phase 2+)

### Not yet started
- **C2** (H-level): PowerShell stdin/pipe exec paths
- **C4**: PowerShell AMSI bypass patterns
- **C11/C12/C13**: Layer 2 (Claude API classifier) and Layer 3 (multi-persona board)
  **DO NOT EXIST in current code** — require implementation from scratch.
- **H1–H20**: High-severity findings (see task brief)
- **M1–M15**: Medium-severity findings
- **D1–D12**: Design recommendations

### Pre-existing security.test.ts failures (not introduced by Phase 1)
These tests were written against a future code version and were already failing
in git HEAD before any Phase 1 changes. They must be addressed in later phases:
- AMBER tier (apt-get, find -exec, xargs, sed -i behaviour changes)
- capString / INPUT_LIMITS shape mismatches
- validatePath allowlist expectations
- validateProcess expectations  
- curl -o output-flag blocking (F-OP-34 extension)

# local-terminal-mcp methodology notes

This file holds repo-specific methodology details. The cross-repo
audit methodology (tools, versions, scope) lives in
[forgerift-license-api/docs/security/methodology.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/methodology.md).
This file's role is to capture decisions specific to local-terminal-mcp
that don't fit cleanly in the cross-repo doc.

## 2026-05-03 — stale-fork backup branch reconciliation

During the F008 cutover (commit `0fca724`), the local working copy of
local-terminal-mcp was discovered to be a stale fork that had been
written against the v1.12.0 sslip.io shape. The audit had been authored
against that fork. `origin/main` had already moved on to v1.13.0 with
the production payments.forgerift.io protocol. Rather than rebase 28
divergent commits, the stale work was preserved on
`s67-s68-stale-fork-backup` and the audit was re-anchored to
`origin/main`.

This note records the per-commit reconciliation decision so the backup
branch can be revisited intentionally, not blindly merged.

### Branch state

- Tip: `763cbbb security: F008 -- point license validation at production Cloudflare Worker`
- Commit count vs origin/main: 29 backup-only commits (28 from S67/S68 plus the local F008 attempt).
- Cumulative diff vs origin/main (excl `dist/`): 33 files, ~3000 ins / ~2500 del.

### Per-commit decisions

| Commit | Subject | Disposition | Rationale |
|---|---|---|---|
| `763cbbb` | F008 — point validation at Cloudflare Worker | **superseded** | Same migration landed on main as `879b163` (endpoint move) + `6da77d1` (v1.13.0 POST + machine_id). Backup version of the fix is structurally older and would conflict with main's evolved auth.ts. |
| `3bab1b1` | S68 hardening v1.13.1 (23 files, tagged v1.13.1) | **partial-overlap, gaps remain** | Some patterns landed on main via the Pass 30—59 closeouts; other patterns are missing (see "Missing patterns" below). The tag `v1.13.1` on this commit is orphan — not on main. The marketplace release is built from main, not the tag. |
| `12432d6` | S67 Phase 7 closure tables + CHANGELOG v1.13.0 | **superseded** | Main has its own evolved CHANGELOG and ADVERSARIAL_REVIEW.md from the Pass 30—59 closeouts. |
| `d736b12` | S67 final dist rebuild | **obsolete** | `dist/` is gitignored on main; rebuilt fresh from source on every `.mcpb` archive. |
| `c9e43c2` | F-S67-31 remove stale tests/ | **partially landed, has value** | The stale `tests/security.test.ts` (legacy location) still exists on main as of 2026-05-03; `src/__tests__/*.test.ts` is the live path that `npm test` runs against. Cherry-pick deferred to next sprint as a cleanup item. |
| `7330871` | F-S67-30 regenerate package-lock.json | **obsolete** | Main has its own evolved lockfile; would just produce a merge conflict. |
| `6841581` | F-S67-3,F-S67-49 rebuild dist + exclude tests from tsconfig (14 files; bundles many F-S67-X) | **partial-overlap, gaps remain** | See "Missing patterns" below. |
| `1646c2b`, `509f389`, `b234124`, `d7e1d61`, `03aa9f1`, `c046674`, `6d97f6a`, `6df73ea`, `70de7d0`, `30f409e`, `6caa498`, `5966cbf`, `ef9f386`, `3092686`, `3abad10`, `a7f6a0a`, `ac9679a`, `a01cb3e`, `54b9a06`, `fd15d5f`, `81ee470`, `6bfed78` | empty bookmark commits | **no content** | These 22 commits are message-only F-S67-X bookmarks; the actual code lives in `6841581` and `3bab1b1`. Nothing to reconcile commit-by-commit. |

### Patterns landed on origin/main

Sampled by grepping `src/tools.ts` and `src/audit.ts` on main for the
documented F-S67-X intent:

- **F-S67-1** — bump to 1.13.0 — landed (main is at 1.13.0; F009 closeout commit `66b7fee` keeps the VERSION constant in sync).
- **F-S67-4** — reg.exe blocked — landed.
- **F-S67-6** — `pythonN.M` versioned launcher pattern — landed.
- **F-S67-8** — groovy/scala/lua/julia/Rscript -e inline eval blocked — landed.
- **F-S67-50** — audit.ts secret prefix vs value-shape split — landed.

### Missing patterns — value worth cherry-picking

These F-S67-X patterns are absent from origin/main and represent real
Windows / general security hardening that didn't survive the protocol
cutover:

- **F-S67-5** — block `Add-MpPreference` / `Set-MpPreference`
  Defender-exclusion cmdlets (otherwise an attacker with command access
  can register an exclusion path and then drop a payload there).
- **F-S67-7** — block package-installer fronts that LOLBin-shell to
  `cmd.exe` /`sh`: `pip3`, `pipx`, `poetry`, `conda`,
  `mamba`, `uv`.
- **F-S67-9** — block `tar --absolute-names` / `-P` (allows tar
  to write outside the current directory — privilege-escalation if the
  tar runs as a higher-privilege process).
- **F-S67-25** — block PuTTY-family exfil (`pscp`, `plink`,
  `psftp`, `puttygen`) and cloud upload tools (`aws s3`,
  `gsutil`, `azcopy`, `rclone`).
- **F-S67-26** — block `/proc/<pid>/environ` and
  `/proc/<pid>/cmdline` info-leak paths (LT runs on Windows so direct
  applicability is low; included for cross-platform parity if a Linux
  build ships).

### Decision and next step

Backup branch **kept** (not deleted) at `s67-s68-stale-fork-backup`
on the remote. The five missing patterns above should be cherry-picked
in a follow-up remediation sprint by re-deriving each pattern as a
fresh commit on top of current main (not by `git cherry-pick`, which
would heavily conflict). Each cherry-pick should land with its own
`security:`-prefixed commit, a regression test in
`src/__tests__/bypass-corpus.test.ts`, and a `F-LT-XX` finding row
in the central `findings.csv`.

**Tag move 2026-05-03 (post version-string sweep).** The `v1.13.1` tag
was moved off the orphan commit `3bab1b1` to the legitimate release
commit on main (`e03ae70 build(mcpb): migrate manifest to v0.4 schema`,
which is the commit at HEAD when the .mcpb archive was built). Sequence:

  1. `git tag -d v1.13.1` (deletes locally; was pointing at `3bab1b1`)
  2. `git push origin :refs/tags/v1.13.1` (deletes from origin)
  3. `git tag -a v1.13.1 -m '...' e03ae70` (retags on main)
  4. `git push origin v1.13.1`

The underlying orphan commit `3bab1b1` is preserved on
`s67-s68-stale-fork-backup` (verified: `git branch --contains 3bab1b1`
returns the backup branch). Only the tag pointer moved; the commit
itself is reachable.

Practical impact of the force-move: near-zero. Per the F008 audit
context the plugin had 0 customer installs in the wild at the moment
of the cutover, so no clone has the old tag cached in a way that
matters. Anyone re-cloning post-move sees the new tag; anyone with a
stale local clone can `git fetch --prune-tags` to reconcile.
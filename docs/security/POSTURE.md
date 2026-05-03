# local-terminal-mcp — security posture

Snapshot date: 2026-05-03 (final pre-marketplace audit).
Per-repo posture for `local-terminal-mcp` only. The family-level
umbrella covering all three ForgeRift repos lives in
[forgerift-license-api/docs/security/POSTURE.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/POSTURE.md);
read that first for cross-cutting context.

## Scope

`local-terminal-mcp` is a stdio MCP plugin that gives Claude controlled,
audited access to a Windows machine's shell. It runs on the customer's
PC under the user's own UID. The plugin is published as an `.mcpb`
archive built from this repo's `main` branch.

## Findings owned by this repo

| ID | Severity | Status | Area | One-liner |
|---|---|---|---|---|
| F008 | CRITICAL | fixed `0fca724` (this repo) + `b26b253` (api) | auth | Plugin sends `product_id`, fails closed on registry-read failure, uses `execFileSync` for the registry probe |
| F009 | MAJOR | fixed `66b7fee` (this repo) + `82aeac4` (api) | version | `src/index.ts` `VERSION` constant aligned with `package.json` (1.13.0) |

The audit's other findings (F001-F006, F007, F010-F013) sit on
`forgerift-license-api` or `vps-control-mcp`; they're tracked in the
central `findings.csv` because the audit covers all three repos as
one product family.

## Hardening shipped in this audit

### F008 close-out (commit `0fca724`)

The original audit was written against a stale local fork that still
had the v1.12.0 sslip.io shape in `src/auth.ts`. On `origin/main`
the protocol switch had already shipped at v1.13.0 (commit `6da77d1`)
— POST + JSON to `payments.forgerift.io` with a SHA-256(MachineGuid)
machine fingerprint. Three remaining gaps closed in `0fca724`:

1. Plugin now sends `product_id = "prod_UPLLbMa79v84EI"` (the
   `local-terminal-mcp` Stripe product). The Worker's
   `register_activation_with_cap` returns `product_mismatch` when a
   license bound to a different product activates against this plugin
   — so a stolen LT license can't be smuggled into the VPS plugin
   and vice versa. Bundle subscriptions store NULL `product_id` on
   the license row (per F013 in license-api) so the Bundle activates
   both plugins.
2. `getMachineId()` no longer falls back to `os.hostname()` on a
   registry-read failure. A stable cross-machine fingerprint would
   defeat the per-machine activation cap; the plugin now fails closed
   with a clear "could not read MachineGuid" startup error.
3. `execSync(string)` -> `execFileSync(argv)` for the `reg.exe`
   probe. The argv form skips `cmd.exe` parsing and `%PATH%` /
   `%PATHEXT%` resolution, so a hostile environment can't substitute
   a different `reg.exe` to short-circuit the machine-id read.

End-to-end smoke against the live Worker via synthetic license keys
seeded + cleaned up through Supabase: bad key -> "License key not
found"; LT-bound key -> 200 + valid:true + activation registered; VPS-
bound key -> "different product" deny + no activation row; rerun on
same machine -> idempotent already_active. `npm test` 421/421 pass.

### F009 close-out (commit `66b7fee`)

`src/index.ts` hard-coded `VERSION = "1.12.2"` while `package.json`
had moved to 1.13.0 via `6da77d1`. Customers installing the 1.13.0
`.mcpb` saw the MCP server identify itself as 1.12.2 in the
`initialize` response, breaking version-sensitive client logic and
making support tickets confusing. `VERSION` is now `1.13.0` with a
sync-reminder comment for future bumps. `dist/` is gitignored and
rebuilt fresh on every archive. `npm test` 421/421 pass post-bump.

## Stale-fork backup branch

A `s67-s68-stale-fork-backup` branch holds 28 unpushed commits from
the local working copy that the F008 audit was originally written
against (against the v1.12.0 sslip.io shape). Per-commit reconciliation
decisions live in [methodology.md](methodology.md) under
"2026-05-03 — stale-fork backup branch reconciliation". Headline:

  - **Branch kept** (not deleted), preserved on the remote.
  - The orphan `v1.13.1` tag at `3bab1b1` does not point at any
    release-buildable revision of main. Next on-main release will be
    `1.13.1` driven by the F009 fix, not by promoting the orphan tag.
  - Five F-S67-X security patterns from the backup branch are documented
    as missing on main (F-S67-5 Add-MpPreference, F-S67-7 pip/poetry
    installers, F-S67-9 tar --absolute-names, F-S67-25 PuTTY + cloud
    upload, F-S67-26 /proc/environ). They should be re-derived as fresh
    `security:`-prefixed commits on top of main, not cherry-picked
    via `git cherry-pick` (would heavily conflict with main's evolved
    `tools.ts` / `audit.ts`).

These are tracked as a follow-up remediation sprint after marketplace
submission. They're not marketplace blockers (the absent patterns
expand the deny coverage rather than close a known active bypass).

## Command-execution model

The plugin runs every shell command through a three-layer pipeline:

1. **BLOCKED tier** — extensive deny patterns covering eval, eval-
   adjacent forms (`-c`, `-Command`, `-EncodedCommand`, `-File`,
   etc.), escape characters, code-exec hooks, sensitive file paths,
   credential-helper subversion, symbol/junction primitives, registry
   write, AV/EDR-disable cmdlets, etc. tier=red, refused.

2. **ALLOWLIST gate** — the binary must be on the positive allowlist
   AND its argv must pass that binary's specific arg validator (e.g.
   `curl` URLs must be `localhost` / `127.0.0.1` / `[::1]`;
   `git` flags must not be in the file-read or code-exec set;
   `npm` is read-only — `ls`, `view`, `outdated`).

3. **AMBER vs GREEN tier** — elevated-risk-but-allowed commands
   surface a warning the user must acknowledge via dry-run before
   execution; the rest go through `execFileSync(shell:false)` with a
   scrubbed env (allowlist of safe vars, `COMSPEC` pinned to
   `System32\cmd.exe`).

Output passes through `scrubSecrets()` before reaching the model.

## Test coverage

`npm test` runs 421 cases across 70 suites covering the deny list, the
allowlist, the per-binary arg validators, and the bypass-corpus
regression suite. Every new bypass class gets a row in
`src/__tests__/bypass-corpus.test.ts` and never re-occurs.

## Continuous monitoring

- `npm audit` re-run on dependency bumps (Cloudflare Workers + Anthropic
  SDK + dotenv only; deps are intentionally minimal).
- `npm test` runs in pre-commit hook (`.githooks/pre-commit`)
  alongside `dist` freshness verification and the merge-conflict
  artifact guard.
- License-validation telemetry lands in the central `license_events`
  Supabase table; bad keys / version drift / product-mismatch hits
  alert the operator via the cron sweep at
  `forgerift-license-api` (`[triggers]` in `wrangler.toml`).

## Methodology + raw evidence

- Cross-repo methodology lives in
  [forgerift-license-api/docs/security/methodology.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/methodology.md).
- Repo-local methodology notes (currently the stale-fork reconciliation):
  [methodology.md](methodology.md).
- Central `findings.csv` carries F008 + F009 rows with status,
  fix_commit, evidence path. Lives in the umbrella repo at
  `forgerift-license-api/docs/security/findings.csv`.

## Marketplace-submission readiness

- All findings owned by this repo are fixed.
- Central `findings.csv` has zero `open-needs-dustin` rows.
- `security:` commits pushed to `origin/main`: `0fca724` (F008),
  `66b7fee` (F009), `8f57fc1` (docs scaffold + stale-fork
  reconciliation).
- POSTURE + WHITEPAPER + methodology in place.
- `npm test` 421/421 pass on `HEAD`.
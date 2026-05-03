# local-terminal-mcp — security whitepaper

How `local-terminal-mcp` keeps Claude's access to your Windows shell
audited, deny-listed, and bounded. Intended for prospective customers,
security reviewers, and Anthropic's marketplace review.

This whitepaper covers the `local-terminal-mcp` plugin specifically.
The family-level overview (license issuance, the validation backend,
the cross-product threat model) lives in
[forgerift-license-api/docs/security/WHITEPAPER.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/WHITEPAPER.md).

## What this plugin does (and what it does not)

`local-terminal-mcp` is a Model Context Protocol server that exposes a
small surface to Claude:

  - `run_command` — execute one binary with one argv on the user's
    PC, sync, returning stdout + stderr + exit code.
  - `run_powershell` — same, but the binary is pinned to
    PowerShell and the input is treated as a script body.
  - `list_directory` — read-only directory listing with the
    sensitive-path guard.
  - `read_file` — read-only text-file read with the sensitive-path
    guard, max 500 lines / call.
  - `find_files` — recursive name-pattern search.
  - `search_file` — grep-equivalent inside one file or directory.
  - `run_git_command`, `run_npm_command` — curated-allowlist
    wrappers around git and npm with the deny patterns layered on top.

It does **not** expose:

  - Arbitrary network access (egress binaries are denylisted; `curl`
    is allowlist-restricted to `localhost` / `127.0.0.1` / `[::1]`).
  - Privilege escalation (run-as verbs, user-account mutation, service
    create / config, scheduled-task create / modify, AV / EDR exclusion
    cmdlets, symbolic-link / junction primitives, registry write).
  - Credential read (Credential Manager, certificate export, the SAM
    hive, browser credential stores, ssh-keygen).

## Threat model

Three threats drive the design:

1. **Prompt injection.** A page or file convinces Claude to issue a
   destructive command (recursive root delete, Defender disable,
   user-account add, etc.). Mitigation: the plugin's deny list fires
   before the binary is launched. Claude can suggest the command, the
   plugin refuses the execution.

2. **Compromised model variant.** A future Claude variant or a hostile
   fine-tune does the wrong thing. Mitigation: the plugin enforces
   the policy; the model never sees the policy code, only the deny
   message. Audit log captures every command + tier so any drift is
   visible after the fact.

3. **License key theft and sharing.** A bad actor steals the customer's
   license key or the customer shares it. Mitigation: the
   `forgerift-license-api` backend binds each license to a Stripe
   product, and the plugin sends `product_id` on every validation
   call so a key bound to a different product (e.g. a stolen
   `vps-control-mcp` key) is denied with `product_mismatch`.
   Per-machine activation cap is enforced atomically by a Postgres
   stored proc; a license-sharing cron sweep alerts the operator
   if one key shows up on >=5 distinct machines in 24h.

## Command pipeline detail

Every call into `run_command` / `run_powershell` / the curated
wrappers traverses three layers.

### Layer 1: BLOCKED tier (deny-first)

A regex deny list drawn from sixteen-plus prior security passes covers,
without quoting the literal exploit forms here:

  - Eval and eval-adjacent forms across every interpreter the plugin
    might exec (Node, Python, Perl, Ruby, Groovy, Scala, Lua, Julia,
    Rscript, plus PowerShell command-string / encoded-command / file
    invocation / Invoke-Expression / Invoke-Command / Add-Type forms).
  - Download cradles: web-request + out-file, in-memory string download,
    BITS Transfer, urlcache-mode certutil.
  - LOLBins and shell-out fronts: regsvr32 registration verbs, rundll32
    arbitrary-DLL exec, mshta, wmic call verbs, mofcomp, installutil.
  - Registry write, exec policy mutation, environment manipulation,
    scheduled-task and service create / modify, AV / EDR exclusion
    cmdlets.
  - Filesystem destruction patterns at root scope, recursive force-remove
    of system roots, secure-delete / cipher-wipe verbs, partition
    management.
  - Symbolic-link / junction primitives that could escape the working
    directory (`mklink`, `New-Item -ItemType SymbolicLink`,
    `New-Item -ItemType HardLink`, POSIX symlink).

Match in this layer = `tier=red`, refused, audit-logged with the
matched pattern + the input.

### Layer 2: ALLOWLIST gate

For commands that survive Layer 1, the binary itself must be on the
positive allowlist (`cmd.exe`, `powershell.exe`, `git`, `npm`,
`node`, `python`, `curl`, `dir`, `type`, `where`,
`findstr`, ...).

Each allowed binary has its own argv validator. Examples:

  - `curl` — URL must resolve to `localhost` / `127.0.0.1` /
    `[::1]`; the validator walks every arg, normalises `--key=value`
    to its value half, matches URLs by substring, also covers
    `--proxy=URL` (this is the post-F010 shape after the bypass fix
    in `vps-control-mcp`; the same validator structure is used here).
  - `git` — upload-pack / receive-pack / askpass / credential-helper
    / protocol-ext config flags are stripped; repo-local hooks are
    neutralised by pre-pending `-c core.hooksPath=NUL`.
  - `npm` — read-only sub-commands only (`ls`, `view`,
    `outdated`, `audit`); install / ci / publish / run / exec are
    denied.

### Layer 3: AMBER warning vs GREEN execution

A small set of commands — `git push`, hard-reset, file deletes
inside the working directory, etc. — fall into AMBER tier: they're
allowed but require a dry-run-first confirmation (the model sees a
"would execute" preview and the user must explicitly proceed).

GREEN-tier commands execute immediately via
`execFileSync(binary, argv, { shell: false })` with:

  - A scrubbed environment (allowlist of safe vars; sensitive ones like
    `COMSPEC` are pinned to `System32\cmd.exe` so a hostile env
    can't redirect cmd.exe lookups).
  - A bounded timeout per binary type.
  - `stdout` + `stderr` captured, run through `scrubSecrets()`
    (which redacts patterns matching API key / token / connection-
    string shapes).
  - Audit log entry with binary, argv, tier, exit code, output length,
    and the scrubbed-secret count.

## Authentication / licensing

On startup, the plugin reads `LT_LICENSE_KEY` from env and POSTs to
`https://payments.forgerift.io/validate` with:

```json
{
  "license_key":     "FRFT-XXXX-XXXX-XXXX-XXXX",
  "machine_id":      "<sha256 of MachineGuid>",
  "product_id":      "prod_UPLLbMa79v84EI",
  "plugin_version":  "1.13.0"
}
```

The Worker hashes the key once more, looks up the license, then calls
the `register_activation_with_cap` Postgres proc which atomically:

  - checks status (active / past_due tolerated within grace,
    expired / revoked rejected),
  - checks the product_id binding (NULL on the row = permissive,
    enabling Bundle subscriptions to satisfy both plugins),
  - checks the per-machine activation cap (default max=1; first machine
    "wins" the slot until the operator deactivates it),
  - registers the activation if needed, increments the counter,
  - returns `ok` / `already_active` / `deactivated` /
    `cap_exceeded` / `product_mismatch`.

If validation fails the plugin exits with a clear error message
pointing the user at `forgerift.io` to manage their subscription.
The plugin never serves any tools to Claude before validation
succeeds.

### Machine fingerprint

The fingerprint is `SHA-256(MachineGuid)` where `MachineGuid` comes
from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` via
`execFileSync('reg.exe', argv)`.

The argv form (not the string form) is used so a hostile `%PATH%`
or `%PATHEXT%` can't substitute a different `reg.exe`. The
plugin fails closed if the registry read fails — no
`os.hostname()` fallback, which would defeat the per-machine cap by
serving a stable cross-machine fingerprint when the registry probe
errored. Both behaviours shipped in the F008 close-out (commit
`0fca724`).

## Data handling

The plugin never sends raw shell output, paths, or filenames anywhere
external. The only outbound HTTP it makes is the validation call to
`payments.forgerift.io`, and that carries only the license key, the
double-hashed machine id, the product id, and the plugin version.

Audit logs are local: a JSONL file under
`%LOCALAPPDATA%\local-terminal-mcp\audit.log`, rotated by size, one
line per shell call. Operator can ship them off-machine via their own
log-collection setup if desired; the plugin doesn't.

## Reporting a vulnerability

See [SECURITY.md](../../SECURITY.md) at the repo root.
`support@forgerift.io`, 90-day coordinated disclosure.

## Audit cadence

Posture refreshes on every commit prefixed `security:`. The central
`findings.csv` (in `forgerift-license-api/docs/security/`) is the
machine-readable cross-repo view; the repo-local
[POSTURE.md](POSTURE.md) is the per-repo summary. Re-runs of
`npm audit` and `npm test` are gated by the pre-commit hook in
`.githooks/pre-commit`.
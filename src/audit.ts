import { appendFileSync, mkdirSync, existsSync, statSync, unlinkSync, renameSync } from "fs";
import { join, normalize } from "path";

// D7: Validate MCP_LOG_DIR at startup — reject paths that would silently
// disable or compromise the audit trail.
function validateLogDir(p: string): string {
  const n = normalize(p).toLowerCase();
  const FORBIDDEN = ['/dev/null', '/dev/zero', '/dev/random', 'nul', 'con', '/dev/stdout', '/dev/stderr'];
  if (FORBIDDEN.includes(n)) {
    throw new Error(`MCP_LOG_DIR "${p}" is a forbidden sink — audit logging would be silently disabled.`);
  }
  if (n.startsWith('/tmp/') || n.startsWith('/var/tmp/') || n === '/tmp' || n === '/var/tmp') {
    throw new Error(`MCP_LOG_DIR "${p}" is in a world-writable temp directory — use a hardened log path.`);
  }
  return p;
}

const LOG_DIR  = validateLogDir(process.env.MCP_LOG_DIR ?? join(process.cwd(), "logs"));
const LOG_FILE = join(LOG_DIR, "audit.log");

// Maximum audit log size before rotation (10 MB default, configurable via AUDIT_MAX_SIZE_MB)
const MAX_AUDIT_BYTES = (parseInt(process.env.AUDIT_MAX_SIZE_MB || '10', 10)) * 1024 * 1024;

try { mkdirSync(LOG_DIR, { recursive: true }); } catch {}

export function auditLog(
  tool: string,
  args: Record<string, unknown>,
  tier: "green" | "amber" | "red",
  blocked: boolean,
  dryRun = false
): void {
  const entry = JSON.stringify({
    ts:      new Date().toISOString(),
    tool,
    tier,
    blocked,
    dry_run: dryRun,
    args:    JSON.stringify(sanitizeArgs(args)).slice(0, 300),
  });

  try {
    rotateIfNeeded();
    appendFileSync(LOG_FILE, entry + "\n");
  } catch {
    // Never crash the server over an audit write failure — log to stdout instead
    console.error('[AUDIT FAIL]', entry);
  }

  // Console summary
  const prefix = blocked ? '⛔ BLOCKED' : tier === 'amber' ? '⚠️  AMBER' : '✓';
  console.log(`[audit] ${prefix} ${tier}${dryRun ? " (dry_run)" : ""} → ${tool}`);
}

// Strip values that look like secrets before logging args
// F-LT-85 (S54): extended token-shape list to align with SECRET_OUTPUT_PATTERNS in tools.ts.
// Audit log is in the trust boundary; missing a token prefix here means a secret survives
// in plaintext in audit.log even though tools.ts scrubs it from tool output.
const SECRET_VALUE_PREFIXES = /^(?:sk-|Bearer |eyJ|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|xoxe\.xox[bp]-|glpat-|sbp_|supabase_svcRole_|AKIA|ASIA|AIza|pk_live_|pk_test_|sk_live_|sk_test_|rk_live_|rk_test_|whsec_|SG\.|ATATT|ATCTT|do_v1_|dop_v1_|dockercfg\.|sq0[ac][st]p-|key-[0-9a-f]{32}|ya29\.|1\/\/|AC[a-z0-9]{32}|npm_[A-Za-z0-9]{36}|-----BEGIN )/i;
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string' && (
      /token|secret|key|password|auth|credential|bearer|api[_-]?key|cookie|session/i.test(k) ||
      SECRET_VALUE_PREFIXES.test(v)
    )) {
      clean[k] = '[REDACTED]';
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

// Simple rotation: when the log exceeds MAX_AUDIT_BYTES, rename to .old and start fresh.
// Checked at most once per 60 seconds to avoid stat() on every call.
let lastRotationCheck = 0;
function rotateIfNeeded(): void {
  const now = Date.now();
  if (now - lastRotationCheck < 60_000) return;
  lastRotationCheck = now;

  try {
    if (!existsSync(LOG_FILE)) return;
    const stats = statSync(LOG_FILE);
    if (stats.size >= MAX_AUDIT_BYTES) {
      const oldPath = LOG_FILE + '.old';
      if (existsSync(oldPath)) unlinkSync(oldPath);
      renameSync(LOG_FILE, oldPath);
      console.log(`[local-terminal-mcp] Audit log rotated (${Math.round(stats.size / 1024 / 1024)}MB). Old log: ${oldPath}`);
    }
  } catch {
    // Rotation failure is non-fatal
  }
}

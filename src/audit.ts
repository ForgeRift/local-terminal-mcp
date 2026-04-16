import { appendFileSync, mkdirSync, existsSync, statSync, unlinkSync, renameSync } from "fs";
import { join } from "path";

const LOG_DIR  = process.env.MCP_LOG_DIR ?? join(process.cwd(), "logs");
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
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string' && (
      /token|secret|key|password|auth/i.test(k) ||
      /^sk-|^Bearer |^eyJ/i.test(v)
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

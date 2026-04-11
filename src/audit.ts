import { appendFileSync, mkdirSync } from "fs";
import { join } from "path";

const LOG_DIR  = process.env.MCP_LOG_DIR ?? join(process.cwd(), "logs");
const LOG_FILE = join(LOG_DIR, "audit.log");

try { mkdirSync(LOG_DIR, { recursive: true }); } catch {}

export function auditLog(
  tool: string,
  args: Record<string, unknown>,
  tier: "read" | "approved" | "escape_hatch",
  dryRun = false
): void {
  const entry = JSON.stringify({
    ts:      new Date().toISOString(),
    tool,
    tier,
    dry_run: dryRun,
    args,
  });
  try { appendFileSync(LOG_FILE, entry + "\n"); } catch {}
  console.log(`[audit] ${tier}${dryRun ? " (dry_run)" : ""} → ${tool}`);
}

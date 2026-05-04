import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import dotenv from "dotenv";
import { auditLog } from "./audit.js";
import { TOOLS, executeTool } from "./tools.js";
import { validateSubscription } from "./auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const PLUGIN_ROOT = join(__dirname, "..");

dotenv.config({ path: join(PLUGIN_ROOT, ".env") });

// F-STDIO-1: redirect all console.log/info/warn/debug to stderr so stdout stays
// clean for the MCP wire protocol. console.error already goes to stderr (safe).
const _origError = console.error.bind(console);
console.log = console.info = console.warn = console.debug = _origError;

// Kept in sync with package.json `version`. F009 (2026-05-03):
// the constant had drifted from "1.12.2" while package.json was at "1.13.0" (now 1.13.1),
// so MCP clients saw the wrong server version on `initialize`. Aligned
// to "1.13.2" in the v1.13.1 release sweep. If package.json is bumped
// further, this
// constant must move with it.
const VERSION = "1.13.2";

// ---------------------------------------------------------------------------
// Subscription validation -- required before serving any tools.
// Reads LT_LICENSE_KEY from env (set via manifest.json user_config or .env).
// ---------------------------------------------------------------------------
const licenseKey = process.env.LT_LICENSE_KEY;
if (!licenseKey) {
  process.stderr.write(
    "[local-terminal-mcp] LT_LICENSE_KEY is required. Visit forgerift.io to subscribe.\n"
  );
  process.exit(1);
}

try {
  await validateSubscription(licenseKey);
} catch (err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  // MachineGuid failures are environmental, not subscription problems --
  // route the user to TROUBLESHOOTING.md / support, not the billing portal.
  if (msg.includes("MachineGuid")) {
    process.stderr.write(`[local-terminal-mcp] Cannot start: ${msg}\n`);
  } else {
    process.stderr.write(`[local-terminal-mcp] Subscription check failed: ${msg}\n`);
    process.stderr.write("[local-terminal-mcp] Visit forgerift.io to manage your subscription.\n");
  }
  process.exit(1);
}

// ---------------------------------------------------------------------------
// MCP server setup
// ---------------------------------------------------------------------------
const server = new Server(
  { name: "local-terminal-mcp", version: VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  const { result, tier, blocked, dryRun } = await executeTool(name, args as Record<string, unknown>);
  auditLog(name, args as Record<string, unknown>, tier, blocked, dryRun);
  return { content: [{ type: "text", text: result }] };
});

// F-STDIO-5: graceful SIGTERM/SIGINT -- allow in-flight audit writes to complete.
function shutdown(signal: string) {
  process.stderr.write("[local-terminal-mcp] " + signal + " received, shutting down\n");
  setTimeout(() => process.exit(0), 500);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

const transport = new StdioServerTransport();
server.connect(transport).catch((err: Error) => {
  // F-STDIO-4: sanitize path-like substrings before writing to stderr.
  const safe = err.message.replace(/[A-Za-z]:[\\\/][^\s]*/g, "<path>").slice(0, 200);
  process.stderr.write("[local-terminal-mcp] Fatal transport error: " + safe + "\n");
  process.exit(1);
});
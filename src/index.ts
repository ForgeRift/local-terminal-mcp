import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import dotenv from "dotenv";
import { auditLog } from "./audit.js";
import { TOOLS, executeTool } from "./tools.js";

// F-STDIO-2: anchor .env and audit dir to plugin install dir, not Claude Desktop cwd.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PLUGIN_ROOT = join(__dirname, "..");

dotenv.config({ path: join(PLUGIN_ROOT, ".env") });

// F-STDIO-1: redirect all console.log/info/warn/debug to stderr so stdout stays
// clean for the MCP wire protocol. console.error already goes to stderr (safe).
const _origError = console.error.bind(console);
console.log = console.info = console.warn = console.debug = _origError;

const VERSION = "1.11.0";

// Transport: stdio (required for .mcpb desktop extension packaging).
// Security:  RED/AMBER/GREEN three-tier model enforced in tools.ts on every call.
// Audit:     Every tool invocation written to logs/audit.log via audit.ts.
// Auth:      Not applicable -- stdio transport is spawned directly by Claude Desktop;
//            no network socket is exposed.

const server = new Server(
  { name: "local-terminal-mcp", version: VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  const { result, tier, blocked, dryRun } = await executeTool(
    name,
    args as Record<string, unknown>
  );
  auditLog(name, args as Record<string, unknown>, tier, blocked, dryRun);
  return { content: [{ type: "text", text: result }] };
});

// F-STDIO-4: sanitize error message before writing to stderr (avoid leaking paths).
// F-STDIO-5: graceful SIGTERM/SIGINT -- flush audit, then exit.
function shutdown(signal: string) {
  process.stderr.write("[local-terminal-mcp] " + signal + " received, shutting down\n");
  // Allow any in-flight audit writes to complete (synchronous), then exit cleanly.
  setTimeout(() => process.exit(0), 500);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

const transport = new StdioServerTransport();
server.connect(transport).catch((err: Error) => {
  // Sanitize path-like substrings before surfacing in stderr / diagnostics.
  const safe = err.message.replace(/[A-Za-z]:[\\\/][^\s]*/g, "<path>").slice(0, 200);
  process.stderr.write("[local-terminal-mcp] Fatal transport error: " + safe + "\n");
  process.exit(1);
});

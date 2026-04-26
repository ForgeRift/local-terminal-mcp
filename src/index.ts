import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dotenv from "dotenv";
import { auditLog } from "./audit.js";
import { TOOLS, executeTool } from "./tools.js";

dotenv.config();

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

// Connect -- stdout is reserved for MCP wire protocol in stdio mode.
const transport = new StdioServerTransport();
server.connect(transport).catch((err: Error) => {
  process.stderr.write("[local-terminal-mcp] Fatal transport error: " + err.message + "\n");
  process.exit(1);
});

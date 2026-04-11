import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dotenv from "dotenv";
import { PORT, validateConfig } from "./config.js";
import { validateAuth } from "./auth.js";
import { auditLog } from "./audit.js";
import { TOOLS, executeTool } from "./tools.js";

dotenv.config();
validateConfig();

// ─── Express App ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (!validateAuth(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

// Active SSE transports keyed by sessionId
const transports = new Map<string, SSEServerTransport>();

// SSE connection — one fresh Server instance per connection
app.get("/sse", requireAuth, async (req, res) => {
  const mcpServer = new Server(
    { name: "local-terminal-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const { result, tier, dryRun } = await executeTool(name, args as Record<string, unknown>);
    auditLog(name, args as Record<string, unknown>, tier, dryRun);
    return { content: [{ type: "text", text: result }] };
  });

  const transport = new SSEServerTransport("/message", res);
  transports.set(transport.sessionId, transport);
  res.on("close", () => transports.delete(transport.sessionId));
  await mcpServer.connect(transport);
});

// Message endpoint — tool call POSTs from Claude
app.post("/message", requireAuth, async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = transports.get(sessionId);
  if (!transport) {
    res.status(404).json({ error: "Session not found. Re-connect via /sse." });
    return;
  }
  await transport.handlePostMessage(req, res, req.body);
});

// Health check — no auth required
app.get("/health", (_req, res) => {
  res.json({
    status:    "ok",
    uptime_s:  Math.round(process.uptime()),
    sessions:  transports.size,
    version:   "1.0.0",
  });
});

// ─── Start — localhost only ────────────────────────────────────────────────────

app.listen(PORT, "127.0.0.1", () => {
  console.log(`[local-terminal-mcp] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[local-terminal-mcp] Auth token: SET`);
});

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dotenv from "dotenv";
import { PORT, RATE_LIMIT_PER_MIN, validateConfig } from "./config.js";
import { validateAuth } from "./auth.js";
import { auditLog } from "./audit.js";
import { TOOLS, executeTool } from "./tools.js";

dotenv.config();
validateConfig();

const VERSION = "1.2.0";

// ─── Rate Limiting ────────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS = 60_000;
const rateLimitBuckets = new Map<string, number[]>();

function checkRateLimit(token: string): boolean {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(token) || [];
  const filtered = bucket.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  if (filtered.length >= RATE_LIMIT_PER_MIN) return false;
  filtered.push(now);
  rateLimitBuckets.set(token, filtered);
  return true;
}

// Clean up old rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, bucket] of rateLimitBuckets.entries()) {
    const filtered = bucket.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    if (filtered.length === 0) rateLimitBuckets.delete(token);
    else rateLimitBuckets.set(token, filtered);
  }
}, 5 * 60_000);

// ─── Express App ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// CORS headers
app.use((_req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  if (_req.method === 'OPTIONS') { res.sendStatus(204); return; }
  next();
});

function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (!validateAuth(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  // Rate limit check
  const token = (req.headers['authorization'] || '').slice(7);
  if (!checkRateLimit(token)) {
    res.status(429).json({ error: "Rate limit exceeded. Try again in a moment." });
    return;
  }

  next();
}

// Active SSE transports keyed by sessionId
const transports = new Map<string, SSEServerTransport>();

// SSE connection — one fresh Server instance per connection
app.get("/sse", requireAuth, async (req, res) => {
  const mcpServer = new Server(
    { name: "local-terminal-mcp", version: VERSION },
    { capabilities: { tools: {} } }
  );

  mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const { result, tier, blocked, dryRun } = await executeTool(name, args as Record<string, unknown>);
    auditLog(name, args as Record<string, unknown>, tier, blocked, dryRun);
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
    version:   VERSION,
  });
});

// ─── Start — localhost only ────────────────────────────────────────────────────

app.listen(PORT, "127.0.0.1", () => {
  console.log(`[local-terminal-mcp] v${VERSION} listening on http://127.0.0.1:${PORT}`);
  console.log(`[local-terminal-mcp] Auth: SET | Rate limit: ${RATE_LIMIT_PER_MIN}/min`);
  console.log(`[local-terminal-mcp] Security: RED/AMBER/GREEN three-tier model active`);
});

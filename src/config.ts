import { randomBytes } from "crypto";

// Port for local MCP server — localhost only, not exposed to network
export const PORT = parseInt(process.env.MCP_PORT ?? "3002", 10);

// Auth token — generated once on first run, stored in .env
export const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? "";

// Rate limiting: requests per minute per token (configurable via RATE_LIMIT_PER_MIN)
export const RATE_LIMIT_PER_MIN = parseInt(process.env.RATE_LIMIT_PER_MIN || '120', 10);

// Audit log max size in MB before rotation
export const AUDIT_MAX_SIZE_MB = parseInt(process.env.AUDIT_MAX_SIZE_MB || '10', 10);

// Validate required env
export function validateConfig(): void {
  if (!AUTH_TOKEN) {
    console.error("FATAL: MCP_AUTH_TOKEN is not set.");
    console.error("Run setup.ps1 to configure the service, or set MCP_AUTH_TOKEN in .env");
    process.exit(1);
  }
}

// Generate a secure random token (used by setup script)
export function generateToken(): string {
  return randomBytes(32).toString("hex");
}

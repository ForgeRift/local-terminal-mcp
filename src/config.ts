import { randomBytes } from "crypto";

// Port for local MCP server — localhost only, not exposed to network
export const PORT = parseInt(process.env.MCP_PORT ?? "3002", 10);

// Auth token — generated once on first run, stored in .env
export const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? "";

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

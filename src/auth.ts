// auth.ts -- subscription validation for stdio transport (v1.13.0)
// Called once on startup before server.connect(). Exits if subscription is invalid.
//
// Changes from v1.12.0:
//   - Switched from GET ?token= to POST with JSON body (key never appears in URLs / logs)
//   - Added machine fingerprinting via Windows MachineGuid (pre-hashed with SHA-256)
//
// The validation endpoint: https://payments.forgerift.io/validate
// Enforces 1 machine per license key. The machine_id is double-hashed server-side
// so ForgeRift never stores the raw MachineGuid.

import https from "https";
import { createHash } from "crypto";
import { execSync } from "child_process";
import os from "os";

const VALIDATE_HOSTNAME = "payments.forgerift.io";
const VALIDATE_PATH     = "/validate";
const TIMEOUT_MS        = 12_000;
const VERSION           = "1.13.0"; // sent with each validation for telemetry / support

// -- Machine fingerprint -------------------------------------------------------

/**
 * Derive a stable machine identifier and hash it with SHA-256.
 * Primary source: Windows MachineGuid from registry (stable across reboots,
 * unique per OS install). Fallback: hostname (less stable, no registry access).
 *
 * The raw GUID/hostname is never transmitted -- only its SHA-256 hex digest.
 * The server additionally hashes the received digest, so ForgeRift's DB
 * contains SHA-256(SHA-256(rawGuid)) -- two layers removed from the source.
 */
function getMachineId(): string {
  let raw = "";

  try {
    const out = execSync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
      { timeout: 3000, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }
    ).toString();
    const match = /MachineGuid\s+REG_SZ\s+([0-9a-f\-]{36})/i.exec(out);
    if (match) raw = match[1].toLowerCase();
  } catch (_err) {
    // Non-Windows or permission failure -- fall through to hostname
  }

  if (!raw) {
    raw = os.hostname() || "unknown";
  }

  return createHash("sha256").update(raw).digest("hex");
}

// -- Validation request -------------------------------------------------------

interface ValidateResponse {
  valid:    boolean;
  message?: string;
  reason?:  string;
}

/**
 * POST the license key + machine fingerprint to the ForgeRift validation API.
 * Resolves on HTTP 200 + valid:true; rejects with a human-readable error otherwise.
 */
export async function validateSubscription(licenseKey: string): Promise<void> {
  const machineId = getMachineId();

  const payload = JSON.stringify({
    license_key:    licenseKey,
    machine_id:     machineId,
    plugin_version: VERSION,
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: VALIDATE_HOSTNAME,
        path:     VALIDATE_PATH,
        method:   "POST",
        timeout:  TIMEOUT_MS,
        headers:  {
          "Content-Type":   "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => { body += chunk; });
        res.on("end", () => {
          let parsed: ValidateResponse = { valid: false };
          try {
            parsed = JSON.parse(body) as ValidateResponse;
          } catch (_e) { /* keep default */ }

          if (res.statusCode === 200 && parsed.valid) {
            resolve();
          } else {
            const reason =
              parsed.reason ??
              parsed.message ??
              `HTTP ${res.statusCode ?? "unknown"}`;
            reject(new Error(reason));
          }
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Subscription check timed out. Check your network connection."));
    });

    req.on("error", (err: Error) => {
      // Sanitize path-like substrings before surfacing to stderr
      const safe = err.message
        .replace(/[A-Za-z]:[\\\/][^\s]*/g, "<path>")
        .slice(0, 150);
      reject(new Error(`Network error during subscription check: ${safe}`));
    });

    req.write(payload);
    req.end();
  });
}

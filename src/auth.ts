// auth.ts -- subscription validation for stdio transport (v1.13.1)
// Called once on startup before server.connect(). Exits if subscription is invalid.
//
// Changes from v1.12.0:
//   - Switched from GET ?token= to POST with JSON body (key never appears in URLs / logs)
//   - Added machine fingerprinting via Windows MachineGuid (pre-hashed with SHA-256)
//   - F008 (audit 2026-05-03): send product_id so the per-product license
//     binding shipped on the Worker actually fires; drop os.hostname()
//     fallback (fail closed -- a stable cross-machine fingerprint would
//     defeat the activation cap); switch execSync(string) to
//     execFileSync(argv) so a hostile %PATH% / %PATHEXT% can't substitute
//     a different reg.exe.
//
// The validation endpoint: https://payments.forgerift.io/validate
// Enforces 1 machine per license key. The machine_id is double-hashed server-side
// so ForgeRift never stores the raw MachineGuid.

import https from "https";
import { createHash } from "crypto";
import { execFileSync } from "child_process";

const VALIDATE_HOSTNAME = "payments.forgerift.io";
const VALIDATE_PATH     = "/validate";
const TIMEOUT_MS        = 12_000;
const VERSION           = "1.13.2"; // sent with each validation for telemetry / support

// Stripe product id for local-terminal-mcp (live mode).
// vps-control-mcp uses prod_UPLLq4Yfv880Se; the Bundle uses prod_UPLLQCpdUvZ0cl.
// Hard-coded rather than env-derived so a misconfigured environment can't
// silently weaken the per-product binding.
const PRODUCT_ID = "prod_UPLLbMa79v84EI";

// -- Machine fingerprint -------------------------------------------------------

/**
 * Derive a stable machine identifier and hash it with SHA-256.
 * Source: Windows MachineGuid from registry (stable across reboots,
 * unique per OS install). The raw GUID is never transmitted -- only its
 * SHA-256 hex digest. The server additionally hashes the received digest,
 * so ForgeRift's DB contains SHA-256(SHA-256(rawGuid)) -- two layers
 * removed from the source.
 *
 * Fails closed on registry-read failure: a missing machine_id would make
 * the Worker's per-machine activation cap unenforceable. Caller surfaces
 * this as a "cannot validate license" startup error.
 *
 * Uses execFileSync against reg.exe directly (argv array, not a shell
 * string) so cmd.exe's parsing rules and a hostile %PATH% / %PATHEXT%
 * cannot be used to substitute a different reg.exe.
 */
function getMachineId(): string {
  let stdout: string;
  try {
    stdout = execFileSync(
      "reg.exe",
      ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"],
      {
        encoding:    "utf8",
        timeout:     3000,
        windowsHide: true,
        stdio:       ["ignore", "pipe", "ignore"],
      }
    );
  } catch {
    throw new Error(
      "Could not read MachineGuid from Windows registry " +
      "(HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid). " +
      "This usually means the plugin is running in a sandboxed or " +
      "containerized environment (e.g. Windows Sandbox) where the " +
      "registry value is not exposed. Install on a real Windows 10 " +
      "or Windows 11 machine. See TROUBLESHOOTING.md > \"MachineGuid " +
      "registry not readable\" or email support@forgerift.io."
    );
  }
  const match = /MachineGuid\s+REG_SZ\s+([0-9a-f\-]{36})/i.exec(stdout);
  if (!match) {
    throw new Error(
      "MachineGuid registry value is present but did not match the " +
      "expected GUID format. This is unusual on a stock Windows " +
      "install; it can happen in heavily customized or restricted " +
      "environments. See TROUBLESHOOTING.md > \"MachineGuid registry " +
      "not readable\" or email support@forgerift.io."
    );
  }
  return createHash("sha256").update(match[1].toLowerCase()).digest("hex");
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
  let machineId: string;
  try {
    machineId = getMachineId();
  } catch (e) {
    return Promise.reject(e instanceof Error ? e : new Error(String(e)));
  }

  const payload = JSON.stringify({
    license_key:    licenseKey,
    machine_id:     machineId,
    product_id:     PRODUCT_ID,
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

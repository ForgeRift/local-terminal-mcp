// auth.ts -- subscription validation for stdio transport (v1.12.0)
// Called once on startup before server.connect(). Exits if subscription is invalid.
// Uses the ForgeRift payments server as the validation oracle; Supabase service-role
// credentials stay server-side and are never embedded in the plugin binary.
import https from "https";
import { URL } from "url";

const VALIDATE_URL = "https://payments.forgerift.io/validate";
const TIMEOUT_MS   = 10_000;

/**
 * Validate a ForgeRift license key against the payments server.
 * Resolves on success (HTTP 200 + valid:true).
 * Rejects with a human-readable Error on any failure.
 */
export async function validateSubscription(licenseKey: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const url = new URL(VALIDATE_URL);
    url.searchParams.set("token", licenseKey);

    const req = https.request(
      {
        hostname: url.hostname,
        path:     url.pathname + url.search,
        method:   "GET",
        timeout:  TIMEOUT_MS,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => { body += chunk; });
        res.on("end", () => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            let reason = `HTTP ${res.statusCode}`;
            try {
              const parsed = JSON.parse(body) as { reason?: string };
              if (parsed.reason) reason = parsed.reason;
            } catch { /* ignore parse errors */ }
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
      // Sanitize path-like strings before surfacing
      const safe = err.message.replace(/[A-Za-z]:[\\\/][^\s]*/g, "<path>").slice(0, 150);
      reject(new Error(`Network error during subscription check: ${safe}`));
    });

    req.end();
  });
}
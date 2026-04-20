import type { Request } from "express";
import { timingSafeEqual } from "crypto";
import { AUTH_TOKEN } from "./config.js";

// F-LT-51 (S52): constant-time token compare.
// `===` leaks length equality in sub-microsecond timing variance; across enough
// requests (or locally-colocated attacker) this reveals token length and
// byte-by-byte prefix. timingSafeEqual short-circuits only on length.
export function validateAuth(req: Request): boolean {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice(7);
  const tBuf = Buffer.from(token, "utf8");
  const aBuf = Buffer.from(AUTH_TOKEN, "utf8");
  if (tBuf.length !== aBuf.length) return false;
  return timingSafeEqual(tBuf, aBuf);
}

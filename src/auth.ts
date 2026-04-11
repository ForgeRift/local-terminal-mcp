import type { Request } from "express";
import { AUTH_TOKEN } from "./config.js";

export function validateAuth(req: Request): boolean {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice(7);
  return token === AUTH_TOKEN;
}

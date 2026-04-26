// Config retained for compatibility.
// audit.ts reads AUDIT_MAX_SIZE_MB directly from process.env.
export const AUDIT_MAX_SIZE_MB = parseInt(process.env.AUDIT_MAX_SIZE_MB || "10", 10);

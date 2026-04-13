import { execSync } from "child_process";
import { readFileSync, readdirSync, statSync } from "fs";
import { join, resolve } from "path";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// ─── Safety Model ──────────────────────────────────────────────────────────────
// Tier 1: Read-only  — always allowed, no confirmation needed
// Tier 2: Approved   — curated write/run commands, always allowed
// Tier 3: Escape hatch — arbitrary command, dry_run=true by default, user confirms

// Hard-blocked patterns — rejected regardless of tier
const BLOCKED_PATTERNS = [
  /rm\s+-rf/i,
  /format\s+[a-z]:/i,
  /del\s+\/[sf]/i,
  /\bshutdown\s+(\/[srhf]|-[srhfPH])/i,   // Windows: shutdown /s /r /h etc. Linux: shutdown -h -r etc.
  /reg\s+delete/i,
  /cipher\s+\/w/i,
  /bcdedit/i,
  /diskpart/i,
  /sc\s+(stop|delete)\s+local-terminal-mcp/i,
];

function isBlocked(cmd: string): boolean {
  return BLOCKED_PATTERNS.some((p) => p.test(cmd));
}

function runCommand(cmd: string, timeoutMs = 10_000): string {
  try {
    return execSync(cmd, {
      timeout: timeoutMs,
      encoding: "utf8",
      windowsHide: true,
    }).trim();
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return `ERROR: ${e.stderr ?? e.stdout ?? e.message ?? "Unknown error"}`.trim();
  }
}

// ─── Tool Definitions ──────────────────────────────────────────────────────────

export const TOOLS: Tool[] = [
  // ── Tier 1: Read-only ────────────────────────────────────────────────────────
  {
    name: "list_directory",
    description: "List files and folders in a directory. Read-only, always safe.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory path to list. Defaults to current directory." },
      },
    },
  },
  {
    name: "read_file",
    description: "Read the contents of a text file. Read-only, always safe. Max 500 lines.",
    inputSchema: {
      type: "object",
      properties: {
        path:       { type: "string", description: "Absolute or relative file path." },
        start_line: { type: "number", description: "First line to read (1-indexed). Default 1." },
        end_line:   { type: "number", description: "Last line to read. Default 500." },
      },
      required: ["path"],
    },
  },
  {
    name: "get_system_info",
    description: "Get OS version, hostname, username, disk space, memory, and running processes. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "find_files",
    description: "Search for files by name pattern in a directory. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        directory: { type: "string", description: "Directory to search in." },
        pattern:   { type: "string", description: "File name pattern (e.g. *.log, config.json)." },
      },
      required: ["directory", "pattern"],
    },
  },

  // ── Tier 2: Approved commands ─────────────────────────────────────────────────
  {
    name: "run_npm_command",
    description: "Run npm install, npm run <script>, or npm list in a project directory.",
    inputSchema: {
      type: "object",
      properties: {
        directory:         { type: "string", description: "Project directory to run the command in. Also accepted as 'working_directory'." },
        working_directory: { type: "string", description: "Alias for 'directory'. Either param is accepted." },
        command:           { type: "string", description: "npm sub-command e.g. 'install', 'run build', 'list'." },
      },
      required: ["directory", "command"],
    },
  },
  {
    name: "run_git_command",
    description: "Run read-only git commands: status, log, diff, branch, fetch.",
    inputSchema: {
      type: "object",
      properties: {
        directory:         { type: "string", description: "Git repo directory. Also accepted as 'working_directory'." },
        working_directory: { type: "string", description: "Alias for 'directory'. Either param is accepted." },
        command:           { type: "string", description: "Git sub-command e.g. 'status', 'log --oneline -10', 'diff'." },
      },
      required: ["directory", "command"],
    },
  },

  // ── Tier 3: Escape hatch ──────────────────────────────────────────────────────
  {
    name: "run_command",
    description: "Run an arbitrary shell command. dry_run=true by default — always preview before executing. Hard-blocked patterns are enforced server-side.",
    inputSchema: {
      type: "object",
      properties: {
        command:       { type: "string",  description: "The command to run." },
        dry_run:       { description: "Default true. Pass false (or the string 'false') only after previewing the command." },
        justification: { type: "string",  description: "Why the structured tools cannot cover this." },
      },
      required: ["command", "justification"],
    },
  },
];

// ─── Tool Executor ─────────────────────────────────────────────────────────────

export async function executeTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ result: string; tier: "read" | "approved" | "escape_hatch"; dryRun: boolean }> {

  const dryRun = false;

  switch (name) {

    // ── Tier 1 ──────────────────────────────────────────────────────────────────
    case "list_directory": {
      const dir = (args.path as string | undefined) ?? ".";
      try {
        const entries = readdirSync(dir);
        const lines = entries.map((e) => {
          try {
            const s = statSync(join(dir, e));
            return `${s.isDirectory() ? "DIR " : "FILE"} ${e}`;
          } catch { return `?    ${e}`; }
        });
        return { result: lines.join("\n") || "(empty)", tier: "read", dryRun };
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "read", dryRun };
      }
    }

    case "read_file": {
      const filePath  = args.path as string;
      const startLine = Math.max(1, (args.start_line as number | undefined) ?? 1);
      const endLine   = Math.min(500, (args.end_line as number | undefined) ?? 500);
      try {
        const lines = readFileSync(resolve(filePath), "utf8").split("\n");
        const slice = lines.slice(startLine - 1, endLine);
        return {
          result: slice.map((l, i) => `${startLine + i}: ${l}`).join("\n"),
          tier: "read",
          dryRun,
        };
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "read", dryRun };
      }
    }

    case "get_system_info": {
      const info = [
        runCommand("ver"),
        runCommand("hostname"),
        runCommand("whoami"),
        "--- Disk ---",
        runCommand("wmic logicaldisk get caption,freespace,size /format:list 2>nul || df -h"),
        "--- Memory ---",
        runCommand("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:list 2>nul"),
      ].join("\n");
      return { result: info, tier: "read", dryRun };
    }

    case "find_files": {
      const dir     = args.directory as string;
      const pattern = args.pattern as string;
      const result  = runCommand(`dir /s /b "${join(dir, pattern)}" 2>nul || find "${dir}" -name "${pattern}" 2>/dev/null`);
      return { result: result || "(no matches)", tier: "read", dryRun };
    }

    // ── Tier 2 ──────────────────────────────────────────────────────────────────
    case "run_npm_command": {
      const dir = (args.directory ?? args.working_directory) as string;
      const cmd = args.command as string;
      const allowed = /^(install|ci|list|run\s+\w[\w:-]*)$/i;
      if (!allowed.test(cmd.trim())) {
        return { result: `ERROR: npm sub-command '${cmd}' is not in the approved list.`, tier: "approved", dryRun };
      }
      const result = runCommand(`cd /d "${dir}" && npm ${cmd}`, 60_000);
      return { result, tier: "approved", dryRun };
    }

    case "run_git_command": {
      const dir = (args.directory ?? args.working_directory) as string;
      const cmd = args.command as string;
      const allowed = /^(status|log|diff|branch|fetch|remote|show|stash list|tag)/i;
      if (!allowed.test(cmd.trim())) {
        return { result: `ERROR: git sub-command '${cmd}' is not in the approved read-only list.`, tier: "approved", dryRun };
      }
      const result = runCommand(`cd /d "${dir}" && git ${cmd}`, 30_000);
      return { result, tier: "approved", dryRun };
    }

    // ── Tier 3 ──────────────────────────────────────────────────────────────────
    case "run_command": {
      const cmd       = args.command as string;
      const isDryRun  = args.dry_run === false || args.dry_run === "false" ? false : true;

      if (isBlocked(cmd)) {
        return { result: `BLOCKED: command matches a hard-blocked pattern and cannot be run.`, tier: "escape_hatch", dryRun: isDryRun };
      }

      if (isDryRun) {
        return {
          result: `DRY RUN — command not executed.\nWould run: ${cmd}\nCall again with dry_run=false to execute.`,
          tier: "escape_hatch",
          dryRun: true,
        };
      }

      const result = runCommand(cmd, 30_000);
      return { result, tier: "escape_hatch", dryRun: false };
    }

    default:
      return { result: `ERROR: Unknown tool '${name}'`, tier: "read", dryRun };
  }
}

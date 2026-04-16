import { execSync } from "child_process";
import { readFileSync, readdirSync, statSync } from "fs";
import { join, resolve, basename } from "path";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// ─── Three-Tier Security Model ──────────────────────────────────────────────────
// GREEN  — Read-only tools + approved sub-commands. Always allowed with audit.
// AMBER  — Moderately risky commands. Forces dry_run=true with ToS warning.
// RED    — Hard-blocked. 100+ patterns across 20 categories. Structured error.
//
// Every command passes through: RED check → AMBER check → GREEN execution.
// Sensitive file reads are blocked at the file level regardless of command tier.

// ─── RED Tier: Hard-Blocked Patterns ────────────────────────────────────────────

interface BlockedPattern {
  pattern: RegExp;
  category: string;
  reason: string;
}

const BLOCKED_PATTERNS: BlockedPattern[] = [
  // ── File Deletion & Data Destruction ──────────────────────────────────────
  { pattern: /\brm\s/i,                           category: 'file-delete',    reason: 'File deletion (rm) is prohibited.' },
  { pattern: /\brmdir\b/i,                        category: 'file-delete',    reason: 'Directory removal (rmdir) is prohibited.' },
  { pattern: /(?:^|[;&|])\s*del\b/i,                          category: 'file-delete',    reason: 'File deletion (del) is prohibited.' },
  { pattern: /\berase\b/i,                        category: 'file-delete',    reason: 'File deletion (erase) is prohibited.' },
  { pattern: /\bunlink\b/i,                       category: 'file-delete',    reason: 'File deletion (unlink) is prohibited.' },
  { pattern: /\btruncate\b/i,                     category: 'file-delete',    reason: 'File truncation is prohibited.' },
  { pattern: /\bshred\b/i,                        category: 'file-delete',    reason: 'Secure file deletion (shred) is prohibited.' },
  { pattern: /\bwipe\b/i,                         category: 'file-delete',    reason: 'Disk wipe is prohibited.' },
  { pattern: /\bdd\s.*if=/i,                      category: 'file-delete',    reason: 'Raw disk copy (dd) is prohibited.' },
  { pattern: /\bcipher\s+\/w/i,                   category: 'file-delete',    reason: 'Cipher wipe is prohibited.' },
  { pattern: /remove-item/i,                      category: 'file-delete',    reason: 'PowerShell Remove-Item is prohibited.' },
  { pattern: /clear-content/i,                    category: 'file-delete',    reason: 'PowerShell Clear-Content is prohibited.' },
  { pattern: /clear-recyclebin/i,                 category: 'file-delete',    reason: 'Emptying recycle bin is prohibited.' },

  // ── Disk Operations & Filesystem ──────────────────────────────────────────
  { pattern: /\bformat\s+[a-z]:/i,               category: 'disk-ops',       reason: 'Disk formatting is prohibited.' },
  { pattern: /\bdiskpart\b/i,                     category: 'disk-ops',       reason: 'Disk partition management is prohibited.' },
  { pattern: /\bfdisk\b/i,                        category: 'disk-ops',       reason: 'Disk partition management is prohibited.' },
  { pattern: /\bparted\b/i,                       category: 'disk-ops',       reason: 'Disk partition management is prohibited.' },
  { pattern: /\bmkfs\b/i,                         category: 'disk-ops',       reason: 'Filesystem creation is prohibited.' },
  { pattern: /\bfsck\b/i,                         category: 'disk-ops',       reason: 'Filesystem check/repair is prohibited.' },
  { pattern: /\bresize2fs\b/i,                    category: 'disk-ops',       reason: 'Filesystem resize is prohibited.' },
  { pattern: /\bmount\b/i,                        category: 'disk-ops',       reason: 'Mount operations are prohibited.' },
  { pattern: /\bumount\b/i,                       category: 'disk-ops',       reason: 'Unmount operations are prohibited.' },
  { pattern: /\bbcdedit\b/i,                      category: 'disk-ops',       reason: 'Boot configuration editing is prohibited.' },
  { pattern: /\bchkdsk\b.*\/[fFrR]/i,            category: 'disk-ops',       reason: 'Disk repair (chkdsk /f /r) is prohibited.' },

  // ── System State Modification ─────────────────────────────────────────────
  { pattern: /\bshutdown\b/i,                     category: 'system-state',   reason: 'System shutdown/restart is prohibited.' },
  { pattern: /\brestart-computer\b/i,             category: 'system-state',   reason: 'System restart is prohibited.' },
  { pattern: /\bstop-computer\b/i,                category: 'system-state',   reason: 'System shutdown is prohibited.' },
  { pattern: /\bsysctl\b/i,                       category: 'system-state',   reason: 'Kernel parameter modification is prohibited.' },
  { pattern: /\bmodprobe\b/i,                     category: 'system-state',   reason: 'Kernel module loading is prohibited.' },
  { pattern: /\binsmod\b/i,                       category: 'system-state',   reason: 'Kernel module insertion is prohibited.' },
  { pattern: /\brmmod\b/i,                        category: 'system-state',   reason: 'Kernel module removal is prohibited.' },

  // ── Process Termination ───────────────────────────────────────────────────
  { pattern: /(?:^|[;&|])\s*kill\b/i,                         category: 'process-kill',   reason: 'Process termination (kill) is prohibited.' },
  { pattern: /\bkillall\b/i,                      category: 'process-kill',   reason: 'Mass process termination is prohibited.' },
  { pattern: /\bpkill\b/i,                        category: 'process-kill',   reason: 'Pattern-based process termination is prohibited.' },
  { pattern: /\btaskkill\b/i,                     category: 'process-kill',   reason: 'Task termination (taskkill) is prohibited.' },
  { pattern: /stop-process/i,                     category: 'process-kill',   reason: 'PowerShell Stop-Process is prohibited.' },
  { pattern: /\btskill\b/i,                       category: 'process-kill',   reason: 'Terminal Services kill is prohibited.' },

  // ── User & Group Management ───────────────────────────────────────────────
  { pattern: /\bnet\s+user\b/i,                   category: 'user-mgmt',      reason: 'User account management is prohibited.' },
  { pattern: /\bnet\s+localgroup\b/i,             category: 'user-mgmt',      reason: 'Local group management is prohibited.' },
  { pattern: /\buseradd\b/i,                      category: 'user-mgmt',      reason: 'User creation is prohibited.' },
  { pattern: /\buserdel\b/i,                      category: 'user-mgmt',      reason: 'User deletion is prohibited.' },
  { pattern: /\busermod\b/i,                      category: 'user-mgmt',      reason: 'User modification is prohibited.' },
  { pattern: /\bpasswd\b/i,                       category: 'user-mgmt',      reason: 'Password change is prohibited.' },
  { pattern: /\bgroupadd\b/i,                     category: 'user-mgmt',      reason: 'Group creation is prohibited.' },
  { pattern: /\bgroupdel\b/i,                     category: 'user-mgmt',      reason: 'Group deletion is prohibited.' },
  { pattern: /new-localuser/i,                    category: 'user-mgmt',      reason: 'PowerShell user creation is prohibited.' },
  { pattern: /add-localgroupmember/i,             category: 'user-mgmt',      reason: 'PowerShell group member addition is prohibited.' },

  // ── File Permissions & Ownership ──────────────────────────────────────────
  { pattern: /\bchmod\b/i,                        category: 'permissions',    reason: 'File permission changes are prohibited.' },
  { pattern: /\bchown\b/i,                        category: 'permissions',    reason: 'File ownership changes are prohibited.' },
  { pattern: /\bchgrp\b/i,                        category: 'permissions',    reason: 'File group changes are prohibited.' },
  { pattern: /\bicacls\b/i,                       category: 'permissions',    reason: 'NTFS permission changes (icacls) are prohibited.' },
  { pattern: /\bcacls\b/i,                        category: 'permissions',    reason: 'NTFS permission changes (cacls) are prohibited.' },
  { pattern: /\btakeown\b/i,                      category: 'permissions',    reason: 'File ownership takeover is prohibited.' },
  { pattern: /set-acl/i,                          category: 'permissions',    reason: 'PowerShell ACL modification is prohibited.' },

  // ── Network Configuration ─────────────────────────────────────────────────
  { pattern: /\bnetsh\b/i,                        category: 'network-config', reason: 'Network configuration (netsh) is prohibited.' },
  { pattern: /\biptables\b/i,                     category: 'network-config', reason: 'Firewall rule modification is prohibited.' },
  { pattern: /\bip\s+route\b/i,                   category: 'network-config', reason: 'Route table modification is prohibited.' },
  { pattern: /\broute\s+(add|delete|change)\b/i,  category: 'network-config', reason: 'Route table modification is prohibited.' },
  { pattern: /\bifconfig\b.*\b(up|down|addr)\b/i, category: 'network-config', reason: 'Network interface modification is prohibited.' },
  { pattern: /new-netfirewallrule/i,              category: 'network-config', reason: 'PowerShell firewall rule creation is prohibited.' },
  { pattern: /set-netadapter/i,                   category: 'network-config', reason: 'PowerShell network adapter changes are prohibited.' },

  // ── Scheduled Execution ───────────────────────────────────────────────────
  { pattern: /\bcrontab\b/i,                      category: 'scheduled-exec', reason: 'Cron job modification is prohibited.' },
  { pattern: /(?:^|[;&|])\s*at\s+\d/i,                      category: 'scheduled-exec', reason: 'Scheduled task creation (at) is prohibited.' },
  { pattern: /\bschtasks\b/i,                     category: 'scheduled-exec', reason: 'Windows Task Scheduler modification is prohibited.' },
  { pattern: /register-scheduledjob/i,            category: 'scheduled-exec', reason: 'PowerShell scheduled job creation is prohibited.' },
  { pattern: /new-scheduledtask/i,                category: 'scheduled-exec', reason: 'PowerShell scheduled task creation is prohibited.' },

  // ── Service Management ────────────────────────────────────────────────────
  { pattern: /\bsc\s+(create|delete|stop|start|config)\b/i, category: 'service-mgmt', reason: 'Windows service management (sc) is prohibited.' },
  { pattern: /\bsystemctl\s+(start|stop|enable|disable|mask)\b/i, category: 'service-mgmt', reason: 'Systemd service management is prohibited.' },
  { pattern: /\bnssm\s+(install|remove|start|stop)\b/i,     category: 'service-mgmt', reason: 'NSSM service management is prohibited.' },
  { pattern: /start-service/i,                    category: 'service-mgmt',   reason: 'PowerShell Start-Service is prohibited.' },
  { pattern: /stop-service/i,                     category: 'service-mgmt',   reason: 'PowerShell Stop-Service is prohibited.' },
  { pattern: /set-service/i,                      category: 'service-mgmt',   reason: 'PowerShell Set-Service is prohibited.' },
  { pattern: /new-service/i,                      category: 'service-mgmt',   reason: 'PowerShell New-Service is prohibited.' },

  // ── Code Execution & Shell Invocation ─────────────────────────────────────
  { pattern: /\beval\b/i,                         category: 'code-exec',      reason: 'eval() is prohibited.' },
  { pattern: /(?:^|[;&|])\s*exec\b/i,                         category: 'code-exec',      reason: 'exec is prohibited.' },
  { pattern: /invoke-expression/i,                category: 'code-exec',      reason: 'PowerShell Invoke-Expression is prohibited.' },
  { pattern: /\biex\b/i,                          category: 'code-exec',      reason: 'PowerShell IEX (Invoke-Expression alias) is prohibited.' },
  { pattern: /\bstart-process\b/i,                category: 'code-exec',      reason: 'PowerShell Start-Process is prohibited.' },
  { pattern: /\bwscript\b/i,                      category: 'code-exec',      reason: 'Windows Script Host (wscript) is prohibited.' },
  { pattern: /\bcscript\b/i,                      category: 'code-exec',      reason: 'Windows Script Host (cscript) is prohibited.' },
  { pattern: /\bmshta\b/i,                        category: 'code-exec',      reason: 'MSHTA execution is prohibited.' },
  { pattern: /\bregsvr32\b/i,                     category: 'code-exec',      reason: 'DLL registration/execution is prohibited.' },
  { pattern: /\brundll32\b/i,                     category: 'code-exec',      reason: 'DLL execution (rundll32) is prohibited.' },

  // ── Data Exfiltration ─────────────────────────────────────────────────────
  { pattern: /\bcurl\b/i,                         category: 'data-exfil',     reason: 'curl is prohibited. Data cannot leave the machine via MCP.' },
  { pattern: /\bwget\b/i,                         category: 'data-exfil',     reason: 'wget is prohibited. Data cannot leave the machine via MCP.' },
  { pattern: /invoke-webrequest/i,                category: 'data-exfil',     reason: 'PowerShell web requests are prohibited.' },
  { pattern: /invoke-restmethod/i,                category: 'data-exfil',     reason: 'PowerShell REST calls are prohibited.' },
  { pattern: /\bscp\b/i,                          category: 'data-exfil',     reason: 'SCP file transfer is prohibited.' },
  { pattern: /\bsftp\b/i,                         category: 'data-exfil',     reason: 'SFTP file transfer is prohibited.' },
  { pattern: /\brsync\b/i,                        category: 'data-exfil',     reason: 'rsync file transfer is prohibited.' },
  { pattern: /\bnc\b\s+-/i,                       category: 'data-exfil',     reason: 'Netcat is prohibited.' },
  { pattern: /\bsocat\b/i,                        category: 'data-exfil',     reason: 'Socat is prohibited.' },
  { pattern: /\bftp\b/i,                          category: 'data-exfil',     reason: 'FTP is prohibited.' },
  { pattern: /\bbitsadmin\b/i,                    category: 'data-exfil',     reason: 'BITS transfer is prohibited.' },
  { pattern: /\bcertutil\s.*-urlcache/i,          category: 'data-exfil',     reason: 'certutil download is prohibited.' },
  { pattern: /new-object\s+.*webclient/i,         category: 'data-exfil',     reason: 'PowerShell WebClient download is prohibited.' },
  { pattern: /\bssh\b/i,                          category: 'data-exfil',     reason: 'SSH connections are prohibited via MCP.' },

  // ── Persistence Mechanisms ────────────────────────────────────────────────
  { pattern: /\breg\s+(add|delete|import|export)\b/i, category: 'persistence', reason: 'Registry modification is prohibited.' },
  { pattern: /set-itemproperty.*registry/i,       category: 'persistence',    reason: 'PowerShell registry modification is prohibited.' },
  { pattern: /new-itemproperty.*registry/i,       category: 'persistence',    reason: 'PowerShell registry creation is prohibited.' },
  { pattern: /\\CurrentVersion\\Run/i,            category: 'persistence',    reason: 'Startup registry key modification is prohibited.' },
  { pattern: /authorized_keys/i,                  category: 'persistence',    reason: 'SSH authorized_keys modification is prohibited.' },
  { pattern: /\.bashrc|\.bash_profile|\.profile/i,category: 'persistence',    reason: 'Shell initialization file modification is prohibited.' },
  { pattern: /startup\s*folder/i,                 category: 'persistence',    reason: 'Startup folder modification is prohibited.' },

  // ── Direct Database Modification ──────────────────────────────────────────
  { pattern: /\b(CREATE|DROP|ALTER|DELETE|TRUNCATE|GRANT|REVOKE)\s/i, category: 'direct-db', reason: 'Database write operations are prohibited. Use structured APIs.' },

  // ── Package Installation ──────────────────────────────────────────────────
  { pattern: /\bnpm\s+install\s+-g\b/i,           category: 'pkg-install',    reason: 'Global npm package installation is prohibited.' },
  { pattern: /\bpip\s+install\b/i,                category: 'pkg-install',    reason: 'pip package installation is prohibited.' },
  { pattern: /\bchoco\s+install\b/i,              category: 'pkg-install',    reason: 'Chocolatey package installation is prohibited.' },
  { pattern: /\bwinget\s+install\b/i,             category: 'pkg-install',    reason: 'winget package installation is prohibited.' },
  { pattern: /\bapt-get\s+install\b/i,            category: 'pkg-install',    reason: 'apt package installation is prohibited.' },
  { pattern: /install-package/i,                  category: 'pkg-install',    reason: 'PowerShell Install-Package is prohibited.' },
  { pattern: /install-module/i,                   category: 'pkg-install',    reason: 'PowerShell Install-Module is prohibited.' },

  // ── Package Removal ───────────────────────────────────────────────────────
  { pattern: /\bnpm\s+uninstall\s+-g\b/i,         category: 'pkg-remove',     reason: 'Global npm package removal is prohibited.' },
  { pattern: /\bpip\s+uninstall\b/i,              category: 'pkg-remove',     reason: 'pip package removal is prohibited.' },
  { pattern: /\bchoco\s+uninstall\b/i,            category: 'pkg-remove',     reason: 'Chocolatey package removal is prohibited.' },
  { pattern: /\bwinget\s+uninstall\b/i,           category: 'pkg-remove',     reason: 'winget package removal is prohibited.' },
  { pattern: /\bapt-get\s+remove\b/i,             category: 'pkg-remove',     reason: 'apt package removal is prohibited.' },
  { pattern: /uninstall-package/i,                category: 'pkg-remove',     reason: 'PowerShell Uninstall-Package is prohibited.' },

  // ── Container & Orchestration ─────────────────────────────────────────────
  { pattern: /\bdocker\s+(run|exec|build|push|pull)\b/i, category: 'container', reason: 'Docker operations are prohibited.' },
  { pattern: /\bkubectl\s+(apply|delete|exec)\b/i,       category: 'container', reason: 'Kubernetes write operations are prohibited.' },

  // ── File Write Protection ─────────────────────────────────────────────────
  { pattern: />\s*[A-Za-z]:\\Windows/i,           category: 'file-write',     reason: 'Writing to Windows system directory is prohibited.' },
  { pattern: />\s*C:\\Program\s+Files/i,          category: 'file-write',     reason: 'Writing to Program Files is prohibited.' },
  { pattern: />\s*\/etc\//i,                      category: 'file-write',     reason: 'Writing to /etc/ is prohibited.' },
  { pattern: />\s*\/usr\//i,                      category: 'file-write',     reason: 'Writing to /usr/ is prohibited.' },
  { pattern: /set-content.*\\windows\\/i,         category: 'file-write',     reason: 'PowerShell writing to Windows directory is prohibited.' },
  { pattern: /out-file.*\\windows\\/i,            category: 'file-write',     reason: 'PowerShell writing to Windows directory is prohibited.' },
  { pattern: /add-content.*\\windows\\/i,         category: 'file-write',     reason: 'PowerShell writing to Windows directory is prohibited.' },

  // ── Environment Variable Manipulation ─────────────────────────────────────
  { pattern: /\bsetx\b/i,                         category: 'env-manip',      reason: 'Persistent environment variable modification (setx) is prohibited.' },
  { pattern: /\[environment\]::setenvironmentvariable/i, category: 'env-manip', reason: 'PowerShell environment variable persistence is prohibited.' },

  // ── Privilege Escalation ──────────────────────────────────────────────────
  { pattern: /\bsudo\b/i,                         category: 'priv-esc',       reason: 'Privilege escalation (sudo) is prohibited.' },
  { pattern: /\brunas\b/i,                        category: 'priv-esc',       reason: 'Privilege escalation (runas) is prohibited.' },
  { pattern: /(?:^|[;&|])\s*su\s/i,                           category: 'priv-esc',       reason: 'User switching (su) is prohibited.' },

  // ── Information Leakage ───────────────────────────────────────────────────
  { pattern: /\\etc\\shadow/i,                    category: 'info-leak',      reason: 'Shadow file access is prohibited.' },
  { pattern: /\bsam\b.*system/i,                  category: 'info-leak',      reason: 'SAM database access is prohibited.' },
  { pattern: /\bcmdkey\s+\/list/i,                category: 'info-leak',      reason: 'Credential enumeration (cmdkey) is prohibited.' },
  { pattern: /\bvaultcmd\b/i,                     category: 'info-leak',      reason: 'Credential vault access is prohibited.' },
  { pattern: /\bdpapi\b/i,                        category: 'info-leak',      reason: 'DPAPI access is prohibited.' },
  { pattern: /get-credential/i,                   category: 'info-leak',      reason: 'PowerShell credential retrieval is prohibited.' },
  { pattern: /convertfrom-securestring/i,         category: 'info-leak',      reason: 'PowerShell secure string decryption is prohibited.' },

  // ── Command Chaining Exploits ─────────────────────────────────────────────
  { pattern: /[;&|]{2}.*\b(rm|del|format|shutdown|kill|taskkill)\b/i, category: 'chaining', reason: 'Command chaining with destructive commands is prohibited.' },
  { pattern: /;\s*\b(rm|del|format|shutdown|kill|taskkill|erase|rmdir|unlink|truncate|shred|wipe|passwd|chmod|chown|curl|wget|ssh|scp|sftp|eval|exec|sudo|runas)\b/i, category: 'chaining', reason: 'Single-semicolon chaining with dangerous commands is prohibited.' },
  { pattern: /\|\s*(bash|sh|cmd|powershell)\b/i,  category: 'chaining',       reason: 'Pipe-to-shell is prohibited.' },
  { pattern: /`[^`]*`/,                           category: 'chaining',       reason: 'Backtick command substitution is prohibited.' },

  // ── Variable Expansion / Obfuscation ──────────────────────────────────────
  { pattern: /\$\(/,                              category: 'obfuscation',    reason: 'Shell command substitution $() is prohibited.' },
  { pattern: /\$\{[^}]+\}/,                       category: 'obfuscation',    reason: 'Variable expansion ${...} is prohibited in commands.' },
  { pattern: /%[A-Za-z_][A-Za-z0-9_]*%/,          category: 'obfuscation',    reason: 'Windows environment variable expansion %VAR% is prohibited.' },

  // ── HTTP Server & Listener Binding ────────────────────────────────────────
  { pattern: /\bnc\s.*-l/i,                       category: 'http-server',    reason: 'Listening socket (netcat) is prohibited.' },
  { pattern: /python\s+-m\s+http\.server/i,       category: 'http-server',    reason: 'Python HTTP server is prohibited.' },
  { pattern: /\bnetstat\b.*-l/i,                  category: 'http-server',    reason: 'Listening port enumeration requires structured tools.' },
  { pattern: /simple-server|http-server.*--port/i, category: 'http-server',   reason: 'Starting HTTP servers is prohibited.' },
];

function checkBlocked(cmd: string): { blocked: true; category: string; reason: string } | { blocked: false } {
  // ── CRITICAL FIX (S35): Reject non-ASCII to prevent Unicode homoglyph bypass ──
  // Cyrillic/Greek lookalikes (e.g. Cyrillic 'р' for Latin 'r') defeat \b word boundaries.
  if (/[^\x00-\x7F]/.test(cmd)) {
    return { blocked: true, category: 'obfuscation', reason: 'Non-ASCII characters in commands are prohibited. This prevents Unicode homoglyph bypasses.' };
  }

  // ── CRITICAL FIX (S35): Check each line independently ──
  // Newlines break regex `.` matching, allowing chaining across lines.
  const lines = cmd.split(/\r?\n/).filter(l => l.trim().length > 0);
  for (const line of lines) {
    for (const { pattern, category, reason } of BLOCKED_PATTERNS) {
      if (pattern.test(line)) {
        return { blocked: true, category, reason };
      }
    }
  }

  // Also check the full combined command (catches cross-line chaining patterns)
  for (const { pattern, category, reason } of BLOCKED_PATTERNS) {
    if (pattern.test(cmd)) {
      return { blocked: true, category, reason };
    }
  }

  return { blocked: false };
}

// ─── AMBER Tier: Warning-Required Commands ──────────────────────────────────────

interface AmberWarning {
  pattern: RegExp;
  risk: string;
}

const AMBER_PATTERNS: AmberWarning[] = [
  { pattern: /\bfind\b.*-exec\b/i,          risk: 'find -exec can execute commands on matched files. Review carefully.' },
  { pattern: /\bxargs\b/i,                  risk: 'xargs pipes input as arguments to other commands. Review carefully.' },
  { pattern: /\bawk\b/i,                    risk: 'awk can write files and execute shell commands.' },
  { pattern: /\bsed\s+-i/i,                 risk: 'sed -i modifies files in-place. Review carefully.' },
  { pattern: /\bforfiles\b/i,               risk: 'forfiles executes commands on matched files. Review carefully.' },
  { pattern: /\brobocopy\b/i,               risk: 'robocopy can move/mirror large directory trees. Review carefully.' },
  { pattern: /\bxcopy\b/i,                  risk: 'xcopy can copy large directory trees. Review carefully.' },
  { pattern: /\bcopy\b.*\/[yY]/i,           risk: 'copy /y overwrites without confirmation. Review carefully.' },
  { pattern: /\bmove\b/i,                   risk: 'move relocates files/directories. Review carefully.' },
  { pattern: /\brename\b.*\*/i,             risk: 'Wildcard rename can affect many files. Review carefully.' },
  { pattern: /\bren\b.*\*/i,               risk: 'Wildcard rename can affect many files. Review carefully.' },
];

function checkAmber(cmd: string): AmberWarning | null {
  for (const entry of AMBER_PATTERNS) {
    if (entry.pattern.test(cmd)) return entry;
  }
  return null;
}

// ─── Sensitive File Protection ──────────────────────────────────────────────────

const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  // Environment files
  /\.env($|\.)/i,
  /\.env\.local/i,
  /\.env\.\w+\.local/i,

  // SSH infrastructure
  /[\\\/]\.ssh[\\\/]/i,
  /id_(rsa|ed25519|ecdsa|dsa)/i,
  /authorized_keys/i,
  /known_hosts/i,

  // Private keys & certificates
  /\.pem$/i,
  /\.key$/i,
  /\.pk8$/i,
  /\.p12$/i,
  /\.pfx$/i,

  // Credential files
  /\.credentials/i,
  /\.aws[\\\/]credentials/i,
  /\.gcloud[\\\/]/i,
  /\.azure[\\\/]/i,

  // Password files
  /\\etc\\shadow/i,
  /\\etc\\gshadow/i,
  /\.htpasswd/i,
  /\.netrc/i,
  /\.pgpass/i,
  /\.my\.cnf/i,

  // Windows credential stores
  /\\Microsoft\\Credentials/i,
  /\\Microsoft\\Protect/i,
  /SAM$/i,
  /SYSTEM$/i,
  /SECURITY$/i,
  /NTUSER\.DAT/i,

  // Application secrets
  /secrets?\.(yml|yaml|json|toml)/i,
  /\.docker[\\\/]config\.json/i,
  /kubeconfig/i,
  /\.kube[\\\/]config/i,

  // Git credentials
  /\.git-credentials/i,
  /\.gitconfig/i,

  // API keys/tokens in common locations
  /token\.json/i,
  /credentials\.json/i,

  // Browser data
  /\\Login Data$/i,
  /\\Cookies$/i,
  /\\Web Data$/i,

  // Windows crypto
  /\.rdp$/i,
];

function isSensitiveFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return SENSITIVE_FILE_PATTERNS.some(p => p.test(normalized) || p.test(basename(normalized)));
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

const COMMAND_TIMEOUT_MS = 30_000;

function runCommand(cmd: string, timeoutMs = COMMAND_TIMEOUT_MS): string {
  try {
    return execSync(cmd, {
      timeout: timeoutMs,
      encoding: "utf8",
      windowsHide: true,
    }).trim();
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string; killed?: boolean };
    if (e.killed) return `ERROR: Command timed out after ${timeoutMs / 1000}s and was killed.`;
    return `ERROR: ${e.stderr ?? e.stdout ?? e.message ?? "Unknown error"}`.trim();
  }
}

function sanitizeDir(dir: string): string {
  if (/["`;|&<>]/.test(dir)) {
    throw new Error(`Directory path contains shell-unsafe characters.`);
  }
  return dir;
}

const MAX_CMD_OUTPUT_CHARS = 10_000;
function truncateOutput(output: string): string {
  if (output.length <= MAX_CMD_OUTPUT_CHARS) return output;
  return (
    output.slice(0, MAX_CMD_OUTPUT_CHARS) +
    `\n\n[TRUNCATED: ${output.length} chars total. Only first ${MAX_CMD_OUTPUT_CHARS} shown.]`
  );
}

function formatBlockedError(category: string, reason: string): string {
  return [
    `⛔ BLOCKED [${category}]`,
    ``,
    reason,
    ``,
    `This command is classified RED (hard-blocked) under the local-terminal-mcp security model.`,
    `It cannot be executed regardless of dry_run setting or justification.`,
    ``,
    `⚠️  Attempting to circumvent command blocks violates the Terms of Service`,
    `    and may result in account suspension.`,
  ].join('\n');
}

function formatAmberWarning(risk: string, cmd: string): string {
  return [
    `⚠️  AMBER WARNING`,
    ``,
    `Risk: ${risk}`,
    ``,
    `Command: ${cmd}`,
    ``,
    `This command is classified AMBER (warning-required). It was NOT executed.`,
    `dry_run has been forced to true for safety.`,
    ``,
    `To proceed: call again with dry_run=false and acknowledge the risk in your justification.`,
    ``,
    `⚠️  Running AMBER commands recklessly may violate the Terms of Service.`,
  ].join('\n');
}

// ─── Tool Definitions ──────────────────────────────────────────────────────────

export const TOOLS: Tool[] = [
  // ── GREEN Tier: Read-only ─────────────────────────────────────────────────────
  {
    name: "list_directory",
    annotations: { title: 'List Directory', readOnlyHint: true, destructiveHint: false },
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
    annotations: { title: 'Read File', readOnlyHint: true, destructiveHint: false },
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
    annotations: { title: 'Get System Info', readOnlyHint: true, destructiveHint: false },
    description: "Get OS version, hostname, username, disk space, memory, and running processes. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "find_files",
    annotations: { title: 'Find Files', readOnlyHint: true, destructiveHint: false },
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

  // ── GREEN Tier: Approved commands ─────────────────────────────────────────────
  {
    name: "run_npm_command",
    annotations: { title: 'Run NPM Command', readOnlyHint: false, destructiveHint: false },
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
    annotations: { title: 'Run Git Command', readOnlyHint: true, destructiveHint: false },
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

  // ── Escape hatch (RED/AMBER checked) ──────────────────────────────────────────
  {
    name: "run_command",
    annotations: { title: 'Run Shell Command', readOnlyHint: false, destructiveHint: true },
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
  {
    name: "search_file",
    annotations: { title: 'Search File', readOnlyHint: true, destructiveHint: false },
    description: "Search for text patterns in a file or directory. Read-only grep/findstr equivalent.",
    inputSchema: {
      type: "object",
      properties: {
        path:    { type: "string", description: "File or directory to search in." },
        pattern: { type: "string", description: "Text or regex pattern to search for." },
      },
      required: ["path", "pattern"],
    },
  },
];

// ─── Tool Executor ─────────────────────────────────────────────────────────────

export async function executeTool(
  name: string,
  args: Record<string, unknown>
): Promise<{ result: string; tier: "green" | "amber" | "red"; blocked: boolean; dryRun: boolean }> {

  switch (name) {

    // ── GREEN Tier: Read-only ────────────────────────────────────────────────────
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
        return { result: lines.join("\n") || "(empty)", tier: "green", blocked: false, dryRun: false };
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "green", blocked: false, dryRun: false };
      }
    }

    case "read_file": {
      const filePath  = args.path as string;

      // Sensitive file guard
      if (isSensitiveFile(filePath)) {
        return {
          result: formatBlockedError('sensitive-file', `Access to '${basename(filePath)}' is blocked. This file matches a sensitive file pattern (credentials, keys, secrets, environment files). Sensitive files cannot be read regardless of command tier.`),
          tier: "red",
          blocked: true,
          dryRun: false,
        };
      }

      const startLine = Math.max(1, (args.start_line as number | undefined) ?? 1);
      const endLine   = Math.min(500, (args.end_line as number | undefined) ?? 500);
      try {
        const lines = readFileSync(resolve(filePath), "utf8").split("\n");
        const slice = lines.slice(startLine - 1, endLine);
        return {
          result: slice.map((l, i) => `${startLine + i}: ${l}`).join("\n"),
          tier: "green",
          blocked: false,
          dryRun: false,
        };
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "green", blocked: false, dryRun: false };
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
      return { result: info, tier: "green", blocked: false, dryRun: false };
    }

    case "find_files": {
      const dir     = args.directory as string;
      const pattern = args.pattern as string;
      const result  = runCommand(`dir /s /b "${join(dir, pattern)}" 2>nul || find "${dir}" -name "${pattern}" 2>/dev/null`);
      return { result: result || "(no matches)", tier: "green", blocked: false, dryRun: false };
    }

    case "search_file": {
      const filePath = args.path as string;
      const pattern  = args.pattern as string;

      // Sensitive file guard
      if (isSensitiveFile(filePath)) {
        return {
          result: formatBlockedError('sensitive-file', `Search in '${basename(filePath)}' is blocked. This file matches a sensitive file pattern.`),
          tier: "red",
          blocked: true,
          dryRun: false,
        };
      }

      const result = runCommand(`findstr /n /i /c:"${pattern}" "${filePath}" 2>nul || grep -n -i "${pattern}" "${filePath}" 2>/dev/null`);
      return { result: result || "(no matches)", tier: "green", blocked: false, dryRun: false };
    }

    // ── GREEN Tier: Approved commands ────────────────────────────────────────────
    case "run_npm_command": {
      const dir = sanitizeDir((args.directory ?? args.working_directory) as string);
      const cmd = args.command as string;
      const allowed = /^(install|ci|list|run\s+\w[\w:-]*)$/i;
      if (!allowed.test(cmd.trim())) {
        return { result: `ERROR: npm sub-command '${cmd}' is not in the approved list.`, tier: "green", blocked: true, dryRun: false };
      }
      const result = runCommand(`cd /d "${dir}" && npm ${cmd}`, 60_000);
      return { result, tier: "green", blocked: false, dryRun: false };
    }

    case "run_git_command": {
      const dir = sanitizeDir((args.directory ?? args.working_directory) as string);
      const cmd = args.command as string;
      const allowed = /^(status|log|diff|branch|fetch|remote|show|stash list|tag|rev-parse|ls-files)/i;
      if (!allowed.test(cmd.trim())) {
        return { result: `ERROR: git sub-command '${cmd}' is not in the approved read-only list.`, tier: "green", blocked: true, dryRun: false };
      }
      const result = runCommand(`cd /d "${dir}" && git ${cmd}`, 30_000);
      return { result, tier: "green", blocked: false, dryRun: false };
    }

    // ── Escape Hatch (RED → AMBER → GREEN pipeline) ────────────────────────────
    case "run_command": {
      const cmd       = args.command as string;
      const isDryRun  = args.dry_run === false || args.dry_run === "false" ? false : true;

      // RED check
      const blockResult = checkBlocked(cmd);
      if (blockResult.blocked) {
        return {
          result: formatBlockedError(blockResult.category, blockResult.reason),
          tier: "red",
          blocked: true,
          dryRun: isDryRun,
        };
      }

      // AMBER check
      const amberResult = checkAmber(cmd);
      if (amberResult && isDryRun) {
        return {
          result: formatAmberWarning(amberResult.risk, cmd),
          tier: "amber",
          blocked: false,
          dryRun: true,
        };
      }

      // Dry run preview
      if (isDryRun) {
        return {
          result: `DRY RUN — command not executed.\nWould run: ${cmd}\nCall again with dry_run=false to execute.`,
          tier: "green",
          blocked: false,
          dryRun: true,
        };
      }

      // AMBER with dry_run=false — execute but log the warning
      const result = truncateOutput(runCommand(cmd, COMMAND_TIMEOUT_MS));
      return {
        result: amberResult
          ? `⚠️ AMBER command executed (acknowledged risk: ${amberResult.risk})\n\n${result}`
          : result,
        tier: amberResult ? "amber" : "green",
        blocked: false,
        dryRun: false,
      };
    }

    default:
      return { result: `ERROR: Unknown tool '${name}'`, tier: "green", blocked: false, dryRun: false };
  }
}

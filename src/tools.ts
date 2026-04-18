import { execSync, execFileSync } from "child_process";
import { readFileSync, readdirSync, statSync, lstatSync, realpathSync } from "fs";
import { join, resolve, basename, normalize } from "path";
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
  { pattern: /\brd\b/i,                           category: 'file-delete',    reason: 'Directory removal (rd) is prohibited.' },
  { pattern: /\bdel\b/i,                          category: 'file-delete',    reason: 'File deletion (del) is prohibited.' },
  { pattern: /\berase\b/i,                        category: 'file-delete',    reason: 'File deletion (erase) is prohibited.' },
  { pattern: /\bunlink\b/i,                       category: 'file-delete',    reason: 'File deletion (unlink) is prohibited.' },
  { pattern: /\btruncate\b/i,                     category: 'file-delete',    reason: 'File truncation is prohibited.' },
  { pattern: /\bshred\b/i,                        category: 'file-delete',    reason: 'Secure file deletion (shred) is prohibited.' },
  { pattern: /\bwipe\b/i,                         category: 'file-delete',    reason: 'Disk wipe is prohibited.' },
  { pattern: /\bdd\s.*if=/i,                      category: 'file-delete',    reason: 'Raw disk copy (dd) is prohibited.' },
  { pattern: /\bcipher\s+\/w/i,                   category: 'file-delete',    reason: 'Cipher wipe is prohibited.' },
  { pattern: /\bremove-item\b/i,                  category: 'file-delete',    reason: 'PowerShell Remove-Item is prohibited.' },
  { pattern: /\bremove-itemproperty\b/i,          category: 'file-delete',    reason: 'PowerShell Remove-ItemProperty is prohibited.' },
  { pattern: /(?<!\w)ri\s+-/i,                    category: 'file-delete',    reason: 'PowerShell Remove-Item alias (ri) with flags is prohibited.' },
  { pattern: /\bclear-item\b/i,                   category: 'file-delete',    reason: 'PowerShell Clear-Item is prohibited.' },
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
  { pattern: /(?:^|[;&|])\s*\bat\b\s+\d/i,                      category: 'scheduled-exec', reason: 'Scheduled task creation (at) is prohibited.' },
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

  // ── Shell Wrappers (F-2/F-4/F-5 fix) ────────────────────────────────────────
  // Block cmd /c and powershell/pwsh -c/-Command/-File/-EncodedCommand outright.
  // These are the canonical dispatch forms that let anything slip past verb blocks.
  { pattern: /\bcmd(\.exe)?\s+\/[cCkK]\b/i,      category: 'code-exec',      reason: 'cmd /c shell dispatch is prohibited. Use structured tools instead.' },
  { pattern: /\bp(ower)?sh(ell)?(\.exe)?\s+.*-(c(om(mand)?)?|f(ile)?|e(nc(odedcommand)?)?)\b/i,
                                                  category: 'code-exec',      reason: 'PowerShell -c/-Command/-File/-EncodedCommand is prohibited.' },
  { pattern: /\bpwsh(\.exe)?\s+.*-(c(om(mand)?)?|f(ile)?|e(nc(odedcommand)?)?)\b/i,
                                                  category: 'code-exec',      reason: 'pwsh (PowerShell 7) -c/-Command/-File/-EncodedCommand is prohibited.' },
  // F-LT-26: PowerShell positional command form — `powershell "code"` with no flag bypasses -c/-Command block.
  // Requires that the first non-whitespace arg does NOT start with '-' (flags are still OK).
  { pattern: /\bp(ower)?sh(ell)?(\.exe)?\s+(?!-)[^\s]/i,  category: 'code-exec', reason: 'PowerShell with a positional (non-flag) first argument is prohibited.' },
  { pattern: /\bpwsh(\.exe)?\s+(?!-)[^\s]/i,              category: 'code-exec', reason: 'pwsh with a positional (non-flag) first argument is prohibited.' },

  // ── Code Execution & Shell Invocation ─────────────────────────────────────
  { pattern: /\beval\b/i,                         category: 'code-exec',      reason: 'eval() is prohibited.' },
  { pattern: /\bexec\b/i,                         category: 'code-exec',      reason: 'exec is prohibited.' },
  { pattern: /invoke-expression/i,                category: 'code-exec',      reason: 'PowerShell Invoke-Expression is prohibited.' },
  { pattern: /\biex\b/i,                          category: 'code-exec',      reason: 'PowerShell IEX (Invoke-Expression alias) is prohibited.' },
  { pattern: /\bstart-process\b/i,                category: 'code-exec',      reason: 'PowerShell Start-Process is prohibited.' },
  { pattern: /\bwscript\b/i,                      category: 'code-exec',      reason: 'Windows Script Host (wscript) is prohibited.' },
  { pattern: /\bcscript\b/i,                      category: 'code-exec',      reason: 'Windows Script Host (cscript) is prohibited.' },
  { pattern: /\bmshta\b/i,                        category: 'code-exec',      reason: 'MSHTA execution is prohibited.' },
  { pattern: /\bregsvr32\b/i,                     category: 'code-exec',      reason: 'DLL registration/execution is prohibited.' },
  { pattern: /\brundll32\b/i,                     category: 'code-exec',      reason: 'DLL execution (rundll32) is prohibited.' },
  { pattern: /\binstallutil\b/i,                  category: 'code-exec',      reason: 'InstallUtil LOLBin execution is prohibited.' },
  // F-LT-30: was /\new-object…/ — \n is a literal newline in JS regex, not \b. Fixed typo.
  // Also added bare ProgID patterns — New-Object -ComObject with non-WScript targets slipped through.
  { pattern: /\bnew-object\s+.*-com(object)?\b/i,       category: 'code-exec', reason: 'PowerShell COM object instantiation is prohibited.' },
  { pattern: /\bshell\.application\b/i,                 category: 'code-exec', reason: 'Shell.Application COM instantiation is prohibited.' },
  { pattern: /\bscripting\.filesystemobject\b/i,        category: 'code-exec', reason: 'Scripting.FileSystemObject COM instantiation is prohibited.' },
  { pattern: /\bwscript\.(shell|network)\b/i,           category: 'code-exec', reason: 'WScript COM object instantiation is prohibited.' },
  { pattern: /\b\.(ShellExecute|Run|Exec)\s*\(/i,       category: 'code-exec', reason: 'COM .ShellExecute/.Run/.Exec method call is prohibited.' },
  { pattern: /\bset-alias\b/i,                          category: 'code-exec', reason: 'PowerShell Set-Alias is prohibited (alias indirection bypass).' },
  { pattern: /\bnew-alias\b/i,                    category: 'code-exec',      reason: 'PowerShell New-Alias is prohibited.' },
  { pattern: /&\s*\$[A-Za-z_]/,                   category: 'code-exec',      reason: 'PowerShell call operator on variable (&$x) is prohibited.' },

  // ── .NET Type Accelerators (F-6 fix) ─────────────────────────────────────
  // Bypass all verb-based blocks via [IO.File]::Delete, [Net.WebClient]::new(), etc.
  { pattern: /\[\s*(System\.)?(IO|Net|Diagnostics|Reflection|Runtime\.InteropServices|Management\.Automation)\b/i,
                                                  category: 'code-exec',      reason: '.NET type accelerator usage is prohibited (bypass vector).' },
  { pattern: /::\s*(Delete|Move|Copy|WriteAllBytes|WriteAllText|DownloadFile|DownloadString|Start|Load|LoadFrom|LoadFile|Invoke)\b/i,
                                                  category: 'code-exec',      reason: '.NET static method invocation for dangerous operations is prohibited.' },

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
  { pattern: /\bbitsadmin\b/i,                    category: 'data-exfil',     reason: 'BITS transfer (LOLBin) is prohibited.' },
  { pattern: /\bcertutil\b/i,                     category: 'data-exfil',     reason: 'certutil is prohibited (LOLBin download/encode vector).' },
  { pattern: /new-object\s+.*webclient/i,         category: 'data-exfil',     reason: 'PowerShell WebClient download is prohibited.' },
  { pattern: /\bssh\b/i,                          category: 'data-exfil',     reason: 'SSH connections are prohibited via MCP.' },
  { pattern: /\bmsbuild\b.*\.xml\b/i,             category: 'data-exfil',     reason: 'MSBuild inline task execution is prohibited (LOLBin).' },

  // ── Environment Variable Enumeration (F-7 supplement) ────────────────────
  { pattern: /\$env:[A-Za-z_]/i,                  category: 'info-leak',      reason: 'PowerShell $env: variable access is prohibited.' },
  { pattern: /get-(childitem|item|content)\s+env:/i, category: 'info-leak',   reason: 'PowerShell environment variable enumeration is prohibited.' },
  // F-LT-26: PowerShell short-alias env reads: gc/gi/gci/cat/type/ls env: also dump environment.
  { pattern: /\b(gc|gi|gci|cat|type|ls)\s+env:/i,   category: 'info-leak',   reason: 'PowerShell env: provider read via alias is prohibited.' },
  // F-LT-23: was set\s*(?:$|[|>&]) — missed `set <PREFIX>` forms like `set GITHUB_`.
  // Fixed: \s|$ after `set` catches `set ` (space+anything), `set` at EOL, and `set|…`.
  { pattern: /(?:^|[\s;&|])set(?:\s|$|[|>&])/i,  category: 'info-leak',      reason: 'cmd set (env dump) is prohibited.' },

  // ── Persistence Mechanisms ────────────────────────────────────────────────
  { pattern: /\breg\s+(add|delete|import|export)\b/i, category: 'persistence', reason: 'Registry modification is prohibited.' },
  { pattern: /set-itemproperty.*registry/i,       category: 'persistence',    reason: 'PowerShell registry modification is prohibited.' },
  { pattern: /new-itemproperty.*registry/i,       category: 'persistence',    reason: 'PowerShell registry creation is prohibited.' },
  { pattern: /\\CurrentVersion\\Run/i,            category: 'persistence',    reason: 'Startup registry key modification is prohibited.' },
  { pattern: /authorized_keys/i,                  category: 'persistence',    reason: 'SSH authorized_keys modification is prohibited.' },
  { pattern: /\.bashrc|\.bash_profile|\.profile/i,category: 'persistence',    reason: 'Shell initialization file modification is prohibited.' },
  { pattern: /startup\s*folder/i,                 category: 'persistence',    reason: 'Startup folder modification is prohibited.' },
  // F-LT-31: actual Startup folder path patterns — `startup folder` keyword missed the real paths.
  { pattern: /\\Start Menu\\Programs\\Startup\\/i,                  category: 'persistence', reason: 'Writing to the Startup folder is prohibited (persistence vector).' },
  { pattern: /\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/i, category: 'persistence', reason: 'Writing to the Startup folder is prohibited (persistence vector).' },
  { pattern: /\bshell:startup\b/i,                                   category: 'persistence', reason: 'shell:startup path is prohibited (persistence vector).' },

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

  // ── WMI / WMIC / CIM (F-9 fix) ───────────────────────────────────────────
  { pattern: /\bwmic\b/i,                         category: 'code-exec',      reason: 'WMIC is prohibited (process creation and file read bypass vector).' },
  { pattern: /\b(invoke-cimmethod|get-wmiobject|gwmi|get-ciminstance|gcim)\b/i,
                                                  category: 'code-exec',      reason: 'WMI/CIM cmdlets are prohibited.' },
  { pattern: /\bWin32_Process\b/i,                category: 'code-exec',      reason: 'Win32_Process WMI class is prohibited.' },

  // ── Command Chaining Exploits ─────────────────────────────────────────────
  { pattern: /[;&|]{2}.*\b(rm|del|format|shutdown|kill|taskkill)\b/i, category: 'chaining', reason: 'Command chaining with destructive commands is prohibited.' },
  { pattern: /;\s*\b(rm|del|format|shutdown|kill|taskkill|erase|rmdir|unlink|truncate|shred|wipe|passwd|chmod|chown|curl|wget|ssh|scp|sftp|eval|exec|sudo|runas)\b/i, category: 'chaining', reason: 'Single-semicolon chaining with dangerous commands is prohibited.' },
  { pattern: /\|\s*(bash|sh|cmd|powershell|pwsh)\b/i, category: 'chaining',   reason: 'Pipe-to-shell is prohibited.' },
  { pattern: /`[^`]*`/,                           category: 'chaining',       reason: 'Backtick command substitution is prohibited.' },
  // F-NEW-5: single-& chaining (Windows CMD separator, distinct from && which is already caught)
  { pattern: /(?<![>&])&(?![&>])/,                category: 'chaining',       reason: 'Single-& command chaining is prohibited (Windows CMD separator).' },

  // ── LOLBin Expansion (F-NEW-5) ────────────────────────────────────────────
  // LOLBAS binaries not covered by existing patterns.
  { pattern: /\bmsiexec\b/i,                      category: 'code-exec',      reason: 'msiexec is prohibited (remote MSI download+exec LOLBin).' },
  { pattern: /\bmsdt\b/i,                         category: 'code-exec',      reason: 'msdt.exe is prohibited (Follina RCE LOLBin, CVE-2022-30190).' },
  { pattern: /\bcmstp\b/i,                        category: 'code-exec',      reason: 'cmstp.exe is prohibited (ClickOnce policy bypass LOLBin).' },
  { pattern: /\besentutl\b/i,                     category: 'data-exfil',     reason: 'esentutl.exe is prohibited (locked-file copy, data exfil LOLBin).' },
  { pattern: /\bhh(\.exe)?\b/i,                   category: 'code-exec',      reason: 'hh.exe is prohibited (HTML Help code execution LOLBin).' },
  { pattern: /\bpcalua\b/i,                       category: 'code-exec',      reason: 'pcalua.exe is prohibited (Program Compatibility Assistant exec LOLBin).' },
  { pattern: /\bodbcconf\b/i,                     category: 'code-exec',      reason: 'odbcconf.exe is prohibited (arbitrary DLL execution LOLBin).' },
  { pattern: /\bregasm\b/i,                       category: 'code-exec',      reason: 'regasm.exe is prohibited (.NET assembly execution LOLBin).' },
  { pattern: /\bregsvcs\b/i,                      category: 'code-exec',      reason: 'regsvcs.exe is prohibited (.NET component services LOLBin).' },
  { pattern: /\bwsl(\.exe)?\b/i,                  category: 'code-exec',      reason: 'wsl.exe is prohibited (WSL shell bypass LOLBin).' },
  { pattern: /\bbash\.exe\b/i,                    category: 'code-exec',      reason: 'bash.exe (WSL) is prohibited (shell bypass LOLBin).' },
  { pattern: /\bmavinject\b/i,                    category: 'code-exec',      reason: 'mavinject.exe is prohibited (DLL injection LOLBin).' },
  { pattern: /\bxwizard\b/i,                      category: 'code-exec',      reason: 'xwizard.exe is prohibited (code execution LOLBin).' },
  { pattern: /\bpresentationhost\b/i,             category: 'code-exec',      reason: 'PresentationHost.exe is prohibited (XAML browser app exec LOLBin).' },
  { pattern: /\bsyncappvpublishingserver\b/i,     category: 'code-exec',      reason: 'SyncAppvPublishingServer is prohibited (PowerShell exec LOLBin).' },
  { pattern: /\bregedit\s+\/s\b/i,               category: 'persistence',    reason: 'regedit /s (silent registry import) is prohibited.' },
  // F-NEW-11: ln --symbolic long-form bypass
  { pattern: /\bln\s+--symbolic\b/i,              category: 'permissions',    reason: 'ln --symbolic (symlink creation, long-form) is prohibited.' },
  { pattern: /\bln\s+-s\b/i,                      category: 'permissions',    reason: 'ln -s (symlink creation) is prohibited.' },

  // ── Variable Expansion / Obfuscation ──────────────────────────────────────
  { pattern: /\$\(/,                              category: 'obfuscation',    reason: 'Shell command substitution $() is prohibited.' },
  { pattern: /\$\{[^}]+\}/,                       category: 'obfuscation',    reason: 'Variable expansion ${...} is prohibited in commands.' },
  { pattern: /%[A-Za-z_][A-Za-z0-9_]*%/,          category: 'obfuscation',    reason: 'Windows environment variable expansion %VAR% is prohibited.' },
  // F-LT-25: cmd.exe substring/replacement expansion — bypasses obfuscation regex + sensitive-path scanner.
  // %VAR:~n,m% slices a variable value; %VAR:X=Y% replaces chars. Both enable character-level obfuscation.
  { pattern: /%[A-Za-z_][A-Za-z0-9_]*:[~!*][^%]*%/, category: 'obfuscation', reason: 'cmd.exe substring/replacement variable expansion (%VAR:~n,m% / %VAR:X=Y%) is prohibited.' },

  // ── HTTP Server & Listener Binding ────────────────────────────────────────
  { pattern: /\bnc\s.*-l/i,                       category: 'http-server',    reason: 'Listening socket (netcat) is prohibited.' },
  { pattern: /python\s+-m\s+http\.server/i,       category: 'http-server',    reason: 'Python HTTP server is prohibited.' },
  { pattern: /\bnetstat\b.*-l/i,                  category: 'http-server',    reason: 'Listening port enumeration requires structured tools.' },
  { pattern: /simple-server|http-server.*--port/i, category: 'http-server',   reason: 'Starting HTTP servers is prohibited.' },

  // ── Interpreter Inline Code Execution (F-LT-5 + F-LT-9) ─────────────────────
  // node -e / -p: eval and print both execute arbitrary JS — same RCE surface
  { pattern: /\bnode\b[^|&;]*\s-[ep]\b/i,         category: 'code-exec',      reason: 'node -e/-p (inline code evaluation) is prohibited.' },
  { pattern: /\bnode\b[^|&;]*(--eval|--print)\b/i, category: 'code-exec',     reason: 'node --eval/--print (inline code evaluation) is prohibited.' },
  { pattern: /\bnode\b[^|&;]*(--require\b|-r\s)/i, category: 'code-exec',     reason: 'node --require/-r (module preload execution) is prohibited.' },
  { pattern: /\bnode\b[^|&;]*(--import\b)/i,       category: 'code-exec',     reason: 'node --import (ESM module preload) is prohibited.' },
  // node --inspect: opens V8 debugger port — RCE if port is reachable (F-LT-14)
  { pattern: /\bnode\b[^|&;]*--inspect\b/i,        category: 'code-exec',     reason: 'node --inspect opens a remote V8 debugger port and is prohibited.' },
  // python -m: invokes arbitrary stdlib modules (http.server, ftplib, pip, etc.)
  { pattern: /\bpython3?\b[^|&;]*\s-m\b/i,         category: 'code-exec',     reason: 'python -m (module invocation) is prohibited. Use structured tools.' },
  { pattern: /\bpy\b[^|&;]*\s-m\b/i,               category: 'code-exec',     reason: 'py -m (module invocation) is prohibited.' },
  // Other language interpreters with inline execution flags
  { pattern: /\bruby\b[^|&;]*\s-[er]\b/i,          category: 'code-exec',     reason: 'ruby -e/-r (inline eval/preload) is prohibited.' },
  { pattern: /\bphp\b[^|&;]*\s-r\b/i,              category: 'code-exec',     reason: 'php -r (inline code evaluation) is prohibited.' },
  { pattern: /\bperl\b[^|&;]*\s-[eE]\b/i,          category: 'code-exec',     reason: 'perl -e/-E (inline code evaluation) is prohibited.' },
  { pattern: /\bdeno\b[^|&;]*(eval|run)\b/i,       category: 'code-exec',     reason: 'deno eval/run is prohibited.' },

  // ── F-LT-32: Interpreter + scriptfile RCE ────────────────────────────────────
  // node/python/perl/ruby/php running a script file = arbitrary code execution given
  // any prior write access to user-writable paths. Block outright.
  { pattern: /\bnode(\.exe)?\s+\S+\.(c?js|mjs|ts)\b/i,  category: 'code-exec', reason: 'node <script> execution is prohibited (RCE vector).' },
  { pattern: /\bpython3?(\.exe)?\s+\S+\.py\b/i,          category: 'code-exec', reason: 'python <script> execution is prohibited.' },
  { pattern: /\bperl(\.exe)?\s+\S+\.pl\b/i,              category: 'code-exec', reason: 'perl <script> execution is prohibited.' },
  { pattern: /\bruby(\.exe)?\s+\S+\.rb\b/i,              category: 'code-exec', reason: 'ruby <script> execution is prohibited.' },
  { pattern: /\bphp(\.exe)?\s+\S+\.php\b/i,              category: 'code-exec', reason: 'php <script> execution is prohibited.' },
  // Redirect to executable/script extension — defense-in-depth for write-then-exec kill chain.
  { pattern: />\s*[^\s|&;]+\.(js|mjs|cjs|ts|py|pl|rb|php|ps1|psm1|vbs|wsf|bat|cmd|hta|exe|dll|msi|lnk)\b/i,
                                                          category: 'file-write', reason: 'Redirect to executable/script file extension is prohibited.' },

  // ── Additional LOLBins (F-LT-15) ─────────────────────────────────────────────
  { pattern: /\bforfiles\b/i,                      category: 'code-exec',     reason: 'forfiles is prohibited (per-file command execution LOLBin).' },
  { pattern: /\bfinger\b/i,                        category: 'data-exfil',    reason: 'finger is prohibited (external user info disclosure).' },
  { pattern: /\bdiskshadow\b/i,                    category: 'code-exec',     reason: 'diskshadow is prohibited (VSS shadow-copy exec LOLBin).' },
  { pattern: /\bmmc(\.exe)?\s/i,                   category: 'code-exec',     reason: 'mmc.exe is prohibited (MMC snap-in code exec LOLBin).' },
];

function checkBlocked(cmd: string): { blocked: true; category: string; reason: string } | { blocked: false } {
  // ── CRITICAL FIX (S35): Reject non-ASCII to prevent Unicode homoglyph bypass ──
  // Cyrillic/Greek lookalikes (e.g. Cyrillic 'р' for Latin 'r') defeat \b word boundaries.
  if (/[^\x00-\x7F]/.test(cmd)) {
    return { blocked: true, category: 'obfuscation', reason: 'Non-ASCII characters in commands are prohibited. This prevents Unicode homoglyph bypasses.' };
  }

  // ── F-LT-24: Reject cmd.exe caret escape outside quoted strings ──────────────
  // Carets outside quotes are cmd.exe escape characters: c^url, ^s^e^t, r^m.
  // They defeat every \b<verb>\b RED pattern by splitting the token character-by-character.
  // Strip double-quoted segments first (carets inside quotes are literal), then reject any ^.
  if (/\^/.test(cmd.replace(/"[^"]*"/g, ''))) {
    return { blocked: true, category: 'obfuscation', reason: 'Caret (^) escape outside quoted strings is prohibited. This prevents cmd.exe caret-obfuscation bypasses (c^url, ^s^e^t).' };
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
  // Environment files — F-LT fix: negative lookahead catches .env" .env) .env/ .env$IFS variants
  /\.env(?![a-zA-Z0-9])/i,

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

  // F-13: additional credential stores missed in original list
  /\.npmrc/i,                                   // NPM_TOKEN
  /\.pypirc/i,                                  // PyPI token
  /pip\.conf/i,                                 // pip credentials
  /\.netrc/i,                                   // HTTP auth (many tools)
  /[\\\/]gh[\\\/]hosts\.yml/i,                  // GitHub CLI token
  /\.azure[\\\/]accessTokens/i,                 // Azure CLI
  /\.azure[\\\/]azureProfile/i,
  /application_default_credentials/i,           // GCP ADC
  /\.terraformrc/i,                             // Terraform Cloud token
  /terraform\.rc/i,
  /\.m2[\\\/]settings\.xml/i,                   // Maven credentials
  /\.gradle[\\\/]gradle\.properties/i,          // Gradle signing
  /\.cargo[\\\/]credentials/i,                  // crates.io token
  /composer[\\\/]auth\.json/i,                  // Composer
  /\.kaggle[\\\/]kaggle\.json/i,                // Kaggle API key
  /PSReadLine[\\\/]ConsoleHost_history/i,        // PowerShell history
  /\.bash_history/i,                            // shell history
  /\.zsh_history/i,
  /\.history$/i,
  /AppData[\\\/]Roaming[\\\/]npm[\\\/]etc[\\\/]npmrc/i,
  /AppData[\\\/]Roaming[\\\/]GitHub CLI/i,
  /Local State$/i,                              // Chrome encryption key
  /\.kdbx$/i,                                   // KeePass
  /wallet\.dat/i,                               // crypto wallets

  // F-LT-13: Browser and app token stores missed in passes 1-2
  /[\\\/]Slack[\\\/]Local Storage[\\\/]/i,          // Slack session tokens (leveldb)
  /[\\\/]discord[\\\/]Local Storage[\\\/]/i,         // Discord tokens
  /[\\\/]discord[\\\/]Session Storage[\\\/]/i,
  /[\\\/]Chrome[\\\/]User Data[\\\/][^\\\/]+[\\\/]Login Data$/i,  // Chrome saved passwords
  /[\\\/]Chrome[\\\/]User Data[\\\/][^\\\/]+[\\\/]Cookies$/i,
  /[\\\/]Firefox[\\\/]Profiles[\\\/]/i,              // Firefox profile data (logins.json etc.)
  /[\\\/]Microsoft[\\\/]Vault[\\\/]/i,               // Windows Credential Manager vault
  /[\\\/]Code[\\\/]User[\\\/]settings\.json$/i,      // VS Code settings (may contain secrets)
  /[\\\/]Code[\\\/]User[\\\/]globalStorage[\\\/]/i,  // VS Code extension storage
];

function isSensitiveFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return SENSITIVE_FILE_PATTERNS.some(p => p.test(normalized) || p.test(basename(normalized)));
}

// F-1 fix: scan a free-form command string for any token that looks like a path
// to a sensitive file. Applies the same SENSITIVE_FILE_PATTERNS used by read_file
// to every whitespace-delimited token in the command, so `type C:\..\.ssh\id_rsa`
// is caught even though the verb `type` isn't in the blocked-pattern list.
function commandContainsSensitivePath(cmd: string): boolean {
  // Split on whitespace and common shell delimiters; strip surrounding quotes
  const tokens = cmd.split(/[\s"']+/).map(t => t.trim()).filter(Boolean);
  return tokens.some(token => isSensitiveFile(token));
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

const COMMAND_TIMEOUT_MS = 30_000;

// ─── F-22: Input size caps (prevents ReDoS amplification + log flooding) ────────
// Every user-supplied string is checked before any regex runs.
// Caps mirror vps-control-mcp's INPUT_LIMITS established in F-VM-3.
const INPUT_LIMITS: Record<string, number> = {
  command:       4_096,  // run_command — generous; most legit commands fit in 256
  filePath:        512,  // read_file / search_file path
  searchPattern:   256,  // search_file pattern (regex)
  findPattern:     256,  // find_files pattern (glob)
  directory:       512,  // all dir / working_directory params
  gitSubCommand:   512,  // run_git_command sub-command string
  npmSubCommand:   256,  // run_npm_command sub-command string
};

function checkSize(value: string, field: keyof typeof INPUT_LIMITS): string | null {
  const limit = INPUT_LIMITS[field];
  if (value.length > limit) {
    return `ERROR: '${field}' exceeds maximum allowed length (${value.length} > ${limit}). Reduce input size.`;
  }
  return null;
}

// ─── F-23/F-NEW-8: ReDoS guard for user-supplied regex (search_file) ────────────
// Classic catastrophic-backtracking shapes are rejected before the regex compiles.
// F-NEW-8 fix: shape 1 now also catches {n,m} inside the group, e.g. (a{2,})+
const CATASTROPHIC_REGEX_SHAPES: RegExp[] = [
  /\([^)]*[+*{]\)\s*[+*{]/, // nested quantifier: (x+)+ (x*)* (x+){n} (x{2,})+
  /\([^)]*\|[^)]*\)\s*[+*{]/, // quantified alternation: (a|b)+
  /(\w\|){4,}/,               // wide alternation: a|b|c|d|... (>3 alternatives)
  /\(.*\).*\\[0-9]\s*[+*{]/,  // quantified backreference: (.+)\1+
  // F-LT-29: three or more sequential .* / .+ (polynomial backtracking on non-matching strings).
  // e.g. .*.*.*.*secret — each .* must try every split point, O(n^k) with k wildcards.
  /(?:\.[*+]){3,}/,
];

function isReDoSPattern(pattern: string): boolean {
  return CATASTROPHIC_REGEX_SHAPES.some(shape => shape.test(pattern));
}

// ─── F-25/F-NEW-9/10: Output-side secret scrubbing ──────────────────────────────
// Scan tool output for known token shapes and PEM headers; redact to [REDACTED].
// F-NEW-9: expanded with post-2020 SaaS token formats.
// F-NEW-10: base64 catch-all tightened from {60,} to {80,} to reduce false positives.
const SECRET_OUTPUT_PATTERNS: RegExp[] = [
  // GitHub
  /ghp_[A-Za-z0-9]{36,}/g,
  /ghs_[A-Za-z0-9]{36,}/g,
  /gho_[A-Za-z0-9]{36,}/g,
  // OpenAI
  /sk-[A-Za-z0-9]{40,}/g,
  // Anthropic
  /sk-ant-[A-Za-z0-9\-_]{80,}/g,
  // AWS
  /AKIA[0-9A-Z]{16}/g,
  /ASIA[0-9A-Z]{16}/g,                          // AWS STS temporary key
  // Slack
  /xox[baprs]-[A-Za-z0-9\-]{20,}/g,
  /xapp-[A-Za-z0-9\-]{20,}/g,                   // Slack app-level token (F-NEW-9)
  // GitLab (F-NEW-9)
  /glpat-[A-Za-z0-9_\-]{20,}/g,
  /glptt-[A-Za-z0-9_\-]{20,}/g,
  /glsoat-[A-Za-z0-9_\-]{20,}/g,
  /glrt-[A-Za-z0-9_\-]{20,}/g,
  /gldt-[A-Za-z0-9_\-]{20,}/g,
  // Stripe (F-NEW-9)
  /sk_live_[A-Za-z0-9]{24,}/g,
  /sk_test_[A-Za-z0-9]{24,}/g,
  /rk_live_[A-Za-z0-9]{24,}/g,
  /whsec_[A-Za-z0-9]{24,}/g,
  // Twilio (F-NEW-9)
  /AC[a-f0-9]{32}/g,
  /SK[a-f0-9]{32}/g,
  // SendGrid (F-NEW-9)
  /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,
  // npm (F-NEW-9)
  /npm_[A-Za-z0-9]{36,}/g,
  // Atlassian (F-NEW-9)
  /ATATT3xFfGF0[A-Za-z0-9_\-=]{20,}/g,
  // DigitalOcean (F-NEW-9)
  /dop_v1_[a-f0-9]{64}/g,
  /doo_v1_[a-f0-9]{64}/g,
  /dor_v1_[a-f0-9]{64}/g,
  // Docker Hub (F-NEW-9)
  /dckr_pat_[A-Za-z0-9_\-]{27,}/g,
  // Square (F-NEW-9)
  /EAAA[A-Za-z0-9_\-]{60,}/g,
  // Mailgun (F-NEW-9)
  /key-[a-f0-9]{32}/g,
  // Google API (F-NEW-9)
  /AIza[A-Za-z0-9_\-]{35}/g,
  // PEM private keys
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
  // High-entropy base64 (tightened to {80,} — F-NEW-10)
  /[A-Za-z0-9+/]{80,}={0,2}(?=\s|$)/g,
];

function scrubSecrets(output: string): string {
  let scrubbed = output;
  for (const pattern of SECRET_OUTPUT_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, '[REDACTED]');
  }
  return scrubbed;
}

// ─── Scrubbed environment for child processes (F-7 fix, F-LT-33 hardening) ───
// F-LT-33: prior blocklist approach missed GITHUB_TOKEN, NPM_TOKEN, HF_TOKEN,
// DATABASE_URL, OPENAI_KEY, etc. (no bare TOKEN/KEY/URL coverage).
// Switched to allowlist (Option B): only pass through variables that are
// safe, well-known system vars. Everything else is dropped — including any
// future secret-shaped vars not yet on any blocklist.
// Allowlist source: standard Windows/POSIX system env vars needed by common tools.
const SAFE_ENV_ALLOWLIST = new Set([
  'PATH', 'PATHEXT',
  'USERPROFILE', 'HOMEPATH', 'HOMEDRIVE', 'HOME',
  'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
  'PROGRAMFILES', 'PROGRAMFILES(X86)',
  'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR',
  'COMSPEC', 'COMPUTERNAME',
  'USERNAME', 'USERDOMAIN', 'USERDNSDOMAIN',
  'TEMP', 'TMP',
  'OS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'NUMBER_OF_PROCESSORS',
  'LANG', 'TZ',
  // Node.js / npm env vars that are safe for child npm processes
  'NODE_PATH', 'NPM_CONFIG_PREFIX',
  // Git needs these for locale/terminal
  'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL',
  'TERM', 'COLORTERM',
]);

function buildSafeEnv(): NodeJS.ProcessEnv {
  const safeEnv: NodeJS.ProcessEnv = {};
  for (const [key, val] of Object.entries(process.env)) {
    if (SAFE_ENV_ALLOWLIST.has(key.toUpperCase()) || SAFE_ENV_ALLOWLIST.has(key)) {
      safeEnv[key] = val;
    }
  }
  return safeEnv;
}

// ─── F-19: execFile wrapper ───────────────────────────────────────────────────
// Structured tools use runFile() with explicit argv arrays and shell:false.
// This eliminates the shell re-parse layer — no metachar injection is possible
// because the OS receives argc/argv directly, never a shell command string.
// run_command (the escape hatch) still uses runCommand/execSync by design —
// it IS a shell command runner — but it is protected by the RED/AMBER pattern
// checks which must pass before execution.
function runFile(
  exe: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}
): string {
  try {
    return execFileSync(exe, args, {
      cwd: opts.cwd,
      env: opts.env ?? buildSafeEnv(),
      timeout: opts.timeoutMs ?? COMMAND_TIMEOUT_MS,
      encoding: "utf8",
      windowsHide: true,
      shell: false,
    }).trim();
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string; killed?: boolean };
    if (e.killed) return `ERROR: Command timed out after ${(opts.timeoutMs ?? COMMAND_TIMEOUT_MS) / 1000}s and was killed.`;
    return `ERROR: ${e.stderr ?? e.stdout ?? e.message ?? "Unknown error"}`.trim();
  }
}

// Simple argv splitter for the restricted sub-command strings we accept from
// run_git_command and run_npm_command. Handles double-quoted tokens only.
// NOT a general shell parser — do not use for untrusted input.
function splitArgv(cmd: string): string[] {
  // F-NEW-13: strip null bytes, CR/LF, and backticks before parsing —
  // these cannot appear in valid git/npm sub-commands and enable injection.
  const sanitized = cmd.replace(/[\x00\r\n`]/g, '');
  const args: string[] = [];
  const re = /"([^"]+)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sanitized)) !== null) {
    args.push(m[1] ?? m[2]);
  }
  return args;
}

// ─── F-NEW-2: Neutralizing -c flags prepended to every git invocation ────────
// Prevents repo-local .git/config from overriding dangerous git config keys
// (diff.external, core.pager, core.fsmonitor, core.sshCommand, core.editor,
// protocol.ext.allow). These empty/safe values take precedence over repo-local
// config because they appear first on the command line.
const GIT_SAFE_CONFIG: string[] = [
  '-c', 'diff.external=',
  '-c', 'core.pager=cat',
  '-c', 'core.fsmonitor=',
  '-c', 'core.sshCommand=',
  '-c', 'core.editor=true',
  '-c', 'protocol.ext.allow=never',
  '-c', 'protocol.file.allow=user',
  // F-LT-10: neutralize repo-local hooks and diff driver commands
  '-c', process.platform === 'win32' ? 'core.hooksPath=NUL' : 'core.hooksPath=/dev/null',
];

// ─── F-NEW-1 + F-NEW-6: git argv hardening ───────────────────────────────────
// Blocks flags that turn read-only git commands into arbitrary file readers or
// code executors: --no-index (untracked file diff), --ext-diff (external diff
// tool exec), -p/--patch (history content dump), -S/-G (pickaxe secret search),
// --output/-O (write to file), --config-env/-c (config injection),
// --exec-path (binary path override), --textconv (filter execution).
// Also blocks 'git show <ref>:<sensitive-path>' historical secret exfil.
const FORBIDDEN_GIT_FLAGS = new Set([
  '--no-index', '--ext-diff', '--textconv', '--output', '-O',
  '--config-env', '-c', '--exec-path', '-p', '--patch', '-S', '-G',
  // F-LT-10: CWD escape and repo-dir override
  '-C', '--work-tree', '--git-dir', '--super-prefix', '--namespace',
  // F-LT-16: reflog/orphan-ref access (exposes deleted secrets)
  '--walk-reflogs', '--reflog',
  // F-LT-21: binary blob leak channel
  '--binary',
]);

function validateGitArgv(subCmd: string, cmdArgs: string[]): string | null {
  for (const arg of cmdArgs) {
    // Exact flag match
    if (FORBIDDEN_GIT_FLAGS.has(arg)) {
      return `git flag '${arg}' is not permitted (file-read or code-exec vector).`;
    }
    // Pickaxe flags (--pickaxe-all, --pickaxe-regex)
    if (/^--pickaxe/.test(arg)) {
      return `git flag '${arg}' (pickaxe search) is not permitted.`;
    }
    // Long-form flags with = assignment
    if (/^--output=/.test(arg) || /^--exec-path=/.test(arg) || /^--config-env=/.test(arg)) {
      return `git flag '${arg}' is not permitted (file-write or config-inject vector).`;
    }
    // F-LT-27: reflog syntax (@{N}, branch@{0}, @{-1}) exposes deleted/stashed secrets
    if (/@\{/.test(arg)) {
      return `git argument '${arg}' uses reflog syntax (@{N}) which is not permitted — reflog entries can expose deleted or stashed credentials.`;
    }
  }
  // For 'show': reject <ref>:<path> where path matches sensitive file patterns
  if (subCmd === 'show') {
    for (const arg of cmdArgs) {
      const colonIdx = arg.indexOf(':');
      if (colonIdx > 0) {
        const refPath = arg.slice(colonIdx + 1);
        if (isSensitiveFile(refPath)) {
          return `git show path '${refPath}' matches a sensitive file pattern and cannot be accessed.`;
        }
      }
    }
  }
  // F-LT-8: scan pathspec tokens (everything after --) for all subcommands
  // Catches: git log -- '*.env', git diff -- id_rsa, git show <sha> -- config/.env
  const ddIdx = cmdArgs.indexOf('--');
  if (ddIdx >= 0) {
    for (const ps of cmdArgs.slice(ddIdx + 1)) {
      if (ps.length > 0 && isSensitiveFile(ps)) {
        return `git pathspec '${ps}' matches a sensitive file pattern and cannot be accessed.`;
      }
    }
  }
  return null;
}

// ─── F-LT-1/2/3/12: Safe git environment ────────────────────────────────────────
// buildSafeGitEnv() extends buildSafeEnv() with git-specific env hardening:
//   F-LT-1: GIT_PAGER outranks core.pager config — force it to 'cat'
//   F-LT-2: GIT_EXTERNAL_DIFF / GIT_DIFF_OPTS invoke arbitrary diff commands
//   F-LT-3: GIT_CONFIG_COUNT/KEY_N/VALUE_N inject arbitrary git config overrides
//   F-LT-12: GIT_DIR/GIT_WORK_TREE/GIT_OBJECT_DIRECTORY redirect git's repo view
function buildSafeGitEnv(dir: string): NodeJS.ProcessEnv {
  const env = buildSafeEnv();

  // F-LT-1: force safe pager — GIT_PAGER overrides any -c core.pager=cat config
  env.GIT_PAGER = 'cat';
  env.PAGER = 'cat';

  // F-LT-2: strip diff-invoking env vars
  delete env.GIT_EXTERNAL_DIFF;
  delete env.GIT_DIFF_OPTS;

  // F-LT-3: strip GIT_CONFIG_COUNT/KEY_N/VALUE_N injection vectors
  // F-LT-12: strip GIT_DIR / GIT_WORK_TREE / GIT_OBJECT_DIRECTORY overrides
  const GIT_ENV_BLOCKLIST = [
    'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS',
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  ];
  for (const key of Object.keys(env)) {
    if (
      GIT_ENV_BLOCKLIST.includes(key) ||
      key.startsWith('GIT_CONFIG_KEY_') ||
      key.startsWith('GIT_CONFIG_VALUE_')
    ) {
      delete env[key];
    }
  }

  // Hardened fixed values
  env.GIT_CONFIG_NOSYSTEM = '1';
  env.GIT_CONFIG_GLOBAL = process.platform === 'win32' ? 'NUL' : '/dev/null';
  env.GIT_TERMINAL_PROMPT = '0';
  env.GIT_ALLOW_PROTOCOL = 'https:http:file';
  env.GIT_CEILING_DIRECTORIES = dir;

  return env;
}

function runCommand(cmd: string, timeoutMs = COMMAND_TIMEOUT_MS): string {
  try {
    return execSync(cmd, {
      timeout: timeoutMs,
      encoding: "utf8",
      windowsHide: true,
      env: buildSafeEnv(),
    }).trim();
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string; killed?: boolean };
    if (e.killed) return `ERROR: Command timed out after ${timeoutMs / 1000}s and was killed.`;
    return `ERROR: ${e.stderr ?? e.stdout ?? e.message ?? "Unknown error"}`.trim();
  }
}

// F-10: replace tiny denylist with a strict allowlist.
// Accepts only absolute Windows paths (drive-letter form) containing safe chars.
// Rejects: UNC paths, device paths (\\.\, \\?\), leading dashes (flag injection),
// and any character outside the alphanumeric + safe punctuation set.
function sanitizeDir(dir: string): string {
  if (!dir || typeof dir !== 'string') throw new Error('Directory path is required.');
  const trimmed = dir.trim();
  // Reject UNC / device namespace / network paths
  // F-LT-6: reject UNC paths in both backslash (\\server) and forward-slash (//server) forms
  if (/^(\\\\|\/\/)/.test(trimmed)) throw new Error('UNC and device paths are not allowed.');
  // Reject leading dash (flag injection: --exec-path, --registry, etc.)
  if (/^[-/]/.test(trimmed)) throw new Error('Directory path must not start with a flag character.');
  // Reject newlines, null bytes, and other control characters
  if (/[\x00-\x1F\x7F]/.test(trimmed)) throw new Error('Directory path contains control characters.');
  // Allow: drive-letter paths (C:\...) and relative paths with safe characters only
  // Safe chars: word chars, spaces, hyphens, dots, underscores, backslash, forward slash, colon (for drive letter), parens
  if (!/^(?:[A-Za-z]:)?[\\\/]?[\w\s.\-\\\/()[\]@+,{}#!]+$/.test(trimmed)) {
    throw new Error(`Directory path contains unsafe characters: ${trimmed}`);
  }
  // F-NEW-12: strip trailing path separator (preserving drive root: C:\)
  const normalized = /^[A-Za-z]:[\\\/]$/.test(trimmed)
    ? trimmed
    : trimmed.replace(/[\\\/]+$/, '');
  return normalized;
}

const MAX_CMD_OUTPUT_CHARS = 10_000;
function truncateOutput(output: string): string {
  if (output.length <= MAX_CMD_OUTPUT_CHARS) return output;
  return (
    output.slice(0, MAX_CMD_OUTPUT_CHARS) +
    `\n\n[TRUNCATED: ${output.length} chars total. Only first ${MAX_CMD_OUTPUT_CHARS} shown.]`
  );
}

// Category-specific "what to do instead" guidance shown in every RED block.
const BLOCKED_ALTERNATIVES: Record<string, string> = {
  'file-delete':    'File deletion is not available via MCP. Perform this operation manually in Explorer or CMD outside of Claude.',
  'disk-ops':       'Disk and partition operations are not available via MCP.',
  'system-state':   'System shutdown/restart must be done manually.',
  'process-kill':   'To stop a process, use Task Manager or do so manually outside of Claude.',
  'user-mgmt':      'User and group management must be done manually via Windows Settings or an elevated CMD.',
  'permissions':    'File permission changes must be done manually.',
  'network-config': 'Network configuration changes must be done manually.',
  'scheduled-exec': 'Scheduled task management must be done manually via Task Scheduler.',
  'service-mgmt':   'Service management must be done manually via services.msc.',
  'code-exec':      'Use structured tools instead: run_npm_command, run_git_command, or run_command with an approved command.',
  'data-exfil':     'Network transfers are not available via MCP. Use your browser or download manager for web requests.',
  'persistence':    'Persistence mechanism changes are not available via MCP.',
  'direct-db':      'Database write operations are not available via MCP. Use your database client directly.',
  'pkg-install':    'Package installation must be done outside of Claude. Run npm install / pip install in your own terminal.',
  'pkg-remove':     'Package removal must be done outside of Claude.',
  'container':      'Container operations are not available via MCP.',
  'file-write':     'Writing to system directories is not available via MCP.',
  'env-manip':      'Environment variable persistence must be done manually via System Properties.',
  'priv-esc':       'Privilege escalation is not available via MCP.',
  'info-leak':      'This information source is not accessible via MCP.',
  'chaining':       'Split into separate run_command calls — one command per call.',
  'obfuscation':    'Simplify the command. Substitution syntax and non-ASCII characters are not permitted.',
  'http-server':    'Starting servers via MCP is not available.',
  'sensitive-file': 'Sensitive files cannot be accessed via MCP. Open the file directly on your machine if needed.',
  'path-validation':'Check the path for control characters or unsupported path formats.',
};

function formatBlockedError(category: string, reason: string): string {
  const alternative = BLOCKED_ALTERNATIVES[category] ?? 'This operation must be performed outside of Claude.';
  return [
    `⛔ BLOCKED [${category}]`,
    ``,
    reason,
    ``,
    `What to do instead: ${alternative}`,
    ``,
    `This command is classified RED (hard-blocked) under the local-terminal-mcp security model.`,
    `It cannot be executed regardless of dry_run setting or justification.`,
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
    description: "List files and folders in a directory. Read-only, always safe. USE THIS — never ask the user to run `dir` or `ls` themselves, never ask them to select or grant a folder through a file picker. local-terminal already has full Windows file system access. Call this tool directly.",
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
    description: "Read the contents of a text file. Read-only, always safe. Max 500 lines. USE THIS — never ask the user to open the file in Notepad or run `type`/`cat` in CMD and paste back. Read it directly.",
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
    description: "Get OS version, hostname, username, disk space, memory, and running processes. Read-only. USE THIS — never ask the user to run systeminfo, ver, hostname, whoami, or Task Manager themselves. This tool returns the canonical machine snapshot.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "find_files",
    annotations: { title: 'Find Files', readOnlyHint: true, destructiveHint: false },
    description: "Search for files by name pattern in a directory. Read-only. USE THIS — never ask the user to run `dir /s`, `where`, or open Windows Search themselves. This tool is the single source for file discovery on their machine.",
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
    description: "Run read-only npm commands in a project directory. Approved sub-commands: list, outdated, audit, view, why, explain. npm install, npm run, and npm ci are NOT available (they execute lifecycle scripts). USE THIS — never ask the user to open a terminal and type npm commands themselves. This tool runs npm in their project directory with full audit logging.",
    inputSchema: {
      type: "object",
      properties: {
        directory:         { type: "string", description: "Project directory to run the command in. Also accepted as 'working_directory'." },
        working_directory: { type: "string", description: "Alias for 'directory'. Either param is accepted." },
        command:           { type: "string", description: "npm sub-command — one of: list, outdated, audit, view, why, explain." },
      },
      required: ["directory", "command"],
    },
  },
  {
    name: "run_git_command",
    annotations: { title: 'Run Git Command', readOnlyHint: true, destructiveHint: false },
    description: "Run read-only git commands: status, log, diff, branch, fetch. USE THIS — never ask the user to run `git status`/`git log`/`git diff`/`git fetch` in their terminal and paste the output. This tool returns the same result and audits every call.",
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
    description: "Run an arbitrary shell command. dry_run=true by default — always preview before executing. Hard-blocked patterns are enforced server-side. USE THIS — never ask the user to open CMD or PowerShell and run the command themselves. Handing commands to the user defeats the audit trail and the RED/AMBER tier checks, and is a defect against the product's automation-first contract.",
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
    description: "Search for text patterns in a file or directory. Read-only grep/findstr equivalent. USE THIS — never ask the user to run findstr or grep themselves. This tool is the canonical search path and respects the sensitive-file block list.",
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
      const rawPath = (args.path as string | undefined) ?? ".";
      // F-NEW-3: UNC/device path rejection — \\server\share resolves WebDAV/NTLM
      // F-LT-6: reject backslash and forward-slash UNC forms
      if (/^(\\\\|\/\/)/.test(rawPath.trim())) {
        return {
          result: formatBlockedError('path-validation', 'UNC and device paths (\\\\server\\share, //server/share) are not allowed.'),
          tier: "red", blocked: true, dryRun: false,
        };
      }
      // F-LT-34: sensitive directory guard — resolving a sensitive dir reveals which
      // credential files exist inside it even without reading their contents.
      // Append '/' to trigger path-segment patterns like /[\\\/]\.ssh[\\\/]/i.
      const rawForSensCheck = rawPath.replace(/\\/g, '/').replace(/\/?$/, '/');
      if (isSensitiveFile(rawForSensCheck)) {
        return {
          result: formatBlockedError('sensitive-file', `Listing '${rawPath}' is blocked — this directory matches a sensitive path pattern (credentials, keys, or secrets directory).`),
          tier: "red", blocked: true, dryRun: false,
        };
      }
      const dir = rawPath;
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
      const filePath = args.path as string;
      // F-22: input size cap
      const _rfSize = checkSize(filePath, 'filePath');
      if (_rfSize) return { result: _rfSize, tier: "green", blocked: false, dryRun: false };
      // F-27: reject control characters in path
      if (/[\x00-\x1F\x7F]/.test(filePath)) {
        return { result: formatBlockedError('path-validation', 'File path contains control characters.'), tier: "red", blocked: true, dryRun: false };
      }

      // F-11/F-14: canonicalize path before any pattern check to defeat UNC,
      // long-path prefix (\\?\), 8.3 short names, symlinks, and ../ traversal.
      // Strip alternate data stream suffix (:streamname) first.
      let canonicalPath: string;
      try {
        // Strip ADS suffix (e.g. file.txt:hidden)
        const stripped = filePath.replace(/:[\w.]+$/, '');
        // Reject UNC / device namespace
        const normalized = normalize(stripped);
        // F-LT-6: reject both backslash and forward-slash UNC forms
        if (/^(\\\\|\/\/)/.test(normalized)) {
          return {
            result: formatBlockedError('sensitive-file', 'UNC and device paths are not allowed.'),
            tier: "red", blocked: true, dryRun: false,
          };
        }
        // resolve() + realpathSync follows symlinks to the true target
        canonicalPath = realpathSync(resolve(stripped));
      } catch (resolveErr: unknown) {
        // F-LT-35: fail-closed — if realpathSync throws (permission error, broken symlink,
        // or dangling path), we cannot verify the canonical target, so we must block.
        // The only safe exception is ENOENT (file genuinely does not exist yet), which
        // is returned as a readable error rather than a security block.
        const code = (resolveErr as NodeJS.ErrnoException).code;
        if (code === 'ENOENT') {
          return { result: `ERROR: File not found: '${filePath}'`, tier: "green", blocked: false, dryRun: false };
        }
        return {
          result: formatBlockedError('path-validation', `Cannot resolve canonical path for '${filePath}': ${(resolveErr as Error).message}. Access denied.`),
          tier: "red", blocked: true, dryRun: false,
        };
      }

      // Sensitive file guard — check BOTH original and canonical path
      if (isSensitiveFile(filePath) || isSensitiveFile(canonicalPath)) {
        return {
          result: formatBlockedError('sensitive-file', `Access to '${basename(canonicalPath)}' is blocked. This file matches a sensitive file pattern (credentials, keys, secrets, environment files). Sensitive files cannot be read regardless of command tier.`),
          tier: "red",
          blocked: true,
          dryRun: false,
        };
      }

      // F-LT-11: NTFS hardlink check — hardlinks share inode data but realpathSync
      // cannot distinguish them (all link paths are equally canonical). If nlink > 1
      // on Windows, use fsutil to enumerate all linked paths and reject if any is sensitive.
      if (process.platform === 'win32') {
        try {
          const st = statSync(canonicalPath);
          if (st.nlink > 1) {
            const fsutilOut = execFileSync('fsutil', ['hardlink', 'list', canonicalPath], {
              encoding: 'utf8', timeout: 5_000, windowsHide: true, shell: false,
            }) as string;
            const linkedPaths = fsutilOut.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            for (const lp of linkedPaths) {
              if (isSensitiveFile(lp)) {
                return {
                  result: formatBlockedError('sensitive-file',
                    `File has a hard link to sensitive location '${basename(lp)}'. Access blocked.`),
                  tier: "red", blocked: true, dryRun: false,
                };
              }
            }
          }
        } catch { /* fsutil unavailable or stat failed — proceed */ }
      }

      const startLine = Math.max(1, (args.start_line as number | undefined) ?? 1);
      const endLine   = Math.min(500, (args.end_line as number | undefined) ?? 500);
      try {
        const lines = readFileSync(canonicalPath, "utf8").split("\n");
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
      const rawDir  = args.directory as string;
      const pattern = args.pattern as string;
      // F-22: input size caps
      const _ffDirSz = checkSize(rawDir, 'directory');
      if (_ffDirSz) return { result: _ffDirSz, tier: "green", blocked: false, dryRun: false };
      const _ffPatSz = checkSize(pattern, 'findPattern');
      if (_ffPatSz) return { result: _ffPatSz, tier: "green", blocked: false, dryRun: false };
      // F-NEW-3: sanitizeDir blocks UNC/device paths (WebDAV/NTLM leak) and flag injection
      let dir: string;
      try { dir = sanitizeDir(rawDir); }
      catch (e: unknown) {
        return { result: `ERROR: ${(e as Error).message}`, tier: "green", blocked: false, dryRun: false };
      }
      // F-19: native fs walk — no shell process, no injection surface.
      // Convert glob pattern to regex: escape regex metacharacters, then
      // restore * → .* and ? → . so standard glob wildcards work as expected.
      const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                             .replace(/\*/g, '.*')
                             .replace(/\?/g, '.');
      const re = new RegExp(`^${escaped}$`, 'i');
      const matches: string[] = [];
      // F-NEW-7: caps to prevent DoS via unbounded walk
      const MAX_RESULTS = 500;
      const MAX_DEPTH   = 8;
      const DEADLINE_MS = 15_000;
      const deadline    = Date.now() + DEADLINE_MS;
      // F-NEW-7: track visited dev:ino pairs to detect and break symlink cycles
      const visited = new Set<string>();
      const walk = (d: string, depth: number) => {
        if (depth > MAX_DEPTH) return;
        if (Date.now() > deadline) return;
        if (matches.length >= MAX_RESULTS) return;
        let entries: string[];
        try { entries = readdirSync(d); } catch { return; }
        for (const e of entries) {
          if (matches.length >= MAX_RESULTS) return;
          if (Date.now() > deadline) return;
          const full = join(d, e);
          // F-NEW-7: lstatSync sees the symlink itself — never follows it
          let lst;
          try { lst = lstatSync(full); } catch { continue; }
          if (lst.isSymbolicLink()) continue;   // skip all symlinks
          if (lst.isDirectory()) {
            // Cycle guard via stable dev:ino identity
            const key = `${lst.dev}:${lst.ino}`;
            if (visited.has(key)) continue;
            visited.add(key);
            // F-LT-7: detect NTFS junction points (reparse points) — lstatSync
            // reports isDirectory()=true for junctions but realpathSync resolves to
            // the junction target. If canonical path differs, skip this entry.
            try {
              const canonical = realpathSync(full);
              if (canonical !== full) continue; // junction or other reparse point
            } catch { continue; } // can't resolve → skip safely
            walk(full, depth + 1);
          } else if (re.test(e)) {
            // F-NEW-4: filter out sensitive file locations before returning
            if (!isSensitiveFile(full)) {
              matches.push(full);
            }
          }
        }
      };
      try {
        walk(dir, 0);
        const suffix = matches.length >= MAX_RESULTS ? `\n(results capped at ${MAX_RESULTS})` : '';
        return {
          result: truncateOutput(matches.join('\n') + suffix) || '(no matches)',
          tier: "green", blocked: false, dryRun: false,
        };
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "green", blocked: false, dryRun: false };
      }
    }

    case "search_file": {
      const filePath = args.path as string;
      const pattern  = args.pattern as string;
      // F-22: input size caps
      const _sfPathSz = checkSize(filePath, 'filePath');
      if (_sfPathSz) return { result: _sfPathSz, tier: "green", blocked: false, dryRun: false };
      const _sfPatSz = checkSize(pattern, 'searchPattern');
      if (_sfPatSz) return { result: _sfPatSz, tier: "green", blocked: false, dryRun: false };
      // F-23: ReDoS guard — reject catastrophic backtracking patterns before compile
      if (isReDoSPattern(pattern)) {
        return { result: `ERROR: Pattern '${pattern}' has a structure (nested quantifiers or wide alternation) that can cause catastrophic backtracking. Simplify the pattern.`, tier: "green", blocked: false, dryRun: false };
      }
      // F-27: reject control characters in path
      if (/[\x00-\x1F\x7F]/.test(filePath)) {
        return { result: formatBlockedError('path-validation', 'File path contains control characters.'), tier: "red", blocked: true, dryRun: false };
      }

      // Sensitive file guard
      if (isSensitiveFile(filePath)) {
        return {
          result: formatBlockedError('sensitive-file', `Search in '${basename(filePath)}' is blocked. This file matches a sensitive file pattern.`),
          tier: "red",
          blocked: true,
          dryRun: false,
        };
      }

      // F-19: native fs search — no shell process, no injection surface.
      let re: RegExp;
      try { re = new RegExp(pattern, 'i'); }
      catch { return { result: `ERROR: Invalid regex pattern: ${pattern}`, tier: "green", blocked: false, dryRun: false }; }

      const searchInFile = (fp: string): string[] => {
        if (isSensitiveFile(fp)) return [];
        try {
          return readFileSync(fp, 'utf8')
            .split('\n')
            .flatMap((line, idx) => re.test(line) ? [`${fp}:${idx + 1}: ${line}`] : []);
        } catch { return []; }
      };

      let hits: string[];
      try {
        const st = statSync(filePath);
        if (st.isDirectory()) {
          hits = readdirSync(filePath).flatMap(e => {
            const fp = join(filePath, e);
            try { return statSync(fp).isDirectory() ? [] : searchInFile(fp); }
            catch { return []; }
          });
        } else {
          hits = searchInFile(filePath);
        }
      } catch (err: unknown) {
        return { result: `ERROR: ${(err as Error).message}`, tier: "green", blocked: false, dryRun: false };
      }
      return { result: truncateOutput(hits.join('\n')) || '(no matches)', tier: "green", blocked: false, dryRun: false };
    }

    // ── GREEN Tier: Approved commands ────────────────────────────────────────────
    case "run_npm_command": {
      const dir = sanitizeDir((args.directory ?? args.working_directory) as string);
      const cmd = args.command as string;
      // F-22: input size cap
      const _npmSz = checkSize(cmd, 'npmSubCommand');
      if (_npmSz) return { result: _npmSz, tier: "green", blocked: false, dryRun: false };
      // F-16: remove run/ci from allowlist — both execute lifecycle scripts from
      // package.json which is attacker-controlled in untrusted repos.
      const allowed = /^(list|ls|outdated|audit|view|why|explain)(\s|$)/i;
      if (!allowed.test(cmd.trim())) {
        return {
          result: `ERROR: npm sub-command '${cmd}' is not in the approved list.\nAllowed: list, outdated, audit, view, why, explain.\nnpm run / npm install execute lifecycle scripts and are not permitted via this tool.`,
          tier: "green", blocked: true, dryRun: false,
        };
      }
      // F-LT-17: block --registry= and related network-override flags that exfil dep graph
      const npmArgParsed = splitArgv(cmd);
      for (const a of npmArgParsed) {
        if (/^--registry(=|$)/i.test(a) || /^--(cafile|proxy|https-proxy)(=|$)/i.test(a)) {
          return {
            result: `ERROR: npm flag '${a}' is not permitted (registry/network override). All npm commands via MCP use the default registry.`,
            tier: "green", blocked: true, dryRun: false,
          };
        }
      }
      // F-19: execFileSync(shell:false) — npm receives argv directly, no shell re-parse.
      const npmArgs = [...npmArgParsed, '--ignore-scripts'];
      const result = runFile('npm', npmArgs, { cwd: dir, timeoutMs: 60_000 });
      return { result, tier: "green", blocked: false, dryRun: false };
    }

    case "run_git_command": {
      const dir = sanitizeDir((args.directory ?? args.working_directory) as string);
      const cmd = args.command as string;
      // F-22: input size cap
      const _gitSz = checkSize(cmd, 'gitSubCommand');
      if (_gitSz) return { result: _gitSz, tier: "green", blocked: false, dryRun: false };
      // F-15: remove fetch from allowlist — it honours transport helpers (ext::,
      // custom sshCommand) which can RCE via repo-local .git/config.
      const allowed = /^(status|log|diff|branch|show|stash list|tag|rev-parse|ls-files)/i;
      if (!allowed.test(cmd.trim())) {
        return { result: `ERROR: git sub-command '${cmd}' is not in the approved read-only list.`, tier: "green", blocked: true, dryRun: false };
      }
      // F-NEW-1 + F-NEW-6: validate argv — block dangerous flags and sensitive show paths
      const splitArgs = splitArgv(cmd);
      const subCmd = (splitArgs[0] ?? '').toLowerCase();
      const argError = validateGitArgv(subCmd, splitArgs.slice(1));
      if (argError) {
        return {
          result: formatBlockedError('sensitive-file', argError),
          tier: "red", blocked: true, dryRun: false,
        };
      }
      // F-LT-1/2/3/12: buildSafeGitEnv() forces GIT_PAGER=cat, strips
      // GIT_EXTERNAL_DIFF, GIT_CONFIG_COUNT/KEY/VALUE, GIT_DIR, GIT_WORK_TREE, etc.
      const safeGitEnv = buildSafeGitEnv(dir);

      // F-LT-4: for 'git show <bare-ref>' pre-flight the commit's touched files.
      // The ref:path form is already blocked in validateGitArgv; this catches the
      // bare <sha> / <tag> form that renders the full commit diff body.
      if (subCmd === 'show') {
        const userArgs = splitArgs.slice(1);
        const ddIdx = userArgs.indexOf('--');
        // Only pre-flight bare refs (no pathspec after --; that's caught by validateGitArgv)
        if (ddIdx < 0) {
          const bareRefs = userArgs.filter(a => !a.startsWith('-') && !a.includes(':'));
          for (const ref of bareRefs) {
            const checkArgs = ['-C', dir, ...GIT_SAFE_CONFIG, '--no-ext-diff',
                               'show', '--name-only', '--no-patch', '--pretty=format:', ref];
            const nameStatus = runFile('git', checkArgs, { env: safeGitEnv, timeoutMs: 10_000 });
            if (nameStatus.startsWith('ERROR:')) continue; // invalid ref — surface in main call
            const touchedFiles = nameStatus.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            for (const file of touchedFiles) {
              if (isSensitiveFile(file)) {
                return {
                  result: formatBlockedError('sensitive-file',
                    `git show '${ref}' touches sensitive file '${file}'. Commit diff blocked to prevent credential exposure via git history.`),
                  tier: "red", blocked: true, dryRun: false,
                };
              }
            }
          }
        }
      }

      // F-LT-28: for 'git diff <ref>' pre-flight touched files — same logic as 'show'.
      // Catches: git diff HEAD~1 HEAD, git diff <sha> -- (no pathspec after --)
      if (subCmd === 'diff') {
        const userArgs = splitArgs.slice(1);
        const ddIdx = userArgs.indexOf('--');
        if (ddIdx < 0) {
          const bareRefs = userArgs.filter(a => !a.startsWith('-') && !a.includes(':'));
          for (const ref of bareRefs) {
            const checkArgs = ['-C', dir, ...GIT_SAFE_CONFIG, '--no-ext-diff',
                               'show', '--name-only', '--no-patch', '--pretty=format:', ref];
            const nameStatus = runFile('git', checkArgs, { env: safeGitEnv, timeoutMs: 10_000 });
            if (nameStatus.startsWith('ERROR:')) continue; // invalid ref — surface in main call
            const touchedFiles = nameStatus.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            for (const file of touchedFiles) {
              if (isSensitiveFile(file)) {
                return {
                  result: formatBlockedError('sensitive-file',
                    `git diff '${ref}' touches sensitive file '${file}'. Diff blocked to prevent credential exposure via git history.`),
                  tier: "red", blocked: true, dryRun: false,
                };
              }
            }
          }
        }
      }

      // F-LT-10: --no-ext-diff blocks repo-seeded diff-driver execution at git level
      // F-19: execFileSync(shell:false) — argv array never touches cmd.exe
      // F-NEW-2: GIT_SAFE_CONFIG prepends neutralizing -c flags
      const gitArgs = ['-C', dir, ...GIT_SAFE_CONFIG, '--no-ext-diff', ...splitArgs];
      const rawOutput = runFile('git', gitArgs, { env: safeGitEnv, timeoutMs: 30_000 });
      // F-LT-18: strip ANSI/terminal escape sequences — prevents git log --pretty=format:%x1b... injection
      const cleanOutput = rawOutput.replace(/\x1b(?:\[[0-9;]*[mGKHFABCDJst]|\][^\x07]*\x07)/g, '');
      // F-25: scrub any accidentally-committed token shapes from git log / diff output
      return { result: truncateOutput(scrubSecrets(cleanOutput)), tier: "green", blocked: false, dryRun: false };
    }

    // ── Escape Hatch (RED → AMBER → GREEN pipeline) ────────────────────────────
    case "run_command": {
      const cmd       = args.command as string;
      const isDryRun  = args.dry_run === false || args.dry_run === "false" ? false : true;
      // F-22: input size cap — bounds regex cost and log flooding
      const _rcSz = checkSize(cmd, 'command');
      if (_rcSz) return { result: _rcSz, tier: "green", blocked: false, dryRun: isDryRun };

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

      // F-1: sensitive path scan — apply SENSITIVE_FILE_PATTERNS to command tokens
      // so `type C:\..\.ssh\id_rsa` is caught regardless of the verb used.
      if (commandContainsSensitivePath(cmd)) {
        return {
          result: formatBlockedError('sensitive-file', 'This command references a sensitive file path. Use read_file only for files you own and that are not credentials or keys.'),
          tier: "red",
          blocked: true,
          dryRun: isDryRun,
        };
      }

      // AMBER check — F-17: server always shows the warning regardless of dry_run value.
      // If dry_run=true: return warning only (command not executed).
      // If dry_run=false: execute AND include warning in the output — warning is never silently bypassed.
      // Without server-side session state we cannot enforce "must see warning before executing",
      // but we can guarantee the warning always appears in the tool response.
      const amberResult = checkAmber(cmd);
      if (amberResult) {
        if (isDryRun) {
          return {
            result: formatAmberWarning(amberResult.risk, cmd),
            tier: "amber",
            blocked: false,
            dryRun: true,
          };
        }
        // dry_run=false — execute but always surface the warning so it is never silently skipped
        // F-25: scrub token shapes from command output
        const amberOutput = truncateOutput(scrubSecrets(runCommand(cmd, COMMAND_TIMEOUT_MS)));
        return {
          result: `⚠️ AMBER command executed (acknowledged risk: ${amberResult.risk})\n\n${amberOutput}`,
          tier: "amber",
          blocked: false,
          dryRun: false,
        };
      }

      // Dry run preview (GREEN-tier command)
      if (isDryRun) {
        return {
          result: `DRY RUN — command not executed.\nWould run: ${cmd}\nCall again with dry_run=false to execute.`,
          tier: "green",
          blocked: false,
          dryRun: true,
        };
      }

      // GREEN execution — F-25: scrub token shapes from command output
      const result = truncateOutput(scrubSecrets(runCommand(cmd, COMMAND_TIMEOUT_MS)));
      return {
        result,
        tier: "green",
        blocked: false,
        dryRun: false,
      };
    }

    default:
      return { result: `ERROR: Unknown tool '${name}'`, tier: "green", blocked: false, dryRun: false };
  }
}

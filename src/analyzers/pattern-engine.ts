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
  { id: 'RS-001', pattern: /\b(?:bash|sh|zsh)\s+-i\s+>&?\s*\/dev\/tcp\//i, category: 'reverse-shell', severity: 'critical', description: 'Bash reverse shell pattern' },
  { id: 'RS-002', pattern: /\bnc\b.*-e\s+(?:\/bin\/(?:ba)?sh|cmd)/i, category: 'reverse-shell', severity: 'critical', description: 'Netcat reverse shell' },
  { id: 'RS-003', pattern: /\bnet\.connect\s*\(.*\bchild_process\b/i, category: 'reverse-shell', severity: 'critical', description: 'Node.js net.connect reverse shell' },
  { id: 'RS-004', pattern: /\bnew\s+WebSocket\b.*\bchild_process\b/is, category: 'reverse-shell', severity: 'critical', description: 'WebSocket reverse shell' },
  { id: 'RS-005', pattern: /\bSocket\b.*\b(?:subprocess|exec|spawn)\b/i, category: 'reverse-shell', severity: 'critical', description: 'Socket-based reverse shell' },
  { id: 'RS-006', pattern: /python\S*\s+-c\s+['"]import\s+socket/i, category: 'reverse-shell', severity: 'critical', description: 'Python reverse shell' },
  { id: 'RS-007', pattern: /\bsocat\b.*\bexec:/i, category: 'reverse-shell', severity: 'critical', description: 'Socat reverse shell' },

  // Curl-pipe execution
  { id: 'CP-001', pattern: /curl\s+[^|]*\|\s*(?:ba)?sh/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-shell execution' },
  { id: 'CP-002', pattern: /wget\s+[^|]*\|\s*(?:ba)?sh/i, category: 'curl-pipe', severity: 'critical', description: 'Wget-pipe-shell execution' },
  { id: 'CP-003', pattern: /curl\s+[^|]*\|\s*python/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-python execution' },

  // Credential harvesting (from B@dskills)
  { id: 'CH-001', pattern: /\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)/i, category: 'credential-harvest', severity: 'critical', description: 'SSH key access' },
  { id: 'CH-002', pattern: /\/\.aws\/credentials/i, category: 'credential-harvest', severity: 'critical', description: 'AWS credentials access' },
  { id: 'CH-003', pattern: /\/\.gnupg\//i, category: 'credential-harvest', severity: 'critical', description: 'GPG key access' },
  { id: 'CH-004', pattern: /\/\.kube\/config/i, category: 'credential-harvest', severity: 'critical', description: 'Kubernetes config access' },
  { id: 'CH-005', pattern: /\/\.docker\/config\.json/i, category: 'credential-harvest', severity: 'critical', description: 'Docker config access' },
  { id: 'CH-006', pattern: /\/\.netrc/i, category: 'credential-harvest', severity: 'warning', description: '.netrc file access' },
  { id: 'CH-007', pattern: /\/\.npmrc/i, category: 'credential-harvest', severity: 'warning', description: '.npmrc file access (may contain auth tokens)' },
  { id: 'CH-008', pattern: /keychain|SecItemCopyMatching|security\s+find-generic-password/i, category: 'credential-harvest', severity: 'critical', description: 'macOS Keychain access' },

  // Exfiltration (from openclaw-security-monitor + B@dskills)
  { id: 'EX-001', pattern: /\.postMessage\s*\(.*\btransfer\b/i, category: 'exfiltration', severity: 'warning', description: 'postMessage with transfer' },
  { id: 'EX-002', pattern: /\bwebhook\b.*\bsend|post\b/i, category: 'exfiltration', severity: 'warning', description: 'Webhook exfiltration pattern' },
  { id: 'EX-003', pattern: /dns.*(?:lookup|resolve).*(?:encode|btoa|Buffer)/i, category: 'exfiltration', severity: 'critical', description: 'DNS exfiltration' },

  // Prompt injection indicators
  { id: 'PI-001', pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — instruction override' },
  { id: 'PI-002', pattern: /you\s+are\s+now\s+(?:a|an|in)\s+/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — role reassignment' },
  { id: 'PI-003', pattern: /system\s*:\s*you\s+(?:must|should|are)/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — fake system prompt' },
  { id: 'PI-004', pattern: /\[SYSTEM\]|\[ADMIN\]|<\|system\|>/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — delimiter escape' },

  // Crypto wallet targeting (from openclaw-security-monitor)
  { id: 'CW-001', pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/, category: 'crypto-wallet', severity: 'warning', description: 'Bitcoin address pattern' },
  { id: 'CW-002', pattern: /\b0x[0-9a-fA-F]{40}\b/, category: 'crypto-wallet', severity: 'warning', description: 'Ethereum address pattern' },
  { id: 'CW-003', pattern: /\bcoinbase\b.*\bapi|key|secret\b/i, category: 'crypto-wallet', severity: 'warning', description: 'Coinbase API access' },

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

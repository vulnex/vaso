/**
 * Line-level sink analysis for Python MCP server source (`python3 server.py`,
 * `uv run server.py`). The Babel analyzers are JavaScript-only, so a Python
 * server used to get no source analysis at all. This covers the two questions
 * MCP-004 and MCP-005 ask:
 *  - exec / fs-access: can the server run commands or code, or read secrets?
 *  - injection: does caller-controlled data reach one of those sinks?
 *
 * Lexical, not a parser: comments and docstrings are skipped, and the
 * injection rules only fire on shapes where the sink's argument is visibly
 * non-literal on the same line.
 */

import { classifySensitivePath } from './sensitive-paths.js';

export interface PythonSinkFinding {
  kind: 'exec' | 'fs-access' | 'injection';
  line: number;
  snippet: string;
  description: string;
}

const EXEC_SINKS: Array<{ re: RegExp; name: (m: RegExpMatchArray) => string }> = [
  { re: /(?<![\w.])(eval|exec)\s*\(/, name: (m) => m[1] },
  { re: /\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/, name: (m) => `subprocess.${m[1]}` },
  { re: /\bos\.(system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(/, name: (m) => `os.${m[1]}` },
  { re: /\basyncio\.create_subprocess_(exec|shell)\s*\(/, name: (m) => `asyncio.create_subprocess_${m[1]}` },
  { re: /\bpty\.spawn\s*\(/, name: () => 'pty.spawn' },
];

const INJECTION_RULES: Array<{ re: RegExp; description: string }> = [
  {
    re: /(?<![\w.])(?:eval|exec)\s*\(\s*(?!["')]|r["']|b["'])/,
    description: 'eval()/exec() of a non-literal expression — caller-controlled code runs in the server',
  },
  {
    re: /(?:\bsys\.executable|["']python[\d.]*["'])\s*,\s*["']-c["']\s*,\s*(?!["'])/,
    description: 'Runs caller-supplied code through `python -c` — arbitrary code execution, no sandbox',
  },
  {
    re: /\bos\.(?:system|popen)\s*\(\s*(?:f["']|[A-Za-z_][\w.]*\s*[,)+%]|["'][^"']*["']\s*(?:\+|%|\.format\b))/,
    description: 'Shell command built from dynamic input (os.system/os.popen) — command injection',
  },
  {
    re: /\bcreate_subprocess_shell\s*\(\s*(?:f["']|[A-Za-z_][\w.]*\s*[,)+%]|["'][^"']*["']\s*(?:\+|%|\.format\b))/,
    description: 'Shell command built from dynamic input (create_subprocess_shell) — command injection',
  },
  {
    re: /\bsubprocess\.\w+\s*\(\s*(?:f["']|[A-Za-z_][\w.]*\s*,|["'][^"']*["']\s*(?:\+|%|\.format\b))[^)]*\bshell\s*=\s*True/,
    description: 'Dynamic command run with shell=True — command injection',
  },
];

/** `os.path.join(base, <name>)` where the joined name reads like caller input. */
const PATH_JOIN_INPUT = /\bos\.path\.join\(\s*[^,()]+,\s*([A-Za-z_][\w.]*)\s*\)/;
const INPUT_PATH_NAME = /(?:path|file|name|dir|rel|target|dest|input|arg|param)/i;
/** Evidence that the file confines joined paths to a base directory. */
const RESOLVES = /\b(?:realpath|abspath|resolve)\s*\(/;
const CONFINES = /\b(?:startswith|commonpath|is_relative_to|relative_to)\s*\(/;
const FILE_OPS = /\bopen\s*\(|\blistdir\s*\(|\bscandir\s*\(|\bmakedirs\s*\(|\bos\.remove\s*\(|\bshutil\.|\.(?:read|write)_(?:text|bytes)\s*\(/;

const STRING_LITERAL = /["']([^"']{2,})["']/g;

/** Code lines with their 1-based numbers; comments and docstring bodies dropped. */
function codeLines(code: string): Array<{ line: number; text: string }> {
  const out: Array<{ line: number; text: string }> = [];
  let inDocstring: string | undefined;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    const trimmed = text.trim();
    if (inDocstring) {
      if (trimmed.includes(inDocstring)) inDocstring = undefined;
      continue;
    }
    const opener = /^[rRbBuUfF]*("""|''')/.exec(trimmed);
    if (opener) {
      // A docstring line; it continues unless it also closes here.
      if (trimmed.indexOf(opener[1], opener[0].length) === -1) inDocstring = opener[1];
      continue;
    }
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    out.push({ line: i + 1, text });
  }
  return out;
}

export function analyzePythonSinks(code: string): PythonSinkFinding[] {
  const findings: PythonSinkFinding[] = [];
  const lines = codeLines(code);
  const confined = RESOLVES.test(code) && CONFINES.test(code);
  const touchesFiles = FILE_OPS.test(code);

  for (const { line, text } of lines) {
    const snippet = text.trim().slice(0, 120);

    for (const { re, name } of EXEC_SINKS) {
      const m = text.match(re);
      if (m) {
        findings.push({ kind: 'exec', line, snippet, description: `${name(m)}() call detected` });
        break;
      }
    }

    if (/\bopen\s*\(|\bPath\s*\(|expanduser\s*\(/.test(text)) {
      for (const m of text.matchAll(STRING_LITERAL)) {
        const labels = classifySensitivePath(m[1]);
        if (labels.length > 0) {
          findings.push({ kind: 'fs-access', line, snippet, description: `reads ${labels[0]}` });
          break;
        }
      }
    }

    for (const { re, description } of INJECTION_RULES) {
      if (re.test(text)) {
        findings.push({ kind: 'injection', line, snippet, description });
        break;
      }
    }

    if (!confined && touchesFiles) {
      const m = PATH_JOIN_INPUT.exec(text);
      const joined = m?.[1].split('.').pop() ?? '';
      if (m && INPUT_PATH_NAME.test(joined)) {
        findings.push({
          kind: 'injection',
          line,
          snippet,
          description: `Path joined from caller input (${joined}) with no containment check — "../" escapes the base directory (path traversal)`,
        });
      }
    }
  }

  return findings;
}

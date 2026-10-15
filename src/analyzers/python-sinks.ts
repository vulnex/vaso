/**
 * Line-level sink analysis for Python MCP server source (`python3 server.py`,
 * `uv run server.py`). The Babel analyzers are JavaScript-only, so a Python
 * server used to get no source analysis at all. This covers the two questions
 * MCP-004 and MCP-005 ask:
 *  - exec / fs-access: can the server run commands or code, or read secrets?
 *  - injection: does caller-controlled data reach one of those sinks?
 *
 * Lexical, not a parser: comments and docstrings are skipped, import aliases
 * are resolved first (`import subprocess as sp`, `from os import system`,
 * `__import__("os")`), and a call spread over several lines is read as one
 * statement. Tool input is followed from the parameters of `@mcp.tool()`
 * functions through assignments in their body, and into local helpers they
 * call — so a fixed command (`subprocess.run(["git", "status"])`) is told
 * apart from one the caller supplies.
 */

import { classifySensitivePath } from './sensitive-paths.js';
import type { DataFlowResult } from './ast-analyzer.js';

export interface PythonSinkFinding {
  kind: 'exec' | 'fs-access' | 'injection';
  line: number;
  snippet: string;
  description: string;
  /** exec: the static text of the command/code argument(s), `{…}` for values. */
  command?: string;
  /** exec: the command/code is computed at runtime. */
  dynamic?: boolean;
  /** exec: the command/code is decoded at runtime (base64, hex, rot13). */
  decoded?: boolean;
  /** exec: tool input reaches the call — how, e.g. `cmd ← query`. */
  toolInput?: string;
}

/** `text` with string-literal contents replaced by spaces (same length, quotes kept). */
function blankStrings(text: string): string {
  return text.replace(/(["'])(?:\\.|(?!\1|\\).)*\1/g, (m) => m[0] + ' '.repeat(m.length - 2) + m[m.length - 1]);
}

const EXEC_SINKS: Array<{ re: RegExp; name: (m: RegExpMatchArray) => string }> = [
  // Not a definition of a function or method named eval/exec (`def eval(self, node)`)
  { re: /(?<![\w.])(?<!\bdef\s+)(eval|exec)\s*\(/, name: (m) => m[1] },
  { re: /\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/, name: (m) => `subprocess.${m[1]}` },
  { re: /\bos\.(system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(/, name: (m) => `os.${m[1]}` },
  { re: /\basyncio\.create_subprocess_(exec|shell)\s*\(/, name: (m) => `asyncio.create_subprocess_${m[1]}` },
  { re: /\bpty\.spawn\s*\(/, name: () => 'pty.spawn' },
  { re: /\bcommands\.getoutput\s*\(/, name: () => 'commands.getoutput' },
];

const INJECTION_RULES: Array<{ re: RegExp; description: string }> = [
  {
    re: /(?<![\w.])(?<!\bdef\s+)(?:eval|exec)\s*\(\s*(?!["')]|r["']|b["'])/,
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
/** Runtime decoding feeding a command: base64/hex/rot13 back into text. */
const DECODES = /\b(?:b64decode|urlsafe_b64decode|b32decode|b16decode|b85decode|a85decode|unhexlify|a2b_base64|fromhex)\s*\(|\bcodecs\.decode\s*\(/;

/** Modules whose functions are sinks, by the name this file binds them to. */
const SINK_MODULES = new Set(['os', 'subprocess', 'asyncio', 'pty', 'commands']);

interface CodeLine {
  line: number;
  text: string;
}

/** Code lines with their 1-based numbers; comments and docstring bodies dropped. */
function codeLines(code: string): CodeLine[] {
  const out: CodeLine[] = [];
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

/**
 * Import aliases rewritten to the canonical dotted names the sink patterns
 * know: `sp.run(` → `subprocess.run(`, `check_output(` (from-imported) →
 * `subprocess.check_output(`, `__import__("os").system(` → `os.system(`.
 */
function aliasRewriter(code: string): (text: string) => string {
  const rewrites: Array<[RegExp, string]> = [];
  for (const m of code.matchAll(/^[ \t]*import[ \t]+([^\n#]+)/gm)) {
    for (const part of m[1].split(',')) {
      const am = /^\s*([\w.]+)\s+as\s+(\w+)\s*$/.exec(part);
      if (am && SINK_MODULES.has(am[1]) && am[2] !== am[1]) {
        rewrites.push([new RegExp(String.raw`(?<![\w.])${am[2]}\.`, 'g'), `${am[1]}.`]);
      }
    }
  }
  for (const m of code.matchAll(/^[ \t]*from[ \t]+(os|subprocess|asyncio|pty)[ \t]+import[ \t]+\(?([^\n#)]+)/gm)) {
    for (const part of m[2].split(',')) {
      const im = /^\s*(\w+)(?:\s+as\s+(\w+))?\s*$/.exec(part);
      if (!im) continue;
      const local = im[2] ?? im[1];
      rewrites.push([new RegExp(String.raw`(?<![\w.])${local}\s*\(`, 'g'), `${m[1]}.${im[1]}(`]);
    }
  }
  return (text: string): string => {
    let out = text.replace(/\b__import__\(\s*["'](\w+)["']\s*\)\s*\./g, '$1.');
    // getattr(os, "sys" + "tem")(cmd): a sink name assembled to dodge a grep.
    out = out.replace(/\bgetattr\(\s*(os|subprocess)\s*,\s*([^)]*)\)\s*\(/g, (m, mod: string, name: string) => {
      const literal = name.replace(/["'\s+]/g, '');
      return /^\w+$/.test(literal) ? `${mod}.${literal}(` : m;
    });
    for (const [re, to] of rewrites) out = out.replace(re, to);
    return out;
  };
}

/** Physical lines merged while a bracket is open, so a multi-line call is one statement. */
function statements(lines: CodeLine[]): Array<CodeLine & { last: number }> {
  const out: Array<CodeLine & { last: number }> = [];
  let current: (CodeLine & { last: number }) | undefined;
  let depth = 0;
  for (const l of lines) {
    if (current && depth > 0) {
      current.text += ' ' + l.text.trim();
      current.last = l.line;
    } else {
      current = { line: l.line, text: l.text, last: l.line };
      out.push(current);
      depth = 0;
    }
    for (const c of l.text.replace(/(["'])(?:\\.|(?!\1|\\).)*\1/g, '')) {
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth = Math.max(0, depth - 1);
    }
  }
  return out;
}

/** Argument text of the call whose `(` is at `open`. */
function callArgs(text: string, open: number): string {
  let depth = 0;
  for (let j = open; j < text.length; j++) {
    const c = text[j];
    if (c === '"' || c === "'") {
      const close = text.indexOf(c, j + 1);
      if (close === -1) break;
      j = close;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return text.slice(open + 1, j);
  }
  return text.slice(open + 1);
}

/** Static text of a call's command argument(s): literals kept, values as `{…}`. */
function commandOf(args: string): { command?: string; dynamic: boolean } {
  const head = args.replace(/\b\w+\s*=[\s\S]*$/, ''); // keyword arguments (shell=, cwd=) aren't the command
  const parts: string[] = [];
  let dynamic = false;
  for (const m of head.matchAll(/(?:[rRbBuU]?(["'])((?:\\.|(?!\1|\\).)*)\1)|(f["'](?:\\.|[^"'])*["'])|([A-Za-z_][\w.]*(?:\([^()]*\))?)/g)) {
    if (m[2] !== undefined) parts.push(m[2]);
    else if (m[3]) { dynamic = true; parts.push(m[3].slice(2, -1)); }
    else if (m[4]) { dynamic = true; parts.push('{…}'); }
  }
  const command = parts.join(' ').trim();
  return { ...(command && command !== '{…}' ? { command } : {}), dynamic };
}

// ── Tool input ──────────────────────────────────────────────────────────

interface PyFunction {
  name: string;
  params: string[];
  start: number; // index into statements
  end: number;
  tool: boolean;
}

const TOOL_DECORATOR = /^\s*@\s*[\w.]*\b(?:tool|call_tool)\b/;

function functionsOf(stmts: Array<CodeLine & { last: number }>): PyFunction[] {
  const fns: PyFunction[] = [];
  for (let i = 0; i < stmts.length; i++) {
    const def = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/.exec(stmts[i].text);
    if (!def) continue;
    const paramText = callArgs(stmts[i].text, def[0].length - 1);
    const indent = def[1].length;
    let end = i + 1;
    while (end < stmts.length && stmts[end].text.search(/\S/) > indent) end++;
    let tool = false;
    for (let d = i - 1; d >= 0 && /^\s*@/.test(stmts[d].text); d--) if (TOOL_DECORATOR.test(stmts[d].text)) tool = true;
    // A bool/int/float parameter can't carry a command or code.
    const params = topLevelParts(paramText)
      .filter((p) => !/:\s*(?:bool|int|float)\b/.test(p) && !/=\s*(?:True|False|-?\d+(?:\.\d+)?)\s*$/.test(p))
      .map((p) => /^\s*\**([A-Za-z_]\w*)/.exec(p)?.[1])
      .filter((p): p is string => !!p && p !== 'self' && p !== 'cls' && p !== 'ctx');
    fns.push({ name: def[2], params, start: i, end, tool });
  }
  return fns;
}

/**
 * Variables (per function) holding an argv list that tool input is only an
 * argument of: `cmd = linter.command + [str(output_dir)]`. Passed to a
 * non-shell call, the input can't choose the program.
 */
const argvNames = new Map<PyFunction, Set<string>>();
const LIST_BUILDING = /^\s*\[|\]\s*\+|\+\s*\[|\bfor\b[\s\S]*\bin\b/;
const SHELL_PROGRAM = /^\s*[rRbBuU]?["'](?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python[\d.]*)["']/;

/** Comma-separated parts at bracket depth 0 (a parameter list with annotations). */
function topLevelParts(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  const clean = text.replace(/(["'])(?:\\.|(?!\1|\\).)*\1/g, (m) => '_'.repeat(m.length));
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { parts.push(text.slice(start, i)); start = i + 1; }
  }
  parts.push(text.slice(start));
  return parts;
}

/** Calls whose result still carries their argument's text. */
const PASSTHROUGH_CALLS = /^(?:str|f|format|join|replace|strip|lstrip|rstrip|lower|upper|split|splitlines|shlex\.split|shlex\.join|os\.path\.join|os\.path\.expanduser|Path|list|tuple|dict|get|pop|encode|decode|append|extend|copy)$/;

/**
 * The parts of an assigned expression whose value flows into the variable:
 * a condition (`a if flag else b`, `not x`) only picks between values, and an
 * arbitrary call (`LanguageConfigLoader.load(language)`) returns its own
 * value — string building and container calls pass their arguments through.
 */
function dataPart(expr: string): string {
  let out = expr.replace(/\bif\b[\s\S]*?\belse\b/g, ' else ').replace(/\bnot\s+[\w.]+/g, '');
  for (let guard = 0; guard < 20; guard++) {
    const m = /([A-Za-z_][\w.]*)\s*\(/.exec(out);
    if (!m) break;
    const open = m.index + m[0].length - 1;
    const args = callArgs(out, open);
    // `value.strip()` keeps its receiver; `Loader.load(name)` keeps neither
    // the class nor (being opaque) the argument.
    const dot = m[1].lastIndexOf('.');
    const method = dot === -1 ? m[1] : m[1].slice(dot + 1);
    const receiver = dot === -1 ? '' : m[1].slice(0, dot);
    const keep = PASSTHROUGH_CALLS.test(m[1]) || PASSTHROUGH_CALLS.test(method);
    out = out.slice(0, m.index) + ` ${receiver} ${keep ? args : ''} ` + out.slice(open + args.length + 2);
  }
  return out;
}

const mentions = (text: string, name: string): boolean => new RegExp(String.raw`(?<![\w.])${name}\b`).test(text);

/**
 * Names in each function that carry tool input: a tool function's
 * parameters, helper parameters passed tainted values at a call site, and
 * variables assigned from them. Two rounds cover tool → helper → helper.
 */
function taintedNames(stmts: Array<CodeLine & { last: number }>, fns: PyFunction[], rewrite: (t: string) => string): Map<PyFunction, Map<string, string>> {
  const tainted = new Map<PyFunction, Map<string, string>>();
  for (const fn of fns) {
    tainted.set(fn, new Map(fn.tool ? fn.params.map((p) => [p, p]) : []));
    argvNames.set(fn, new Set());
  }
  const byName = new Map(fns.map((f) => [f.name, f]));
  for (let round = 0; round < 3; round++) {
    for (const fn of fns) {
      const names = tainted.get(fn)!;
      for (let i = fn.start + 1; i < fn.end; i++) {
        const text = rewrite(stmts[i].text);
        const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
        if (assign && !names.has(assign[1])) {
          const rhs = dataPart(assign[2]);
          const from = [...names.keys()].find((n) => mentions(rhs, n));
          if (from) {
            names.set(assign[1], `${assign[1]} ← ${names.get(from)}`);
            // An argv list with the input as one of its arguments.
            if (LIST_BUILDING.test(assign[2]) || argvNames.get(fn)!.has(from)) argvNames.get(fn)!.add(assign[1]);
          }
        }
        for (const call of text.matchAll(/(?<![\w.])(?:self\.)?(\w+)\s*\(/g)) {
          const callee = byName.get(call[1]);
          if (!callee || callee === fn) continue;
          const args = callArgs(text, call.index + call[0].length - 1).split(',');
          args.forEach((arg, idx) => {
            const from = [...names.keys()].find((n) => mentions(arg, n));
            const param = callee.params[idx];
            const calleeNames = tainted.get(callee)!;
            if (from && param && !calleeNames.has(param)) calleeNames.set(param, `${param} ← ${names.get(from)}`);
          });
        }
      }
    }
  }
  return tainted;
}

export function analyzePythonSinks(code: string): PythonSinkFinding[] {
  const findings: PythonSinkFinding[] = [];
  const rewrite = aliasRewriter(code);
  const lines = codeLines(code);
  const stmts = statements(lines);
  const fns = functionsOf(stmts);
  const tainted = taintedNames(stmts, fns, rewrite);
  const fnAt = (i: number): PyFunction | undefined => fns.filter((f) => i > f.start && i < f.end).at(-1);
  const confined = RESOLVES.test(code) && CONFINES.test(code);
  const touchesFiles = FILE_OPS.test(code);
  const injectedLines = new Set<number>();

  // Physical-line rules: injection shapes visible on one line.
  for (const { line, text: raw } of lines) {
    const text = rewrite(raw);
    const snippet = raw.trim().slice(0, 120);

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
        injectedLines.add(line);
        break;
      }
    }

    if (!confined && touchesFiles) {
      const m = PATH_JOIN_INPUT.exec(text);
      const joined = m?.[1].split('.').pop() ?? '';
      // The name suggests input; whether it is: a parameter (a helper's
      // caller may pass tool input) or a tainted name is; a local built from
      // a hash or a constant table joins nothing the caller chose
      const si = stmts.findIndex((s) => s.line <= line && line <= s.last);
      const fnHere = si >= 0 ? fnAt(si) : undefined;
      const root = m?.[1].split('.')[0] ?? '';
      const fromInput = m && (!fnHere || fnHere.params.includes(root) || root === 'self' || tainted.get(fnHere)?.has(root) === true);
      if (m && INPUT_PATH_NAME.test(joined) && fromInput) {
        findings.push({
          kind: 'injection',
          line,
          snippet,
          description: `Path joined from caller input (${joined}) with no containment check — "../" escapes the base directory (path traversal)`,
        });
      }
    }
  }

  // Statement-level: exec sinks (a call may span lines), with tool-input tracing.
  stmts.forEach((stmt, i) => {
    const text = rewrite(stmt.text);
    for (const { re, name } of EXEC_SINKS) {
      // Matched on code only: `"eval": "eval() has…"` is a string, not a call
      const m = re.exec(blankStrings(text));
      if (!m) continue;
      const sink = name(m);
      const args = callArgs(text, (m.index ?? 0) + m[0].length - 1);
      const { command, dynamic } = commandOf(args);
      const fn = fnAt(i);
      const names = fn ? tainted.get(fn)! : new Map<string, string>();
      // Keyword arguments other than the command (cwd=, env=) don't carry it.
      const commandArgs = args.replace(/\b(?!shell\b)\w+\s*=[^,]*/g, '');
      const shellCall = /\bshell\s*=\s*True\b/.test(args) || /^(?:eval|exec|os\.(?:system|popen)|asyncio\.create_subprocess_shell|subprocess\.(?:getoutput|getstatusoutput)|commands\.getoutput)$/.test(sink);
      // Without a shell, input in an argument position can't pick the
      // program: count the program itself (a bare tainted command, or the
      // first element of a literal argv — any element after a shell/-c).
      const first = topLevelParts(commandArgs)[0]?.trim() ?? '';
      const argv = fn ? argvNames.get(fn)! : new Set<string>();
      const from = [...names.keys()].find((n) => {
        if (!mentions(commandArgs, n)) return false;
        if (shellCall || sink.startsWith('os.exec') || sink.startsWith('os.spawn')) return true;
        if (first.startsWith('[')) {
          const elems = topLevelParts(first.slice(1, -1));
          return mentions(elems[0] ?? '', n) || (SHELL_PROGRAM.test(elems[0] ?? '') && mentions(first, n));
        }
        if (!mentions(first, n)) return false;
        return /^[A-Za-z_][\w.]*$/.test(first) ? !argv.has(first) : !LIST_BUILDING.test(first);
      });
      const finding: PythonSinkFinding = {
        kind: 'exec',
        line: stmt.line,
        snippet: lines.find((l) => l.line === stmt.line)!.text.trim().slice(0, 120),
        description: `${sink}() call detected`,
        ...(command ? { command } : {}),
        ...(dynamic ? { dynamic } : {}),
        ...(DECODES.test(args) ? { decoded: true } : {}),
        ...(from ? { toolInput: names.get(from) } : {}),
      };
      findings.push(finding);

      const covered = [...injectedLines].some((l) => l >= stmt.line && l <= stmt.last);
      if (!covered) {
        const shell = /\bshell\s*=\s*True\b/.test(args) || /^(?:os\.(?:system|popen)|asyncio\.create_subprocess_shell|subprocess\.(?:getoutput|getstatusoutput)|commands\.getoutput)$/.test(sink);
        if (from) {
          findings.push({
            kind: 'injection',
            line: stmt.line,
            snippet: finding.snippet,
            description: `${sink}() runs a command built from tool input (${names.get(from)})${shell ? ' through a shell' : ''} — command injection`,
          });
        } else if (shell && stmt.last > stmt.line && /^\s*(?:f["']|(?![rRbBuU]?["'])[A-Za-z_])/.test(args)) {
          findings.push({ kind: 'injection', line: stmt.line, snippet: finding.snippet, description: 'Dynamic command run with shell=True — command injection' });
        }
      }
      break;
    }
  });

  return findings.sort((a, b) => a.line - b.line);
}

// ── Capabilities for skill code (SKL-001/003) ───────────────────────────

export interface PythonCapability {
  kind: 'exec' | 'eval' | 'network' | 'file-read';
  line: number;
  snippet: string;
  description: string;
  /** exec/eval: what is run is computed at runtime, not a literal. */
  dynamic?: boolean;
}

/** Client/connection constructors among NETWORK_CALLS: they open nothing and send nothing. */
const CLIENT_CONSTRUCTORS = /^(?:Client|AsyncClient|Session|ClientSession|PoolManager|ProxyManager|HTTPConnection|HTTPSConnection|SSHClient|FTP|FTP_TLS|SMTP|SMTP_SSL|socket|create_connection)$/;
const NETWORK_CALLS = /\b(?:requests|httpx|aiohttp|urllib\.request|urllib3|http\.client|socket|ftplib|smtplib|paramiko)\s*\.\s*(\w+)\s*\(|\burlopen\s*\(|\bClientSession\s*\(|\bcreate_connection\s*\(/;
const FILE_READS = /\bopen\s*\([^)]*\)|\.read_(?:text|bytes)\s*\(|\bshutil\.copy\w*\s*\(/;

/**
 * What a Python file can do, for skill audits: run commands or code, talk
 * to the network, read files. Same lexer as the MCP analysis (aliases,
 * multi-line calls, docstrings skipped), without the MCP tool-input model.
 */
export function analyzePythonCapabilities(code: string): PythonCapability[] {
  const out: PythonCapability[] = [];
  const rewrite = aliasRewriter(code);
  const lines = codeLines(code);
  for (const stmt of statements(lines)) {
    const text = rewrite(stmt.text);
    const snippet = lines.find((l) => l.line === stmt.line)!.text.trim().slice(0, 120);
    for (const { re, name } of EXEC_SINKS) {
      // Matched on code only: `"eval": "eval() has…"` is a string, not a call
      const m = re.exec(blankStrings(text));
      if (!m) continue;
      const sink = name(m);
      const { dynamic } = commandOf(callArgs(text, (m.index ?? 0) + m[0].length - 1));
      out.push({ kind: sink === 'eval' || sink === 'exec' ? 'eval' : 'exec', line: stmt.line, snippet, description: `${sink}() call`, ...(dynamic ? { dynamic } : {}) });
      break;
    }
    const net = NETWORK_CALLS.exec(text);
    if (net) out.push({ kind: 'network', line: stmt.line, snippet, description: `network call (${net[0].replace(/\s*\($/, '')})` });
    const read = FILE_READS.exec(text);
    if (read && !/["'][wax]b?\+?["']/.test(read[0])) out.push({ kind: 'file-read', line: stmt.line, snippet, description: `file read (${read[0].slice(0, 40)})` });
  }
  return out;
}

/** What a tracked variable holds. `envall` is the whole environment (`dict(os.environ)`). */
type SourceKind = 'file' | 'env' | 'envall';

/** A call's top-level arguments: positional values, and keyword name → value. */
function splitArgs(args: string): { positional: string[]; keywords: Map<string, string> } {
  const positional: string[] = [];
  const keywords = new Map<string, string>();
  for (const part of topLevelParts(args)) {
    const kw = /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*([\s\S]*)$/.exec(part);
    if (kw) keywords.set(kw[1], kw[2]);
    else if (part.trim()) positional.push(part.trim());
  }
  return { positional, keywords };
}

/**
 * Sources written inline in a call's arguments (`json=dict(os.environ)`,
 * `data=os.environ["KEY"]`, `open(p).read()`): the same kinds an assignment
 * tracks, reported under the expression itself.
 */
function inlineSources(text: string): Array<[string, SourceKind]> {
  const out: Array<[string, SourceKind]> = [];
  const whole = /\b(?:dict\s*\(\s*)?os\.environ\b(?!\s*(?:\[|\.get\b|\.setdefault\b|\.pop\b))\s*\)?/.exec(text);
  if (whole) out.push([whole[0].trim(), 'envall']);
  for (const m of text.matchAll(/\bos\.(?:environ\s*\[[^\]]+\]|environ\.get\s*\([^)]*\)|getenv\s*\([^)]*\))/g)) out.push([m[0], 'env']);
  const read = FILE_READS.exec(text);
  if (read) out.push([read[0], 'file']);
  return out;
}

/** Programs whose arguments leave the machine: an env secret in their argv is sent somewhere. */
const NETWORK_PROGRAM = /^(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|ssh|telnet)$/;

/** The literal program a process call runs, when it is written out. */
function literalProgram(first: string | undefined): string | undefined {
  if (!first) return undefined;
  const head = first.startsWith('[') ? topLevelParts(first.slice(1, first.lastIndexOf(']')))[0] ?? '' : first;
  const lit = /^\s*[rRbBuU]?(["'])([^"']+)\1\s*$/.exec(head);
  return lit ? lit[2].trim().split(/\s+/)[0].split('/').pop() : undefined;
}

/** Process calls that run a program directly, without a shell (unless `shell=True`). */
const DIRECT_EXEC = /^(?:subprocess\.(?:run|call|check_call|check_output|Popen)|asyncio\.create_subprocess_exec)$/;

/**
 * Python skill code in the shape the skill checks read from `analyzeCode`
 * (SKL-001/003/006/010): eval-exec calls, reads of credential paths, and
 * file/environment values flowing into a network or process call.
 *
 * Precision (real skills: Anthropic's xlsx/pptx/skill-creator, Hermes'
 * bundled set): sources are tracked per function, never across them; only
 * argument values count, never keyword names (`text=True`, `data=body`);
 * `env=`/`cwd=` and other process options aren't data the process sends; and
 * a single environment value (a user agent, an API key in the headers of the
 * API it belongs to) is exfiltration only in a request body or in the argv of
 * a network program — file contents and the whole environment, anywhere.
 */
export function analyzePythonDataFlow(code: string): DataFlowResult[] {
  const out: DataFlowResult[] = [];
  const rewrite = aliasRewriter(code);
  const lines = codeLines(code);
  const stmts = statements(lines);
  const fns = functionsOf(stmts);
  const scopes = new Map<PyFunction | undefined, Map<string, SourceKind>>([[undefined, new Map()]]);
  const scopeOf = (fn: PyFunction | undefined): Map<string, SourceKind> => {
    let m = scopes.get(fn);
    if (!m) scopes.set(fn, (m = new Map()));
    return m;
  };
  const report = (kind: SourceKind): 'file' | 'env' => (kind === 'file' ? 'file' : 'env');

  stmts.forEach((stmt, i) => {
    const text = rewrite(stmt.text);
    const snippet = lines.find((l) => l.line === stmt.line)!.text.trim().slice(0, 120);
    // Enclosing functions, outermost first; module-level names are visible too
    const enclosing = fns.filter((f) => i > f.start && i < f.end);
    const visible = new Map<string, SourceKind>(scopes.get(undefined));
    for (const f of enclosing) for (const [v, k] of scopes.get(f) ?? []) visible.set(v, k);
    const local = scopeOf(enclosing.at(-1));

    for (const { re, name } of EXEC_SINKS) {
      // Matched on code only: `"eval": "eval() has…"` is a string, not a call
      const m = re.exec(blankStrings(text));
      if (!m) continue;
      const args = callArgs(text, (m.index ?? 0) + m[0].length - 1);
      const sink = name(m);
      const { command, dynamic } = commandOf(args);
      const { positional, keywords } = splitArgs(args);
      const shell = /^True\b/.test(keywords.get('shell')?.trim() ?? '');
      const program = literalProgram(positional[0]);
      // Run directly, the program can't be a shell or an interpreter given code to run
      const noShell = DIRECT_EXEC.test(sink) && !shell
        && !SHELL_PROGRAM.test(positional[0]?.replace(/^\[\s*/, '') ?? '')
        && !/["']-c["']/.test(positional.join(','));
      out.push({
        type: 'eval-exec', line: stmt.line, snippet, description: `${sink}() call detected`,
        ...(command ? { command } : {}), ...(dynamic ? { dynamic } : {}), ...(DECODES.test(args) ? { decoded: true } : {}),
        ...(noShell ? { noShell } : {}),
      });
      if (sink !== 'eval' && sink !== 'exec') {
        // What the process gets: its argv and stdin, not env=/cwd=/timeout=
        const sent = [...positional, keywords.get('args') ?? '', keywords.get('input') ?? ''].join(',');
        const flows = [...[...visible].filter(([v]) => mentions(sent, v)), ...inlineSources(sent)];
        for (const [v, kind] of flows) {
          if (kind === 'env' && !(program && NETWORK_PROGRAM.test(program))) continue;
          out.push({ type: 'source-to-sink', source: v, sourceKind: report(kind), sink, line: stmt.line, snippet, description: `Data flows from "${v}" into process execution "${sink}"` });
        }
      }
      break;
    }

    if (/\bopen\s*\(|\bPath\s*\(|expanduser\s*\(/.test(text)) {
      for (const m of text.matchAll(STRING_LITERAL)) {
        if (classifySensitivePath(m[1]).length > 0) {
          out.push({ type: 'fs-access', source: m[1], line: stmt.line, snippet, description: `Reading sensitive path: ${m[1]}` });
          break;
        }
      }
    }

    const net = NETWORK_CALLS.exec(text);
    // Building a client or connection (`httpx.Client(base_url=url)`) sends nothing
    const constructs = net !== null && CLIENT_CONSTRUCTORS.test(net[1] ?? (/\w+/.exec(net[0])?.[0] ?? ''));
    if (net && !constructs) {
      const { positional, keywords } = splitArgs(callArgs(text, text.indexOf('(', net.index)));
      const all = [...positional, ...keywords.values()].join(',');
      // A request body, or the payload of a raw socket send
      const rawSend = /^(?:send|sendall|sendto|sendmail|write)$/.test(net[1] ?? '');
      const body = [...(rawSend ? positional : positional.slice(1)), ...['data', 'json', 'files', 'content', 'body', 'msg'].map((k) => keywords.get(k) ?? '')].join(',');
      const inline = [
        ...inlineSources(all).filter(([, kind]) => kind !== 'env'),
        ...inlineSources(body).filter(([, kind]) => kind === 'env'),
      ];
      for (const [v, kind] of [...[...visible].filter(([v, k]) => mentions(k === 'env' ? body : all, v)), ...inline]) {
        out.push({ type: 'source-to-sink', source: v, sourceKind: report(kind), sink: net[1] ?? 'urlopen', line: stmt.line, snippet, description: `Data flows from "${v}" to network sink "${net[0].replace(/\s*\($/, '')}"` });
      }
    }

    // Track what assignments hold: file contents, environment values, or
    // values derived from either; a plain reassignment clears the name.
    const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
    if (assign) {
      const [, target, rhs] = assign;
      const values = rhs.replace(/\b[A-Za-z_]\w*\s*=(?!=)/g, ' ');
      if (FILE_READS.test(rhs)) local.set(target, 'file');
      else if (/\bos\.environ\b(?!\s*(?:\[|\.get\b|\.setdefault\b|\.pop\b))/.test(rhs)) local.set(target, 'envall');
      else if (/\bos\.(?:environ|getenv)\b/.test(rhs)) local.set(target, 'env');
      else {
        const from = [...visible].find(([v]) => mentions(values, v));
        if (from) local.set(target, from[1]);
        else local.delete(target);
      }
    }
    // `with open(p) as f:` binds a file handle
    const withOpen = /\bwith\s+open\s*\([^)]*\)\s+as\s+(\w+)/.exec(text);
    if (withOpen) local.set(withOpen[1], 'file');
  });
  return out;
}

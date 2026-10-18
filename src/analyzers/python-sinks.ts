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

/**
 * Each string literal in `text` replaced by `fill(literal)`: one pass, quotes
 * matched with backslash escapes, a literal never crossing a line. An
 * unterminated one runs to the end of its line (one broken token, as Python
 * reads it). A regex for this retried from every quote of an unterminated
 * `"\\"\\"…` run — quadratic, minutes on a 100 KB line.
 */
export function mapStringLiterals(text: string, fill: (literal: string) => string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c !== '"' && c !== "'") {
      const next = nextQuote(text, i);
      out += text.slice(i, next);
      i = next;
      continue;
    }
    let j = i + 1;
    while (j < text.length && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
    const end = j < text.length && text[j] === c ? j + 1 : Math.min(j, text.length);
    out += fill(text.slice(i, end));
    i = end;
  }
  return out;
}

function nextQuote(text: string, from: number): number {
  const d = text.indexOf('"', from);
  const s = text.indexOf("'", from);
  const n = d < 0 ? s : s < 0 ? d : Math.min(d, s);
  return n < 0 ? text.length : n;
}

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
export function blankStrings(text: string): string {
  return mapStringLiterals(text, (m) => m.length < 2 ? m : m[0] + ' '.repeat(m.length - 2) + m[m.length - 1]);
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

const INJECTION_RULES: Array<{ re: RegExp; description: string; dashC?: boolean }> = [
  {
    re: /(?<![\w.])(?<!\bdef\s+)(?:eval|exec)\s*\(\s*(?!["')]|r["']|b["'])/,
    description: 'eval()/exec() of a non-literal expression — caller-controlled code runs in the server',
  },
  {
    re: /(?:\bsys\.executable|["']python[\d.]*["'])\s*,\s*["']-c["']\s*,\s*(?!["'])/,
    description: 'Runs caller-supplied code through `python -c` — arbitrary code execution, no sandbox',
    dashC: true,
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

export interface CodeLine {
  line: number;
  text: string;
}

/**
 * Triple-quoted strings, per line: `doc` for the lines of a docstring (a
 * string statement on its own, `"""Doc…`), `data` for the body of one that is
 * assigned or passed (`X = """`, `dedent("""`) — its opening and closing
 * lines excluded, they hold code. A data string's closing `"""` is not read
 * as a docstring opener (that dropped the code after it).
 */
export function pythonStringLines(lines: string[]): Array<'doc' | 'data' | undefined> {
  const out: Array<'doc' | 'data' | undefined> = [];
  let inDoc: string | undefined; // closing delimiter
  let inData: string | undefined;
  for (const text of lines) {
    const trimmed = text.trim();
    if (inDoc) {
      out.push('doc');
      if (trimmed.includes(inDoc)) inDoc = undefined;
      continue;
    }
    if (inData) {
      if (trimmed.includes(inData)) { inData = undefined; out.push(undefined); } else out.push('data');
      continue;
    }
    const opener = /^[rRbBuUfF]*("""|''')/.exec(trimmed);
    if (opener) {
      // it continues unless it also closes here
      if (trimmed.indexOf(opener[1], opener[0].length) === -1) inDoc = opener[1];
      out.push('doc');
      continue;
    }
    for (const delim of ['"""', "'''"]) {
      if (trimmed.split(delim).length % 2 === 0) { inData = delim; break; }
    }
    out.push(undefined);
  }
  return out;
}

/** Code lines with their 1-based numbers; comments, docstrings and multi-line string bodies dropped. */
export function codeLines(code: string): CodeLine[] {
  const out: CodeLine[] = [];
  const lines = code.split('\n');
  const strings = pythonStringLines(lines);
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    const trimmed = text.trim();
    if (strings[i] !== undefined) continue;
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    out.push({ line: i + 1, text });
  }
  return out;
}

/**
 * Names bound only to string literals (`_CHILD_SCRIPT = "import sys; …"`,
 * `SCRIPT = textwrap.dedent("""…""")`) and never a parameter: what they hold
 * is fixed text, whatever runs it.
 */
function stringConstantNames(lines: CodeLine[], fns: PyFunction[]): Set<string> {
  const literal = new Set<string>();
  const other = new Set<string>(fns.flatMap((f) => f.params));
  for (const { text } of lines) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(.*)$/.exec(text);
    if (m) (FIXED_TEXT.test(m[2]) ? literal : other).add(m[1]);
    for (const b of text.matchAll(/\b(?:for|as)\s+([A-Za-z_]\w*)/g)) other.add(b[1]);
  }
  return new Set([...literal].filter((n) => !other.has(n)));
}

/** A string literal (not an f-string), possibly dedented. */
const FIXED_TEXT = /^(?:textwrap\.)?(?:dedent\s*\(\s*)?[rRbBuU]{0,2}(?:"|')/;

/** `-c` and combined short flags ending in it (`-lc`, `-ec`): the next argument is code. */
const DASH_C = /^[rRbBuU]?(["'])-[A-Za-z]*c\1$/;

/** The code argument after `-c` in an argv, or undefined when there is none. */
function codeAfterDashC(argv: string[]): string | undefined {
  const c = argv.findIndex((e) => DASH_C.test(e.trim()));
  return c > 0 ? (argv[c + 1] ?? '').trim() : undefined;
}

function isFixedCode(expr: string, constants: Set<string>): boolean {
  return FIXED_TEXT.test(expr) || constants.has(expr);
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
    // The name stops at `(` too (a name holding one is never rewritten), and
    // its leading space is the name's: `,\s*[^)]*` split a long space run
    // every way, and each `getattr(` scanned the rest of the text (quadratic)
    out = out.replace(/\bgetattr\(\s*(os|subprocess)\s*,([^()]*)\)\s*\(/g, (m, mod: string, name: string) => {
      const literal = name.replace(/["'\s+]/g, '');
      return /^\w+$/.test(literal) ? `${mod}.${literal}(` : m;
    });
    for (const [re, to] of rewrites) out = out.replace(re, to);
    return out;
  };
}

/** Physical lines merged while a bracket is open, so a multi-line call is one statement. */
export function statements(lines: CodeLine[]): Array<CodeLine & { last: number }> {
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
    for (const c of mapStringLiterals(l.text, () => '')) {
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth = Math.max(0, depth - 1);
    }
  }
  return out;
}

/** Argument text of the call whose `(` is at `open`. */
export function callArgs(text: string, open: number): string {
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
  // keyword arguments (shell=, cwd=) aren't the command; the text is for
  // messages, so a bounded head keeps the literal tokenizer below linear
  const head = args.slice(0, 2000).replace(/\b\w+\s*=[\s\S]*$/, '');
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
export function topLevelParts(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  const clean = mapStringLiterals(text, (m) => '_'.repeat(m.length));
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
  const constants = stringConstantNames(lines, fns);
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

    for (const { re, description, dashC } of INJECTION_RULES) {
      if (re.test(text)) {
        // `python -c` running a constant script: the code is fixed, what
        // follows it is the script's argv (`[sys.executable, "-c", SCRIPT, path]`)
        const code = dashC ? /["']-c["']\s*,\s*([^,)\]]+)/.exec(text)?.[1]?.trim() : undefined;
        if (code !== undefined && isFixedCode(code, constants)) continue;
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
      // The argv when it is written out: a list, or create_subprocess_exec's
      // positional arguments
      const argvParts = first.startsWith('[') ? topLevelParts(first.slice(1, -1))
        : sink === 'asyncio.create_subprocess_exec' ? topLevelParts(commandArgs) : undefined;
      // A shell or interpreter given `-c CODE`: the code is what runs; what
      // follows it is the code's argv (`$1`, `sys.argv[1]`), not code
      const dashCode = argvParts && (SHELL_PROGRAM.test(argvParts[0] ?? '') || /^\s*sys\.executable\s*$/.test(argvParts[0] ?? ''))
        ? codeAfterDashC(argvParts) : undefined;
      const from = [...names.keys()].find((n) => {
        if (!mentions(commandArgs, n)) return false;
        if (dashCode !== undefined) return mentions(argvParts![0], n) || mentions(dashCode, n);
        if (shellCall || sink.startsWith('os.exec') || sink.startsWith('os.spawn')) return true;
        if (first.startsWith('[')) {
          const elems = argvParts!;
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
export function splitArgs(args: string): { positional: string[]; keywords: Map<string, string> } {
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
  const constants = stringConstantNames(lines, fns);
  const scopes = new Map<PyFunction | undefined, Map<string, SourceKind>>([[undefined, new Map()]]);
  const scopeOf = (fn: PyFunction | undefined): Map<string, SourceKind> => {
    let m = scopes.get(fn);
    if (!m) scopes.set(fn, (m = new Map()));
    return m;
  };
  const report = (kind: SourceKind): 'file' | 'env' => (kind === 'file' ? 'file' : 'env');
  // Everything per statement is proportional to that statement: scanning all
  // lines, all functions or every tracked name each time made a file of
  // 40 000 statements take minutes.
  const lineText = new Map(lines.map((l) => [l.line, l.text]));
  const enclosing: PyFunction[] = []; // functions around the statement, outermost first
  let nextFn = 0;

  stmts.forEach((stmt, i) => {
    const text = rewrite(stmt.text);
    const snippet = (lineText.get(stmt.line) ?? '').trim().slice(0, 120);
    // Functions nest: leave the ones that ended, enter the ones whose `def` precedes
    while (enclosing.length > 0 && i >= enclosing[enclosing.length - 1].end) enclosing.pop();
    while (nextFn < fns.length && fns[nextFn].start < i) {
      const f = fns[nextFn++];
      if (i < f.end) enclosing.push(f);
    }
    // Tracked names this statement mentions — module level, then enclosing
    // functions, the innermost binding winning
    const visible = new Map<string, SourceKind>();
    for (const id of new Set(text.match(/[A-Za-z_]\w*/g) ?? [])) {
      let kind = scopes.get(undefined)?.get(id);
      for (const f of enclosing) kind = scopes.get(f)?.get(id) ?? kind;
      if (kind !== undefined) visible.set(id, kind);
    }
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
      // An interpreter or shell run directly with literal `-c` code
      // (`[python, "-c", "import sys; print(sys.version)"]`): fixed code,
      // only the interpreter's path is chosen at runtime
      const list = positional[0]?.trim() ?? '';
      const argv = list.startsWith('[') ? topLevelParts(list.slice(1, list.lastIndexOf(']')))
        : sink === 'asyncio.create_subprocess_exec' ? positional : [];
      const dashCode = DIRECT_EXEC.test(sink) && !shell ? codeAfterDashC(argv) : undefined;
      const fixedCode = dashCode !== undefined && isFixedCode(dashCode, constants);
      out.push({
        type: 'eval-exec', line: stmt.line, snippet, description: `${sink}() call detected`,
        ...(command ? { command } : {}), ...(dynamic ? { dynamic } : {}), ...(DECODES.test(args) ? { decoded: true } : {}),
        ...(noShell ? { noShell } : {}), ...(fixedCode ? { fixedCode } : {}),
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

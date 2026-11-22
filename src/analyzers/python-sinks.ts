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

import { cutLine } from './finding-snippet.js';
import { classifySensitivePath } from './sensitive-paths.js';
import type { DataFlowResult } from './ast-analyzer.js';
import { credentialEnvName, onVendorHost, ownedCredential, signingSecret, staticOrigin, vendorApiDomains, vendorUrlSlot } from './vendor-domains.js';

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
  /** `file-path`: a file read, written or listed at a path tool input names (see `fileOp`). */
  kind: 'exec' | 'fs-access' | 'injection' | 'file-path';
  line: number;
  snippet: string;
  /** The whole line when `snippet` is a cut of it. */
  sourceLine?: string;
  description: string;
  /** exec: the static text of the command/code argument(s), `{…}` for values. */
  command?: string;
  /** exec: the command/code is computed at runtime. */
  dynamic?: boolean;
  /** exec: the command/code is decoded at runtime (base64, hex, rot13). */
  decoded?: boolean;
  /** exec, file-path: tool input reaches the call — how, e.g. `cmd ← query`. */
  toolInput?: string;
  /** file-path: what the call does with the path (listing/stat-only paths are `meta`). */
  fileOp?: 'read' | 'write' | 'meta';
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
/** pathlib joins: `Path(base) / <name>`, `ROOT / <name>` (ROOT a Path), and `Path(base, <name>)`. */
const PATHLIB_DIV = /(?:(?<![\w.])(?:pathlib\.)?(?:Pure)?Path\([^()]*\)|(?<![\w.])([A-Za-z_][\w.]*))\s*\/\s*([A-Za-z_][\w.]*)(?![\w.]*\s*\()/g;
/** `ROOT.joinpath(<name>)`, `Path(base).joinpath("a", <name>)`: the last argument is the caller's part. */
const PATHLIB_JOINPATH = /(?:(?<![\w.])(?:pathlib\.)?(?:Pure)?Path\([^()]*\)|(?<![\w.])([A-Za-z_][\w.]*))\.joinpath\(([^()]*)\)/g;
const PATHLIB_CTOR =/(?<![\w.])(?:pathlib\.)?(?:Pure)?Path\(\s*[^,()]+,\s*([A-Za-z_][\w.]*)\s*\)/;
/** Names bound to a Path: `ROOT = Path("/srv")`, `self.base = pathlib.Path.home() / "x"`. */
const PATH_BINDING = /(?<![\w.])((?:self\.)?[A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(?:pathlib\.)?(?:Pure)?Path\b/g;

/** The caller-named part a pathlib join adds to a base directory, if any. */
function pathlibJoin(text: string, pathNames: Set<string>): string | undefined {
  const code = blankStrings(text);
  for (const m of code.matchAll(PATHLIB_DIV)) {
    if (m[1] === undefined || pathNames.has(m[1])) return m[2];
  }
  for (const m of code.matchAll(PATHLIB_JOINPATH)) {
    if (m[1] !== undefined && !pathNames.has(m[1])) continue;
    const last = /([A-Za-z_][\w.]*)\s*$/.exec(m[2].split(',').pop() ?? '')?.[1];
    if (last) return last;
  }
  return PATHLIB_CTOR.exec(code)?.[1];
}
/** Evidence that the file confines joined paths to a base directory. */
const RESOLVES = /\b(?:realpath|abspath|resolve)\s*\(/;
const CONFINES = /\b(?:startswith|commonpath|is_relative_to|relative_to)\s*\(/;
const FILE_OPS = /\bopen\s*\(|\blistdir\s*\(|\bscandir\s*\(|\bmakedirs\s*\(|\bos\.remove\s*\(|\bshutil\.|\.(?:read|write)_(?:text|bytes)\s*\(/;

const STRING_LITERAL = /["']([^"']{2,})["']/g;
/** Runtime decoding feeding a command: base64/hex/rot13 back into text. */
const DECODES = /\b(?:b64decode|urlsafe_b64decode|b32decode|b16decode|b85decode|a85decode|unhexlify|a2b_base64|fromhex)\s*\(|\bcodecs\.decode\s*\(/;

/** Modules whose functions are sinks, by the name this file binds them to. */
const SINK_MODULES = new Set(['os', 'subprocess', 'asyncio', 'pty', 'commands', 'shutil']);

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
    // A joined package's next file (`// === pkg/x.py ===`) starts outside any string
    if (FILE_MARKER.test(trimmed)) { inDoc = inData = undefined; out.push(undefined); continue; }
    if (inDoc) {
      out.push('doc');
      if (trimmed.includes(inDoc)) inDoc = undefined;
      continue;
    }
    if (inData) {
      // `""" + x + """` closes the string and opens the next one: a code
      // line, still inside data after it
      const delimiters = trimmed.split(inData).length - 1;
      if (delimiters === 0) out.push('data');
      else { out.push(undefined); if (delimiters % 2 === 1) inData = undefined; }
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
    out.push({ line: i + 1, text: stripComment(text) });
  }
  return out;
}

/**
 * `text` without a trailing `# comment` (a `#` inside a string literal is
 * text). A line that opens or closes a triple-quoted string is kept whole:
 * part of it is string body this line can't tell from code.
 */
export function stripComment(text: string): string {
  if (!text.includes('#')) return text;
  let from = 0;
  const triples = [...text.matchAll(/"""|'''/g)];
  if (triples.length > 0) {
    if (triples.length % 2 === 1) return text;
    const last = triples[triples.length - 1];
    from = (last.index ?? 0) + 3;
  }
  const at = blankStrings(text.slice(from)).indexOf('#');
  return at < 0 ? text : text.slice(0, from + at).trimEnd();
}

/**
 * Names bound only to fixed values and never a parameter: string literals
 * (`_CHILD_SCRIPT = "import sys; …"`, `SCRIPT = textwrap.dedent("""…""")`),
 * a parenthesised run of them over several lines (`S = (\n "a\n"\n f"b{_N}"\n)`),
 * and numbers. An f-string is fixed when every name it interpolates is
 * (to a fixpoint, so `f"exit({_EXIT})"` with `_EXIT = 3` is). Whatever runs
 * such a value runs fixed text.
 */
function stringConstantNames(stmts: CodeLine[], fns: PyFunction[]): Set<string> {
  const bound = new Map<string, string[]>();
  const other = new Set<string>(fns.flatMap((f) => f.params));
  for (const { text } of stmts) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]*)$/.exec(text);
    if (m) {
      const values = bound.get(m[1]);
      if (values) values.push(m[2]); else bound.set(m[1], [m[2]]);
    }
    for (const b of text.matchAll(/\b(?:for|as)\s+([A-Za-z_]\w*)/g)) other.add(b[1]);
  }
  const constants = new Set<string>();
  // Each round can only add names: an f-string's names may be bound later in the file
  for (let changed = true, guard = 0; changed && guard < 10; guard++) {
    changed = false;
    for (const [name, values] of bound) {
      if (constants.has(name) || other.has(name)) continue;
      if (values.every((v) => fixedValue(v, constants))) { constants.add(name); changed = true; }
    }
  }
  return constants;
}

/** A string literal (not an f-string), possibly dedented. */
const FIXED_TEXT = /^(?:textwrap\.)?(?:dedent\s*\(\s*)?[rRbBuU]{0,2}(?:"|')/;

/**
 * `expr` is fixed text or a number: literals (implicitly or `+`-concatenated,
 * optionally parenthesised or dedented) and f-strings interpolating only
 * `constants`. A triple-quoted body is dropped from the statement text by
 * `codeLines`, so an unclosed plain one counts as fixed (as FIXED_TEXT read it).
 */
function fixedValue(expr: string, constants: Set<string>): boolean {
  let e = expr.trim().replace(/^(?:textwrap\.)?dedent\s*\(/, '(');
  if (/^-?\d[\d_]*(?:\.\d+)?$/.test(e) || /^(?:True|False|None)$/.test(e)) return true;
  let sawLiteral = false;
  let i = 0;
  while (i < e.length) {
    const c = e[i];
    if (/[\s()+]/.test(c)) { i++; continue; }
    const prefix = /^[rRbBuUfF]{0,2}(?="|')/.exec(e.slice(i, i + 3));
    if (!prefix) return false;
    const fString = /[fF]/.test(prefix[0]);
    let j = i + prefix[0].length;
    const triple = e.startsWith(e[j].repeat(3), j);
    const delim = triple ? e[j].repeat(3) : e[j];
    j += delim.length;
    const start = j;
    while (j < e.length && !e.startsWith(delim, j)) j += e[j] === '\\' ? 2 : 1;
    if (j >= e.length) return triple && !fString;
    if (fString) {
      // `{{` is a literal brace; `{name!r:>10}` interpolates `name`
      const body = e.slice(start, j).replace(/\{\{|\}\}/g, '');
      for (const field of body.matchAll(/\{([^{}]*)\}/g)) {
        const ids = field[1].replace(/![rsa]\s*$|![rsa]?:[^{}]*$|:[^{}]*$/, '').match(/[A-Za-z_]\w*/g) ?? [];
        if (ids.some((id) => !constants.has(id))) return false;
      }
    }
    sawLiteral = true;
    i = j + delim.length;
  }
  return sawLiteral;
}
/** `-c` and combined short flags ending in it (`-lc`, `-ec`): the next argument is code. */
const DASH_C = /^[rRbBuU]?(["'])-[A-Za-z]*c\1$/;

/** The code argument after `-c` in an argv, or undefined when there is none. */
function codeAfterDashC(argv: string[]): string | undefined {
  const c = argv.findIndex((e) => DASH_C.test(e.trim()));
  return c > 0 ? (argv[c + 1] ?? '').trim() : undefined;
}

function isFixedCode(expr: string, constants: Set<string>): boolean {
  return FIXED_TEXT.test(expr) || constants.has(expr) || fixedValue(expr, constants);
}

interface ContinuationState {
  /** The open triple-quoted string's delimiter. */
  triple?: string;
  /** Open brackets. */
  depth: number;
  /** The line ended in a `\` outside a string. */
  backslash: boolean;
}

/** `state` after one physical line: strings, brackets and a trailing `\` followed. */
function scanContinuation(t: string, state: ContinuationState): void {
  let i = 0;
  const last = t.trimEnd().length - 1;
  state.backslash = false;
  while (i < t.length) {
    if (state.triple) {
      const close = t.indexOf(state.triple, i);
      if (close < 0) return;
      i = close + 3;
      state.triple = undefined;
      continue;
    }
    const c = t[i];
    if (c === '#') return;
    if (c === '"' || c === "'") {
      if (t.startsWith(c.repeat(3), i)) { state.triple = c.repeat(3); i += 3; continue; }
      let j = i + 1;
      while (j < t.length && t[j] !== c) j += t[j] === '\\' ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') state.depth++;
    else if (c === ')' || c === ']' || c === '}') state.depth = Math.max(0, state.depth - 1);
    else if (c === '\\' && i === last) { state.backslash = true; return; }
    i++;
  }
}

interface DefinitionScopes {
  /** Whether the line at an offset is inside a `def` or `class` body. */
  inside(offset: number): boolean;
  /** The 1-based first and last line of the innermost `def`/`class` around the line at an offset. */
  enclosing(offset: number): [number, number] | undefined;
  /** The same for a 1-based line number. */
  enclosingLine(line: number): [number, number] | undefined;
  /** Whether the body starting at a 1-based line is a `class` body. */
  isClass(first: number): boolean;
}

/**
 * The `def`/`class` bodies of a file: some less-indented line above a line
 * opens one. A `try:`/`if` block at module level is still module level. One
 * pass over the lines, on first use.
 */
function definitionScopes(code: string): DefinitionScopes {
  let starts: number[] | undefined;
  // per line: index into `ranges` of the innermost def/class around it, or -1
  let innermost: Int32Array | undefined;
  const ranges: Array<[number, number]> = [];
  const classes = new Set<number>();
  const build = (): void => {
    starts = [];
    const around: number[] = [];
    // open blocks as [indent, index into ranges when opened by def/class, else -1]
    const stack: Array<[number, number]> = [];
    const innermostOpen = (): number => {
      for (let k = stack.length - 1; k >= 0; k--) if (stack[k][1] >= 0) return stack[k][1];
      return -1;
    };
    let lastCode = 0;
    let start = 0;
    // A line inside a triple-quoted string, an open bracket or after a `\`
    // continues the statement above: its indentation closes nothing
    const open: ContinuationState = { depth: 0, backslash: false };
    while (start <= code.length) {
      const nl = code.indexOf('\n', start);
      const end = nl < 0 ? code.length : nl;
      const line = code.slice(start, end);
      const lead = /^[ \t]*/.exec(line)![0].length;
      const index = starts.length;
      starts.push(start);
      if (FILE_MARKER.test(line.trim())) { open.triple = undefined; open.depth = 0; open.backslash = false; }
      const continued = open.triple !== undefined || open.depth > 0 || open.backslash;
      scanContinuation(line, open);
      if (continued) {
        around.push(innermostOpen());
        if (line.trim() !== '') lastCode = index;
      } else if (/^\s*(?:#|$)/.test(line)) {
        around.push(innermostOpen());
      } else {
        while (stack.length > 0 && stack[stack.length - 1][0] >= lead) {
          const [, r] = stack.pop()!;
          if (r >= 0) ranges[r][1] = lastCode + 1;
        }
        around.push(innermostOpen());
        let r = -1;
        if (/^[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]/.test(line)) {
          r = ranges.length;
          ranges.push([index + 1, index + 1]);
          if (/^[ \t]*class[ \t]/.test(line)) classes.add(index + 1);
        }
        stack.push([lead, r]);
        lastCode = index;
      }
      if (nl < 0) break;
      start = nl + 1;
    }
    for (const [, r] of stack) if (r >= 0) ranges[r][1] = lastCode + 1;
    innermost = Int32Array.from(around);
  };
  const lineAt = (offset: number): number => {
    if (!starts) build();
    let lo = 0;
    let hi = starts!.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts![mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  return {
    inside: (offset) => {
      const line = lineAt(offset);
      return innermost![line] >= 0;
    },
    enclosing: (offset) => {
      const line = lineAt(offset);
      const r = innermost![line];
      return r >= 0 ? ranges[r] : undefined;
    },
    enclosingLine: (line) => {
      if (!starts) build();
      const r = line >= 1 && line <= innermost!.length ? innermost![line - 1] : -1;
      return r >= 0 ? ranges[r] : undefined;
    },
    isClass: (first) => {
      if (!starts) build();
      return classes.has(first);
    },
  };
}

/**
 * Import aliases rewritten to the canonical dotted names the sink patterns
 * know: `sp.run(` → `subprocess.run(`, `check_output(` (from-imported) →
 * `subprocess.check_output(`, `__import__("os").system(` → `os.system(`.
 */
function aliasRewriter(code: string): (text: string, line?: number) => string {
  // One map per rewrite shape, applied in a single pass per text (a regex
  // per alias over every line was O(aliases × lines)); the first binding of
  // a name wins, as when each rewrite ran in turn.
  const moduleAliases = new Map<string, string>(); // `sp.` → `subprocess.`
  const callAliases = new Map<string, { target: string; extra?: string }>(); // `run(` → `subprocess.run(`
  const shellKwargs = new Set<string>(); // `**OPTS` → `shell=True, **OPTS`
  const addModule = (name: string, to: string): void => { if (!moduleAliases.has(name)) moduleAliases.set(name, to); };
  const addCall = (name: string, target: string, extra?: string): void => {
    if (!callAliases.has(name)) callAliases.set(name, extra ? { target, extra } : { target });
  };
  for (const m of code.matchAll(/^[ \t]*import[ \t]+([^\n#]+)/gm)) {
    for (const part of m[1].split(',')) {
      const am = /^\s*([\w.]+)\s+as\s+(\w+)\s*$/.exec(part);
      if (am && SINK_MODULES.has(am[1]) && am[2] !== am[1]) addModule(am[2], `${am[1]}.`);
    }
  }
  // From-imports and module-level `def`/`class` in file order: the last
  // binding of a name is what it calls (`from subprocess import run` then
  // `def run(…)` is the local function; a later re-import is the sink again)
  const bindings: Array<{ at: number; name: string; target?: string }> = [];
  // An import inside a def/class binds the name there only: inside that body
  // it is the sink whatever the module binds; elsewhere it is a call alias
  // only when nothing at module level binds the name
  const localImports: Array<{ name: string; target: string }> = [];
  // name → the bodies importing it, as [first line, last line, target]
  const scopedCalls = new Map<string, Array<[number, number, string]>>();
  const scopes = definitionScopes(code);
  for (const m of code.matchAll(/^[ \t]*from[ \t]+(os|subprocess|asyncio|pty|shutil)[ \t]+import[ \t]+\(?([^\n#)]+)/gm)) {
    const body = /^[ \t]/.test(m[0]) ? scopes.enclosing(m.index ?? 0) : undefined;
    for (const part of m[2].split(',')) {
      const im = /^\s*(\w+)(?:\s+as\s+(\w+))?\s*$/.exec(part);
      if (!im) continue;
      const binding = { at: m.index ?? 0, name: im[2] ?? im[1], target: `${m[1]}.${im[1]}` };
      if (body) {
        localImports.push(binding);
        const list = scopedCalls.get(binding.name) ?? [];
        if (list.length === 0) scopedCalls.set(binding.name, list);
        list.push([body[0], body[1], binding.target]);
      } else {
        bindings.push(binding);
      }
    }
  }
  // The call alias of a name on a line: the innermost body importing it there, else the file-wide one.
  // Bodies nest, so with each body's parent (the nearest earlier one containing it) the innermost one
  // around a line is the last body starting at or before it, or the first of its parents reaching it
  const parents = new Map<string, Int32Array>();
  for (const [name, list] of scopedCalls) {
    list.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    const parent = new Int32Array(list.length);
    const stack: number[] = [];
    list.forEach((r, k) => {
      while (stack.length > 0 && list[stack[stack.length - 1]][1] < r[0]) stack.pop();
      parent[k] = stack.length > 0 ? stack[stack.length - 1] : -1;
      stack.push(k);
    });
    parents.set(name, parent);
  }
  const callAt = (name: string, line: number | undefined): { target: string; extra?: string } | undefined => {
    const scoped = line === undefined ? undefined : scopedCalls.get(name);
    if (scoped) {
      const parent = parents.get(name)!;
      let lo = 0;
      let hi = scoped.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (scoped[mid][0] <= line!) lo = mid;
        else hi = mid - 1;
      }
      for (let k = scoped[lo][0] <= line! ? lo : -1; k >= 0; k = parent[k]) {
        if (line! > scoped[k][1]) continue;
        // a class body's names aren't seen inside its methods or nested classes
        if (scopes.isClass(scoped[k][0]) && scopes.enclosingLine(line!)?.[0] !== scoped[k][0]) continue;
        return { target: scoped[k][2] };
      }
    }
    return callAliases.get(name);
  };
  if (bindings.length > 0 || localImports.length > 0) {
    const imported = new Set([...bindings, ...localImports].map((b) => b.name));
    for (const d of code.matchAll(/^(?:async[ \t]+)?(?:def|class)[ \t]+([A-Za-z_]\w*)/gm)) {
      if (imported.has(d[1])) bindings.push({ at: d.index ?? 0, name: d[1] });
    }
    bindings.sort((a, b) => a.at - b.at);
    const last = new Map<string, string | undefined>();
    for (const b of bindings) last.set(b.name, b.target);
    for (const [name, target] of last) if (target) addCall(name, target);
    for (const { name, target } of localImports) if (!last.has(name)) addCall(name, target);
  }
  // Paths and file openers imported under another name: `from pathlib import Path as P`
  // reads as `Path(`, `from aiofiles import open as aopen` as `aiofiles.open(`
  for (const m of code.matchAll(/^[ \t]*from[ \t]+(pathlib|aiofiles|io|codecs)[ \t]+import[ \t]+\(?([^\n#)]+)/gm)) {
    for (const part of m[2].split(',')) {
      const im = /^\s*(\w+)\s+as\s+(\w+)\s*$/.exec(part);
      if (im && im[1] !== im[2]) addCall(im[2], m[1] === 'pathlib' ? im[1] : `${m[1]}.${im[1]}`);
    }
  }
  // Names bound by assignment at any indent: a module (`sp = importlib.import_module("subprocess")`),
  // a sink function (`runner = subprocess.run`, `run = getattr(subprocess, "r" + "un")`,
  // `_ev = getattr(builtins, "eval")`, `b = a` with `a` one, `b = a = os.system`,
  // `functools.partial(subprocess.run, shell=True)`), keyword options that turn
  // the shell on (`OPTS = {"shell": True}`)
  const modules = new Map<string, string>([...SINK_MODULES, 'builtins'].map((m) => [m, m]));
  for (const m of code.matchAll(/^[ \t]*import[ \t]+([^\n#]+)/gm)) {
    for (const part of m[1].split(',')) {
      const am = /^\s*([\w.]+)\s+as\s+(\w+)\s*$/.exec(part);
      if (am && (SINK_MODULES.has(am[1]) || am[1] === 'builtins')) modules.set(am[2], am[1]);
    }
  }
  const assigned: Array<[string, string]> = [];
  const CHAIN = /^([A-Za-z_]\w*)[ \t]*=(?!=)[ \t]*(\S.*)$/;
  // Over comment-stripped lines: a trailing `# note` must not hide the binding
  const ASSIGNMENT = /^[ \t]*([A-Za-z_]\w*)[ \t]*(?::[^=\n]+)?=[ \t]*([^\n]{1,300}?)[ \t]*$/;
  for (const { text } of codeLines(code)) {
    const am = ASSIGNMENT.exec(text);
    if (!am) continue;
    const [, name, rhs] = am;
    // `b = a = os.system`: every target binds the last expression
    let expr = rhs;
    const names = [name];
    for (let chain = CHAIN.exec(expr); chain && names.length < 8; chain = CHAIN.exec(expr)) {
      names.push(chain[1]);
      expr = chain[2];
    }
    for (const n of names) assigned.push([n, expr]);
  }
  for (const [name, expr] of assigned) {
    // (the name may be split into literals: `import_module("subpro" + "cess")`)
    const spelled = /^(?:importlib\.import_module|__import__)\(\s*((?:["']\w*["']\s*\+\s*){0,8}["']\w+["'])\s*\)$/.exec(expr)?.[1];
    const mod = spelled?.replace(/["'\s+]/g, '');
    if (mod && (SINK_MODULES.has(mod) || mod === 'builtins') && name !== mod) {
      modules.set(name, mod);
      addModule(name, mod === 'builtins' ? '' : `${mod}.`);
    }
  }
  // `partial` under the names it is imported as: `from functools import partial as P`, `import functools as ft`
  const partialNames = new Set(['partial', 'functools.partial']);
  for (const m of code.matchAll(/^[ \t]*from[ \t]+functools[ \t]+import[ \t]+\(?([^\n#)]+)/gm)) {
    for (const part of m[1].split(',')) {
      const im = /^\s*partial\s+as\s+(\w+)\s*$/.exec(part);
      if (im) partialNames.add(im[1]);
    }
  }
  for (const m of code.matchAll(/^[ \t]*import[ \t]+([^\n#]+)/gm)) {
    for (const part of m[1].split(',')) {
      const am = /^\s*functools\s+as\s+(\w+)\s*$/.exec(part);
      if (am) partialNames.add(`${am[1]}.partial`);
    }
  }
  const plainAliases: Array<[string, string]> = [];
  for (const [name, expr] of assigned) {
    const call = /^([A-Za-z_][\w.]*)\(\s*([A-Za-z_][\w.]*)\s*,(.*)\)$/.exec(expr);
    const partial = call && partialNames.has(call[1]) ? [call[0], call[2], call[3]] : null;
    const target = sinkReference(partial ? partial[1] : expr, modules);
    if (target && target !== name) {
      addCall(name, target, partial && /\bshell\s*=\s*True\b/.test(partial[2]) ? 'shell=True' : undefined);
    } else if (/^[A-Za-z_]\w*$/.test(expr) && expr !== name) {
      plainAliases.push([name, expr]);
    }
    if (/^(?:\{.*["']shell["']\s*:\s*True\b.*\}|dict\(.*\bshell\s*=\s*True\b.*\))$/.test(expr)) shellKwargs.add(name);
  }
  // `b = a` where `a` is a sink alias (or a from-imported sink), a few hops
  for (let hop = 0, changed = true; changed && hop < 4; hop++) {
    changed = false;
    for (const [name, from] of plainAliases) {
      const to = callAliases.get(from);
      if (to && !callAliases.has(name)) { callAliases.set(name, to); changed = true; }
    }
  }
  const identifier = /(?<![\w.])([A-Za-z_]\w*)(\s*\(|\.)/g;
  const rewriteAliases = (text: string, line?: number): string => {
    // edits as [start, end, replacement]; an insertion has start === end
    const edits: Array<[number, number, string]> = [];
    // brackets matched once per text, on the first call that needs one
    let closes: Int32Array | undefined;
    for (const m of text.matchAll(identifier)) {
      const [whole, name, after] = m;
      const at = m.index ?? 0;
      if (after === '.') {
        const to = moduleAliases.get(name);
        if (to !== undefined) edits.push([at, at + whole.length, to]);
        continue;
      }
      const call = callAt(name, line);
      // `def run(self):` defines a name, it doesn't call the imported one
      if (!call || /\b(?:def|class)[ \t]+$/.test(text.slice(Math.max(0, at - 16), at))) continue;
      edits.push([at, at + whole.length, `${call.target}(`]);
      // keyword arguments the alias was bound with go in before its call's `)`
      const close = call.extra ? closingParen(text, at + whole.length, (closes ??= matchBrackets(text))) : -1;
      if (close >= 0) edits.push([close, close, `, ${call.extra}`]);
    }
    if (edits.length === 0) return text;
    edits.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
    let out = '';
    let last = 0;
    for (const [start, end, to] of edits) {
      if (start < last) continue;
      out += text.slice(last, start) + to;
      last = end;
    }
    return out + text.slice(last);
  };
  return (text: string, line?: number): string => {
    let out = text.replace(/\b__import__\(\s*["'](\w+)["']\s*\)\s*\./g, '$1.');
    // getattr(os, "sys" + "tem")(cmd): a sink name assembled to dodge a grep.
    // The name stops at `(` too (a name holding one is never rewritten), and
    // its leading space is the name's: `,\s*[^)]*` split a long space run
    // every way, and each `getattr(` scanned the rest of the text (quadratic)
    out = out.replace(/\bgetattr\(\s*(os|subprocess|builtins)\s*,([^()]*)\)\s*\(/g, (m, mod: string, name: string) => {
      const literal = name.replace(/["'\s+]/g, '');
      if (!/^\w+$/.test(literal)) return m;
      return mod === 'builtins' ? `${literal}(` : `${mod}.${literal}(`;
    });
    out = out.replace(/(?<![\w.])builtins\.(\w+)\s*\(/g, '$1(');
    if (moduleAliases.size > 0 || callAliases.size > 0 || scopedCalls.size > 0) out = rewriteAliases(out, line);
    if (shellKwargs.size > 0) out = out.replace(/\*\*([A-Za-z_]\w*)\b/g, (m, name: string) => (shellKwargs.has(name) ? `shell=True, ${m}` : m));
    return out;
  };
}

/** Furthest a call's closing `)` is looked for. */
const MAX_CALL_SCAN = 4000;

/**
 * For each opening bracket in `text`, the index of the bracket that closes
 * it (any kind, as a depth count would), or -1; quoted text is skipped. One
 * pass with a stack: looking up a call's `)` is constant time, however many
 * calls a line nests.
 */
function matchBrackets(text: string): Int32Array {
  const closes = new Int32Array(text.length).fill(-1);
  const open: number[] = [];
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '(' || c === '[' || c === '{') open.push(i);
    else if (c === ')' || c === ']' || c === '}') {
      const at = open.pop();
      if (at !== undefined) closes[at] = i;
    }
  }
  return closes;
}

/** The index of the `)` closing a call whose arguments start at `from` (just after its `(`), or -1. */
function closingParen(text: string, from: number, closes: Int32Array): number {
  const close = from > 0 && text[from - 1] === '(' ? closes[from - 1] : -1;
  return close >= 0 && close - from < MAX_CALL_SCAN && text[close] === ')' ? close : -1;
}

/** Builtins that run code. */
const CODE_BUILTINS = new Set(['eval', 'exec', 'compile', '__import__']);

/**
 * The sink an assigned expression names: `subprocess.run`, `sp.run` (sp a
 * module alias), `getattr(subprocess, "r" + "un")`, `getattr(builtins, "eval")`,
 * `builtins.exec`. Undefined for anything else.
 */
function sinkReference(expr: string, modules: Map<string, string>): string | undefined {
  const qualify = (alias: string, fn: string): string | undefined => {
    const mod = modules.get(alias);
    if (!mod || !/^\w+$/.test(fn)) return undefined;
    if (mod === 'builtins') return CODE_BUILTINS.has(fn) ? fn : undefined;
    return `${mod}.${fn}`;
  };
  const dotted = /^([A-Za-z_]\w*)\.(\w+)$/.exec(expr);
  if (dotted) return qualify(dotted[1], dotted[2]);
  const ga = /^getattr\(\s*([A-Za-z_]\w*)\s*,([^()]*)\)$/.exec(expr);
  if (ga && /^\s*(?:["'][\w]*["']\s*\+?\s*)+$/.test(ga[2])) return qualify(ga[1], ga[2].replace(/["'\s+]/g, ''));
  return undefined;
}

/** The marker between files of a joined multi-file source. */
const FILE_MARKER = /^\/\/ === .+ ===$/;

/**
 * Physical lines merged while a bracket is open, so a multi-line call is one
 * statement. Brackets are counted outside strings, a triple-quoted string
 * followed from its opening line to its closing one (`execute("""` …
 * `""", (a, b))`: the body lines are dropped by `codeLines`, the closing line
 * starts inside the string) — miscounting one let a single statement swallow
 * the rest of a package. A file marker always starts a statement.
 */
export function statements(lines: CodeLine[]): Array<CodeLine & { last: number }> {
  const out: Array<CodeLine & { last: number }> = [];
  let current: (CodeLine & { last: number }) | undefined;
  let depth = 0;
  let triple: string | undefined; // the open triple-quoted string's delimiter
  for (const l of lines) {
    const marker = FILE_MARKER.test(l.text.trim());
    if (marker) { depth = 0; triple = undefined; }
    if (current && depth > 0 && !marker) {
      current.text += ' ' + l.text.trim();
      current.last = l.line;
    } else {
      current = { line: l.line, text: l.text, last: l.line };
      out.push(current);
      depth = 0;
    }
    const t = l.text;
    let i = 0;
    while (i < t.length) {
      if (triple) {
        const close = t.indexOf(triple, i);
        if (close < 0) break;
        i = close + 3;
        triple = undefined;
        continue;
      }
      const c = t[i];
      if (c === '#') break;
      if (c === '"' || c === "'") {
        if (t.startsWith(c.repeat(3), i)) { triple = c.repeat(3); i += 3; continue; }
        let j = i + 1;
        while (j < t.length && t[j] !== c) j += t[j] === '\\' ? 2 : 1;
        i = j + 1;
        continue;
      }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth = Math.max(0, depth - 1);
      i++;
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
  /** Every parameter by position (`self`/`cls` dropped), for matching call arguments. */
  positional: string[];
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
    const parts = topLevelParts(paramText);
    const params = parts
      .filter((p) => !/:\s*(?:bool|int|float)\b/.test(p) && !/=\s*(?:True|False|-?\d+(?:\.\d+)?)\s*$/.test(p))
      .map((p) => /^\s*\**([A-Za-z_]\w*)/.exec(p)?.[1])
      .filter((p): p is string => !!p && p !== 'self' && p !== 'cls' && p !== 'ctx');
    const positional = parts.map((p) => /^\s*([A-Za-z_]\w*)/.exec(p)?.[1] ?? '').filter((p) => p !== 'self' && p !== 'cls');
    fns.push({ name: def[2], params, start: i, end, tool, positional });
  }
  // Registered without a decorator: `mcp.add_tool(read)`, `mcp.tool()(read)`, `Tool.from_function(read)`
  const registered = new Set<string>();
  for (const st of stmts) {
    const code = blankStrings(st.text);
    if (!/\b(?:add_tool|from_function|tool)\s*\(/.test(code)) continue;
    for (const m of code.matchAll(/\.\s*(?:add_tool|from_function)\s*\(\s*(?:(?:self|cls)\.)?([A-Za-z_]\w*)\s*[,)]|\.\s*tool\s*\([^()]*\)\s*\(\s*(?:(?:self|cls)\.)?([A-Za-z_]\w*)\s*[,)]/g)) {
      registered.add(m[1] ?? m[2]);
    }
  }
  if (registered.size > 0) for (const f of fns) if (registered.has(f.name)) f.tool = true;
  return fns;
}

/**
 * The MCP tool functions of a Python server (`@mcp.tool()`, `@server.call_tool()`
 * decorated), by name: each function's source text, decorators excluded —
 * what MCP-019 classifies as a source or a sink tool.
 */
export function pythonToolHandlers(code: string): Map<string, string> {
  const stmts = statements(codeLines(code));
  const out = new Map<string, string>();
  for (const f of functionsOf(stmts)) {
    if (!f.tool || out.has(f.name)) continue;
    out.set(f.name, stmts.slice(f.start, f.end).map((st) => st.text).join('\n'));
  }
  return out;
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
const PASSTHROUGH_CALLS = /^(?:str|f|format|join|replace|strip|lstrip|rstrip|lower|upper|split|splitlines|shlex\.split|shlex\.join|os\.path\.join|os\.path\.expanduser|os\.path\.(?:realpath|abspath|normpath)|Path|list|tuple|dict|get|pop|encode|decode|append|extend|copy)$/;

/**
 * The parts of an assigned expression whose value flows into the variable:
 * a condition (`a if flag else b`, `not x`) only picks between values, and an
 * arbitrary call (`LanguageConfigLoader.load(language)`) returns its own
 * value — string building and container calls pass their arguments through,
 * and so does a same-file helper that returns what it is given (`returners`:
 * `clean(query)` with `def clean(p): return p.strip()`), for the arguments it
 * returns only — per call site.
 */
function dataPart(expr: string, returners?: ReadonlyMap<string, ReturnedArgs>): string {
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
    // `"".join(c for c in name if c.isalnum())`: a filtered comprehension
    // keeps only what passes the filter — not the argument's text
    const filtered = method === 'join' && /\bfor\b[\s\S]*\bin\b[\s\S]*\bif\b/.test(args);
    const keep = !filtered && (PASSTHROUGH_CALLS.test(m[1]) || PASSTHROUGH_CALLS.test(method));
    const helper = returners && (dot === -1 || receiver === 'self' || receiver === 'cls') ? returners.get(method) : undefined;
    const kept = keep ? args : helper ? returnedArgs(args, helper) : '';
    out = out.slice(0, m.index) + ` ${receiver} ${kept} ` + out.slice(open + args.length + 2);
  }
  return out;
}

/** The parameters a same-file helper returns (derived or as is), by position and by name. */
interface ReturnedArgs {
  at: Set<number>;
  names: Set<string>;
}

/** The arguments of one call a helper returns: positional by index, keyword by parameter name. */
function returnedArgs(args: string, helper: ReturnedArgs): string {
  const parts = topLevelParts(args);
  let index = 0;
  const kept: string[] = [];
  for (const part of parts) {
    const kw = /^\s*([A-Za-z_]\w*)\s*=(?!=)([\s\S]*)$/.exec(part);
    if (kw) {
      if (helper.names.has(kw[1])) kept.push(kw[2]);
    } else if (/^\s*\*/.test(part)) {
      kept.push(part.replace(/^\s*\*+/, ''));
    } else if (helper.at.has(index++)) {
      kept.push(part);
    }
  }
  return kept.join(' , ');
}

/** Rounds of the returners fixpoint (a helper returning another helper's result). */
const MAX_RETURNER_ROUNDS = 8;

/**
 * Same-file functions whose return value carries a parameter (`return p.strip()`,
 * `q = os.path.join(BASE, p)` then `return q`): by name, which parameters.
 * What a call returns then carries those arguments of that call only.
 */
function passingReturners(stmts: Array<CodeLine & { last: number }>, fns: PyFunction[],
  rewrite: (t: string, line?: number) => string, fnAt: (i: number) => PyFunction | undefined): Map<string, ReturnedArgs> {
  const out = new Map<string, ReturnedArgs>();
  const texts: Array<string | undefined> = new Array(stmts.length);
  const textAt = (i: number): string => (texts[i] ??= rewrite(stmts[i].text, stmts[i].line));
  let changed = true;
  for (let round = 0; changed && round < MAX_RETURNER_ROUNDS; round++) {
    changed = false;
    for (const fn of fns) {
      const from = new Map<string, Set<string>>(fn.positional.filter(Boolean).map((p) => [p, new Set([p])]));
      if (from.size === 0) continue;
      const returned = new Set<string>();
      for (let i = fn.start + 1; i < fn.end; i++) {
        if (fnAt(i) !== fn) continue;
        const text = textAt(i);
        const ret = /^\s*return\s+([\s\S]+)$/.exec(text);
        if (ret) {
          // A tuple (`return path, title or key, False`): its parts are
          // unpacked one by one, which the caller's taint doesn't follow
          const inner = /^\s*\(([\s\S]*)\)\s*$/.exec(ret[1])?.[1] ?? ret[1];
          if (topLevelParts(inner).length > 1) continue;
          const data = dataPart(ret[1], out);
          for (const [n, roots] of from) if (mentions(data, n)) for (const r of roots) returned.add(r);
          continue;
        }
        const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
        if (!assign) continue;
        const data = dataPart(assign[2], out);
        const roots = new Set<string>();
        for (const [n, r] of from) if (mentions(data, n)) for (const x of r) roots.add(x);
        if (roots.size > 0) from.set(assign[1], roots);
        else from.delete(assign[1]);
      }
      if (returned.size === 0) continue;
      const prev = out.get(fn.name);
      if (prev && [...returned].every((p) => prev.names.has(p))) continue;
      const names = new Set([...(prev?.names ?? []), ...returned]);
      const at = new Set<number>();
      fn.positional.forEach((p, idx) => { if (names.has(p)) at.add(idx); });
      out.set(fn.name, { at, names });
      changed = true;
    }
  }
  return out;
}

/** The helper (of `returners`) whose returned arguments carry `name` in `expr`, if any. */
function returnerCarrying(expr: string, name: string, returners: ReadonlyMap<string, ReturnedArgs>): string | undefined {
  for (const m of expr.matchAll(/(?<![\w.])(?:(?:self|cls)\.)?([A-Za-z_]\w*)\s*\(/g)) {
    const helper = returners.get(m[1]);
    if (helper && mentions(returnedArgs(callArgs(expr, m.index + m[0].length - 1), helper), name)) return m[1];
  }
  return undefined;
}

const mentions = (text: string, name: string): boolean => new RegExp(String.raw`(?<![\w.])${name}\b`).test(text);

/**
 * A tools/call dispatcher a low-level server writes itself
 * (`async def handle_tools_call(self, message)` picking the tool by name):
 * what it is given is the request, so its parameters carry tool input.
 */
const TOOL_DISPATCHER = /^_*(?:handle_?)?(?:tools?_?call|call_?tools?)$/i;
/** Rounds of the taint fixpoint: each adds a name or ends it; bounds a pathological file. */
const MAX_TAINT_ROUNDS = 32;

/**
 * The names a `for` loop, a comprehension (`[open(p) for p in paths]`),
 * `with … as` or a walrus binds from an expression: `[names, expression]` pairs.
 */
function otherBindings(text: string): Array<[string[], string]> {
  const out: Array<[string[], string]> = [];
  const loop = /^\s*(?:async\s+)?for\s+([\w\s,()[\]]+?)\s+in\s+([\s\S]+?):\s*$/.exec(text);
  if (loop) out.push([identifiersOf(loop[1]), loop[2]]);
  else if (/\bfor\b/.test(text)) {
    // a comprehension's iterable: up to its `if`, the next `for`, or its closing bracket
    const clean = mapStringLiterals(text, (m) => '_'.repeat(m.length));
    for (const m of clean.matchAll(/(?<![\w.])for\s+([\w\s,()]+?)\s+in\s+/g)) {
      const start = m.index + m[0].length;
      let depth = 0;
      let end = start;
      for (; end < clean.length; end++) {
        const c = clean[end];
        if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') { if (--depth < 0) break; }
        else if (depth === 0 && /^(?:if|for|async)\b/.test(clean.slice(end, end + 6)) && /\s/.test(clean[end - 1] ?? '')) break;
      }
      out.push([identifiersOf(m[1]), text.slice(start, end)]);
    }
  }
  const withAs = /^\s*(?:async\s+)?with\s+([\s\S]+?)\s+as\s+([A-Za-z_]\w*)\s*:/.exec(text);
  if (withAs) out.push([[withAs[2]], withAs[1]]);
  for (const m of text.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*:=\s*([^,()]+(?:\([^()]*\)[^,()]*)*)/g)) out.push([[m[1]], m[2]]);
  return out;
}

/**
 * Names in each function that carry tool input: a tool function's (or a
 * tools/call dispatcher's) parameters, helper parameters passed tainted
 * values at a call site, and variables assigned from them (also tuple
 * unpacking, `for` targets, `with … as`, walrus). Iterated to a fixpoint, so
 * tool → helper → helper chains of any length taint, in any order of
 * declaration. `blank` hides the arguments a confining helper takes
 * (`open_repo(repo_path)` validates and returns): its result is not the
 * caller's raw input. What a helper in `returners` returns carries the
 * arguments it returns (`q = clean(query)`: `q ← clean() ← query`).
 */
function taintedNames(stmts: Array<CodeLine & { last: number }>, fns: PyFunction[], rewrite: (t: string, line?: number) => string,
  blank: (text: string) => string = (t) => t, returners: ReadonlyMap<string, ReturnedArgs> = new Map()): Map<PyFunction, Map<string, string>> {
  /** `target ← from`, naming the helper the value came back through */
  const label = (target: string, expr: string, from: string, chain: string): string => {
    const via = returners.size > 0 && !mentions(dataPart(expr), from) ? returnerCarrying(expr, from, returners) : undefined;
    return via ? `${target} ← ${via}() ← ${chain}` : `${target} ← ${chain}`;
  };
  const tainted = new Map<PyFunction, Map<string, string>>();
  for (const fn of fns) {
    const seeded = fn.tool || TOOL_DISPATCHER.test(fn.name);
    tainted.set(fn, new Map(seeded ? fn.params.map((p) => [p, p]) : []));
    argvNames.set(fn, new Set());
  }
  const byName = new Map(fns.map((f) => [f.name, f]));
  const texts: Array<string | undefined> = new Array(stmts.length);
  const textAt = (i: number): string => (texts[i] ??= rewrite(stmts[i].text, stmts[i].line));
  let changed = true;
  for (let round = 0; changed && round < MAX_TAINT_ROUNDS; round++) {
    changed = false;
    for (const fn of fns) {
      const names = tainted.get(fn)!;
      if (names.size === 0) continue;
      for (let i = fn.start + 1; i < fn.end; i++) {
        const text = textAt(i);
        const data = blank(text);
        const assign = /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(data);
        if (assign) {
          const targets = assign[1].split(',').map((t) => t.trim());
          const rhs = dataPart(assign[2], returners);
          const from = targets.some((t) => !names.has(t)) ? [...names.keys()].find((n) => mentions(rhs, n)) : undefined;
          if (from) {
            for (const target of targets) {
              if (names.has(target)) continue;
              names.set(target, label(target, assign[2], from, names.get(from)!));
              changed = true;
              // An argv list with the input as one of its arguments.
              if (LIST_BUILDING.test(assign[2]) || argvNames.get(fn)!.has(from)) argvNames.get(fn)!.add(target);
            }
          }
        }
        for (const [targets, expr] of otherBindings(data)) {
          if (targets.every((t) => names.has(t))) continue;
          const rhs = dataPart(expr, returners);
          const from = [...names.keys()].find((n) => mentions(rhs, n));
          if (!from) continue;
          for (const target of targets) {
            if (names.has(target)) continue;
            names.set(target, label(target, expr, from, names.get(from)!));
            changed = true;
          }
        }
        for (const call of text.matchAll(/(?<![\w.])(?:self\.)?(\w+)\s*\(/g)) {
          const callee = byName.get(call[1]);
          if (!callee || callee === fn) continue;
          const args = callArgs(text, call.index + call[0].length - 1).split(',');
          const calleeNames = tainted.get(callee)!;
          args.forEach((arg, idx) => {
            const param = callee.params[idx];
            if (!param || calleeNames.has(param)) return;
            const plain = blank(arg);
            const from = [...names.keys()].find((n) => mentions(plain, n));
            if (!from) return;
            calleeNames.set(param, `${param} ← ${names.get(from)}`);
            changed = true;
          });
        }
      }
    }
  }
  return tainted;
}

/**
 * Helpers that confine a parameter and return a value (`open_repo(repo_path)`:
 * validates the path against the allowed root, then returns the repository
 * opened there): by name, the argument positions whose value comes back
 * confined. What they return is not the caller's raw path.
 */
function confiningReturners(stmts: Array<CodeLine & { last: number }>, fns: PyFunction[],
  rewrite: (t: string, line?: number) => string, confinedIn: Map<PyFunction, Map<string, number>>,
  fnAt: (i: number) => PyFunction | undefined): Map<string, Set<number>> {
  const out = new Map<string, Set<number>>();
  for (const fn of fns) {
    const confined = confinedIn.get(fn);
    if (!confined || confined.size === 0) continue;
    const from = new Map<string, Set<string>>(fn.positional.filter(Boolean).map((p) => [p, new Set([p])]));
    const positions = new Set<number>();
    for (let i = fn.start + 1; i < fn.end; i++) {
      if (fnAt(i) !== fn) continue;
      const text = rewrite(stmts[i].text, stmts[i].line);
      if (/^\s*return\s+\S/.test(text)) {
        for (const [c, at] of confined) {
          if (at >= i) continue;
          fn.positional.forEach((p, idx) => { if (p && (c === p || from.get(c)?.has(p))) positions.add(idx); });
        }
        continue;
      }
      const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
      if (!assign) continue;
      const data = dataPart(assign[2]);
      const roots = new Set<string>();
      for (const [n, r] of from) if (mentions(data, n)) for (const x of r) roots.add(x);
      if (roots.size > 0) from.set(assign[1], roots);
      else from.delete(assign[1]);
    }
    if (positions.size > 0) out.set(fn.name, positions);
  }
  return out;
}

/** `text` with the arguments confining helpers confine blanked out (same length). */
function blankConfinedArgs(text: string, returners: Map<string, Set<number>>): string {
  let out = text;
  for (const m of text.matchAll(/(?<![\w.])(?:self\.)?(\w+)\s*\(/g)) {
    const positions = returners.get(m[1]);
    if (!positions) continue;
    const open = m.index + m[0].length - 1;
    let at = open + 1;
    topLevelParts(callArgs(text, open)).forEach((part, idx) => {
      if (positions.has(idx) && !/^\s*\w+\s*=/.test(part)) out = out.slice(0, at) + ' '.repeat(part.length) + out.slice(at + part.length);
      at += part.length + 1;
    });
  }
  return out;
}

/**
 * A resolved path tested against a base (`is_relative_to`, `relative_to`,
 * `commonpath`, `startswith(<base>)`), or two resolved paths compared. A
 * `startswith("http")` on a literal confines nothing.
 */
const PATH_CONFINES = /\.(?:is_relative_to|relative_to)\s*\(|\bcommon(?:path|prefix)\s*\(|\.startswith\s*\(\s*(?![rRbBuUfF]{0,2}["'])|\b(?:realpath|abspath)\s*\([^\n]*\)\s*(?:==|!=)|(?:==|!=)\s*(?:os\.path\.)?(?:realpath|abspath)\s*\(/;
const RESOLVED_COMPARE = /\b(?:realpath|abspath)\s*\([^\n]*\)\s*(?:==|!=)|(?:==|!=)\s*(?:os\.path\.)?(?:realpath|abspath)\s*\(/;
/** A value that is a resolved path: `os.path.realpath(…)`, `os.path.abspath(…)`, `(BASE / name).resolve()`. */
const RESOLVED_VALUE = /^\s*(?:(?:os\.path|posixpath)\.)?(?:realpath|abspath)\s*\([\s\S]*\)\s*$|\.resolve\s*\([^()]*\)\s*$/;
const IDENTIFIERS = /(?<![\w.])[A-Za-z_]\w*/g;
const identifiersOf = (text: string): string[] => [...text.matchAll(IDENTIFIERS)].map((m) => m[0]);

/** Names a check resolves itself: the arguments of `realpath(…)`/`abspath(…)`, the receiver of `.resolve()`. */
function resolvedInside(region: string): string[] {
  const out: string[] = [];
  for (const m of region.matchAll(/\b(?:realpath|abspath)\s*\(|\.resolve\s*\(/g)) {
    if (m[0].startsWith('.')) {
      const start = receiverStart(region, m.index);
      if (start !== undefined) out.push(...identifiersOf(region.slice(start, m.index)));
    } else {
      out.push(...identifiersOf(callArgs(region, m.index + m[0].length - 1)));
    }
  }
  return out;
}

/**
 * The names a check statement confines: the resolved path a base test is
 * made on (`p.is_relative_to(BASE)` with `p` resolved,
 * `os.path.realpath(full).startswith(ROOT)`, `os.path.commonpath([full, BASE])`,
 * `os.path.dirname(full) != os.path.realpath(ROOT)`). An unresolved path
 * (`path.startswith(ROOT)`) is confined by none of them: `ROOT/../etc` passes.
 */
function confinedByCheck(text: string, resolved: ReadonlySet<string>): string[] {
  const code = blankStrings(text);
  if (!PATH_CONFINES.test(code)) return [];
  const out: string[] = [];
  const take = (region: string): void => {
    for (const n of identifiersOf(region)) if (resolved.has(n)) out.push(n);
    out.push(...resolvedInside(region));
  };
  // A test whose result is thrown away (`full.startswith(BASE)` on its own
  // line) confines nothing; `relative_to` raises, so it checks even there
  const discarded = expressionStatement(code);
  const depth = discarded ? bracketDepths(code) : undefined;
  const used = (at: number): boolean => !depth || depth[at] > 0;
  for (const m of code.matchAll(/\.(startswith|is_relative_to|relative_to)\s*\(\s*/g)) {
    if (m[1] === 'startswith' && /^[rRbBuUfF]{0,2}["']/.test(code.slice(m.index + m[0].length))) continue;
    if (m[1] !== 'relative_to' && !used(m.index)) continue;
    const start = receiverStart(code, m.index);
    if (start !== undefined) take(code.slice(start, m.index));
  }
  for (const m of code.matchAll(/\bcommon(?:path|prefix)\s*\(/g)) if (used(m.index)) take(callArgs(code, m.index + m[0].length - 1));
  if (RESOLVED_COMPARE.test(code) && !(discarded && [...code.matchAll(/[=!]=/g)].some((m) => depth![m.index] === 0))) take(code);
  return out;
}

/** A statement that is only an expression: no assignment, condition, assert, return… — its value is discarded. */
function expressionStatement(code: string): boolean {
  if (/^\s*(?:if|elif|while|assert|return|yield|raise|with|for|async|await|del|lambda|print)\b/.test(code)) return false;
  const depth = bracketDepths(code);
  for (let i = 0; i < code.length; i++) {
    if (code[i] !== '=' || depth[i] !== 0) continue;
    if (code[i + 1] === '=' || /[=!<>]/.test(code[i - 1] ?? '')) continue;
    return false; // an assignment (`ok = …`, `x += …`, `:=`)
  }
  return true;
}

/** Bracket depth before each character of string-blanked code. */
function bracketDepths(code: string): Int32Array {
  const out = new Int32Array(code.length + 1);
  let d = 0;
  for (let i = 0; i < code.length; i++) {
    out[i] = d;
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') d = Math.max(0, d - 1);
  }
  out[code.length] = d;
  return out;
}

/**
 * Where, in each function, a name is first confined to a base directory (a
 * statement index): resolved and then tested against a base, or passed to a
 * same-file helper that does that with the parameter it lands in. Judged per
 * function and per name — an `os.path.abspath(…)` in one place and a
 * `startswith(prefix)` in another confine nothing.
 */
function confinedNamesByFunction(stmts: Array<CodeLine & { last: number }>, fns: PyFunction[],
  rewrite: (t: string, line?: number) => string): Map<PyFunction, Map<string, number>> {
  const direct = new Map<PyFunction, Map<string, number>>();
  // the parameters each local name comes from: `full = realpath(join(BASE, p))` from `p`
  const derived = new Map<PyFunction, Map<string, Set<string>>>();
  const texts: Array<string | undefined> = new Array(stmts.length);
  const textAt = (i: number): string => (texts[i] ??= rewrite(stmts[i].text, stmts[i].line));
  for (const fn of fns) {
    const confined = new Map<string, number>();
    const resolved = new Set<string>();
    const from = new Map<string, Set<string>>(fn.positional.filter(Boolean).map((p) => [p, new Set([p])]));
    // stored test results (`ok = full.startswith(BASE)`): the names they confine once tested
    const flags = new Map<string, string[]>();
    for (let i = fn.start + 1; i < fn.end; i++) {
      const text = textAt(i);
      const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
      let checked = confinedByCheck(text, resolved);
      const code = blankStrings(text);
      if (CONDITION.test(code)) {
        const test = conditionTest(code);
        for (const [flag, names] of flags) if (mentions(test, flag)) checked = [...checked, ...names];
        if (checked.length > 0 && !guardsSink(textAt, fn, i, test, checked)) checked = [];
      } else if (assign && checked.length > 0 && !/\.relative_to\s*\(/.test(code) && !TERNARY.test(dataPart(assign[2]))) {
        // a result stored, not acted on: it confines once an `if` tests it
        flags.set(assign[1], checked);
        checked = [];
      }
      for (const n of checked) if (!confined.has(n)) confined.set(n, i);
      if (!assign) continue;
      const [, name, rhs] = assign;
      if (RESOLVED_VALUE.test(blankStrings(rhs))) resolved.add(name);
      else resolved.delete(name);
      const data = dataPart(rhs);
      const roots = new Set<string>();
      for (const [n, r] of from) if (mentions(data, n)) for (const x of r) roots.add(x);
      if (roots.size > 0) from.set(name, roots);
      else from.delete(name);
    }
    direct.set(fn, confined);
    derived.set(fn, from);
  }
  // helpers that confine a parameter: the argument positions they confine, by name
  const helpers = new Map<string, Set<number>>();
  for (const fn of fns) {
    const from = derived.get(fn)!;
    const positions = new Set<number>();
    fn.positional.forEach((p, idx) => {
      if (!p) return;
      for (const c of direct.get(fn)!.keys()) if (c === p || from.get(c)?.has(p)) positions.add(idx);
    });
    if (positions.size > 0) helpers.set(fn.name, positions);
  }
  if (helpers.size === 0) return direct;
  for (const fn of fns) {
    const confined = direct.get(fn)!;
    for (let i = fn.start + 1; i < fn.end; i++) {
      const text = textAt(i);
      for (const call of text.matchAll(/(?<![\w.])(?:self\.)?(\w+)\s*\(/g)) {
        const positions = helpers.get(call[1]);
        if (!positions || call[1] === fn.name) continue;
        const args = topLevelParts(callArgs(text, call.index + call[0].length - 1));
        for (const idx of positions) {
          for (const n of identifiersOf(args[idx] ?? '')) if ((confined.get(n) ?? Infinity) > i) confined.set(n, i);
        }
      }
    }
  }
  return direct;
}

const CONDITION = /^\s*(?:(?:el)?if|while)\b/;
const TERNARY = /\bif\b[\s\S]*\belse\b/;
/** A statement that leaves the function or the loop (or the process). */
const EXITS = /^\s*(?:raise|return|continue|break)\b|\b(?:sys\.exit|os\._exit|exit|abort)\s*\(/;
const indentOf = (text: string): number => text.search(/\S/);

/** The test of an `if`/`elif`/`while` statement (string-blanked): up to its top-level colon. */
function conditionTest(code: string): string {
  const depth = bracketDepths(code);
  for (let i = 0; i < code.length; i++) if (code[i] === ':' && depth[i] === 0 && code[i + 1] !== '=') return code.slice(0, i);
  return code;
}

/**
 * Whether the containment test of the `if`/`while` at statement `at` acts
 * on the sink: a failed test leaves (`if not full.startswith(BASE): raise`,
 * or an `else:` that raises), or the names it checks are used only inside
 * the branch where it passed. A test whose branch does nothing about it
 * (`if full.startswith(BASE): print("ok")`, then `open(full)`) confines nothing.
 */
function guardsSink(textAt: (i: number) => string, fn: PyFunction,
  at: number, test: string, names: string[]): boolean {
  const code = blankStrings(textAt(at));
  const indent = indentOf(code);
  const inline = code.slice(test.length + 1);
  let end = at + 1;
  while (end < fn.end && indentOf(textAt(end)) > indent) end++;
  const exits = (from: number, to: number, first?: string): boolean => {
    if (first !== undefined && EXITS.test(first)) return true;
    for (let j = from; j < to; j++) if (EXITS.test(blankStrings(textAt(j)))) return true;
    return false;
  };
  const failed = /^\s*(?:(?:el)?if|while)\s+not\b/.test(test) || /!=|\bis\s+False\b|==\s*False\b/.test(test);
  if (failed) return exits(at + 1, end, inline);
  // `if ok_test: … else: raise`
  if (end < fn.end && indentOf(textAt(end)) === indent && /^\s*else\s*:/.test(textAt(end))) {
    const elseCode = blankStrings(textAt(end));
    let elseEnd = end + 1;
    while (elseEnd < fn.end && indentOf(textAt(elseEnd)) > indent) elseEnd++;
    if (exits(end + 1, elseEnd, elseCode.slice(elseCode.indexOf(':') + 1))) return true;
  }
  // used only inside the passing branch
  for (let j = end; j < fn.end; j++) {
    const later = blankStrings(textAt(j));
    if (names.some((n) => mentions(later, n))) return false;
  }
  return true;
}

/** Whether a name (derived as `chain`, e.g. `full ← path`) was confined before statement `at`. */
function confinedBefore(confined: Map<string, number> | undefined, name: string, chain: string | undefined, at: number): boolean {
  if (!confined || confined.size === 0) return false;
  return (chain ? chain.split(' ← ') : [name]).some((n) => (confined.get(n) ?? Infinity) < at);
}

type FileOp = 'read' | 'write' | 'meta';
/** Module-level file calls by what they do with their path argument(s). `open` reads or writes by its mode. */
const PY_FS_FUNCS = new Map<string, { op: FileOp | 'open'; paths: number }>([
  ...['open', 'io.open', 'codecs.open', 'aiofiles.open', 'os.open'].map((n) => [n, { op: 'open' as const, paths: 1 }] as const),
  ...['os.remove', 'os.unlink', 'os.rmdir', 'os.removedirs', 'os.makedirs', 'os.mkdir', 'os.chmod', 'os.truncate', 'shutil.rmtree']
    .map((n) => [n, { op: 'write' as const, paths: 1 }] as const),
  ...['os.rename', 'os.replace', 'os.symlink', 'os.link', 'shutil.copy', 'shutil.copy2', 'shutil.copyfile', 'shutil.copytree', 'shutil.move']
    .map((n) => [n, { op: 'write' as const, paths: 2 }] as const),
  ...['os.listdir', 'os.scandir', 'os.walk', 'os.stat', 'os.lstat', 'glob.glob', 'glob.iglob']
    .map((n) => [n, { op: 'meta' as const, paths: 1 }] as const),
]);
const PY_FS_CALL = /(?<![\w.])(?<!\bdef\s+)((?:io|codecs|aiofiles|os|shutil|glob)\.)?(\w+)\s*\(/g;
/** Keyword names the path arguments of those calls go by. */
const PATH_KEYWORDS = ['file', 'path', 'src', 'dst', 'top', 'pathname'];
/** pathlib methods by what they do with the receiver's path. */
const PATH_METHODS: Record<string, FileOp | 'open'> = {
  read_text: 'read', read_bytes: 'read', open: 'open',
  write_text: 'write', write_bytes: 'write', unlink: 'write', rmdir: 'write', mkdir: 'write', touch: 'write',
  rename: 'write', symlink_to: 'write', iterdir: 'meta', glob: 'meta', rglob: 'meta', stat: 'meta', lstat: 'meta',
};
/** Method names other types share (file objects, zip members, dicts): only a Path receiver counts. */
const AMBIGUOUS_METHODS = new Set(['open', 'glob', 'stat', 'lstat', 'rename', 'mkdir', 'rmdir']);
const PATH_METHOD = /\.(read_text|read_bytes|open|write_text|write_bytes|unlink|rmdir|mkdir|touch|rename|symlink_to|iterdir|glob|rglob|stat|lstat)\s*\(/g;
const PATH_CALL_RECEIVER = /^\(|^(?:pathlib\.)?(?:Pure|Posix|Windows)?Path\s*\(/;

/** File calls that delete their path (reported as writes, described as deletes). */
const DELETE_CALL = /(?:^|\.)(?:unlink|remove|removedirs|rmdir|rmtree)$/;

/** A literal open mode that writes (`"w"`, `'ab'`, `"r+"`); anything else reads. */
const writesMode = (mode: string | undefined): boolean => mode !== undefined && /^\s*[rRbBuU]{0,2}["'][^"']*[wax+]/.test(mode);

/** Where the receiver expression ending right before `code[dot]` starts (`Path(p)`, `(ROOT / name)`, `self.p`). */
function receiverStart(code: string, dot: number): number | undefined {
  let i = dot;
  // a method chain (`Path(p).expanduser().read_text`): back over each call in turn
  for (let hop = 0; hop < 8; hop++) {
    if (code[i - 1] === ')' || code[i - 1] === ']') {
      let depth = 0;
      const end = i;
      for (i = end - 1; i >= 0; i--) {
        const c = code[i];
        if (c === ')' || c === ']') depth++;
        else if ((c === '(' || c === '[') && --depth === 0) break;
      }
      if (i < 0) return undefined;
    }
    const at = i;
    while (i > 0 && /[\w.]/.test(code[i - 1])) i--;
    if (!(code[i] === '.' && i < at && (code[i - 1] === ')' || code[i - 1] === ']'))) break;
  }
  return i < dot ? i : undefined;
}

/** File calls in a statement: the call, what it does with its path(s), and the path expressions. */
function pythonFileCalls(text: string, pathNames: Set<string>): Array<{ sink: string; op: FileOp; paths: string[] }> {
  const code = blankStrings(text);
  const out: Array<{ sink: string; op: FileOp; paths: string[] }> = [];
  for (const m of code.matchAll(PY_FS_CALL)) {
    const sink = (m[1] ?? '') + m[2];
    const spec = PY_FS_FUNCS.get(sink);
    if (!spec) continue;
    const { positional, keywords } = splitArgs(callArgs(text, m.index + m[0].length - 1));
    // `os.open(path, flags)` writes by its flags, the others by their mode
    const writes = sink === 'os.open' ? /\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b/.test(positional[1] ?? keywords.get('flags') ?? '')
      : writesMode(positional[1] ?? keywords.get('mode'));
    const op = spec.op === 'open' ? (writes ? 'write' : 'read') : spec.op;
    const paths = positional.slice(0, spec.paths);
    for (const kw of PATH_KEYWORDS) if (keywords.has(kw)) paths.push(keywords.get(kw)!);
    out.push({ sink, op, paths });
  }
  for (const m of code.matchAll(PATH_METHOD)) {
    const method = m[1];
    const start = receiverStart(code, m.index);
    if (start === undefined) continue;
    const receiver = text.slice(start, m.index);
    if (AMBIGUOUS_METHODS.has(method) && !PATH_CALL_RECEIVER.test(receiver) && !pathNames.has(receiver)) continue;
    const { positional, keywords } = splitArgs(callArgs(text, m.index + m[0].length - 1));
    const spec = PATH_METHODS[method];
    const op = spec === 'open' ? (writesMode(positional[0] ?? keywords.get('mode')) ? 'write' : 'read') : spec;
    // `p.rename(target)`, `link.symlink_to(target)`: the argument is a path too
    const paths = method === 'rename' || method === 'symlink_to' ? [receiver, ...positional.slice(0, 1)] : [receiver];
    out.push({ sink: `${receiver.length > 40 ? receiver.slice(0, 37) + '…' : receiver}.${method}`, op, paths });
  }
  return out;
}

export function analyzePythonSinks(code: string): PythonSinkFinding[] {
  const findings: PythonSinkFinding[] = [];
  const rewrite = aliasRewriter(code);
  const lines = codeLines(code);
  const stmts = statements(lines);
  const fns = functionsOf(stmts);
  const constants = stringConstantNames(stmts, fns);
  // The innermost function each statement sits in, and the statement each
  // line belongs to — precomputed: a lookup per line was quadratic
  const innermost: Array<PyFunction | undefined> = new Array(stmts.length);
  for (const f of fns) for (let j = f.start + 1; j < f.end; j++) innermost[j] = f;
  const fnAt = (i: number): PyFunction | undefined => innermost[i];
  const lineText = new Map(lines.map((l) => [l.line, l.text]));
  const stmtOfLine = new Map<number, number>();
  stmts.forEach((s, i) => { for (let l = s.line; l <= s.last; l++) if (!stmtOfLine.has(l)) stmtOfLine.set(l, i); });
  // Module-level code: any containment in the file counts; in a function,
  // only a check on the same name, before the use (`confinedNamesByFunction`)
  const confined = RESOLVES.test(code) && CONFINES.test(code);
  const confinedIn = RESOLVES.test(code) && PATH_CONFINES.test(blankStrings(code))
    ? confinedNamesByFunction(stmts, fns, rewrite) : new Map<PyFunction, Map<string, number>>();
  // What a validate-and-return helper gives back is confined, not raw input
  const returners = confiningReturners(stmts, fns, rewrite, confinedIn, fnAt);
  // What a helper returns of its arguments, those it confines left out
  const passing = passingReturners(stmts, fns, rewrite, fnAt);
  for (const [name, positions] of returners) {
    const helper = passing.get(name);
    if (!helper) continue;
    const fn = fns.find((f) => f.name === name);
    for (const at of positions) {
      helper.at.delete(at);
      if (fn?.positional[at]) helper.names.delete(fn.positional[at]);
    }
    if (helper.at.size === 0 && helper.names.size === 0) passing.delete(name);
  }
  const tainted = taintedNames(stmts, fns, rewrite, returners.size > 0 ? (t) => blankConfinedArgs(t, returners) : undefined, passing);
  const touchesFiles = FILE_OPS.test(code);
  const pathNames = new Set<string>();
  if (touchesFiles) for (const m of code.matchAll(PATH_BINDING)) pathNames.add(m[1]);
  /**
   * Whether the path bound at statement `at` is confined afterwards, itself
   * or through what is derived from it (`p = base / p` then
   * `resolved = p.resolve()` and `resolved.is_relative_to(base)`).
   */
  const confinedLater = (fn: PyFunction, target: string, at: number): boolean => {
    const confinedHere = confinedIn.get(fn);
    if (!confinedHere || confinedHere.size === 0) return false;
    if (confinedHere.has(target)) return true;
    const derived = new Set([target]);
    for (let i = at + 1; i < fn.end; i++) {
      if (fnAt(i) !== fn) continue;
      const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(rewrite(stmts[i].text, stmts[i].line));
      if (!assign) continue;
      const rhs = dataPart(assign[2]);
      if ([...derived].some((n) => mentions(rhs, n))) {
        derived.add(assign[1]);
        if ((confinedHere.get(assign[1]) ?? -1) > i) return true;
      }
    }
    return false;
  };
  const injectedLines = new Set<number>();
  // Lines with a path traversal join, and the names they bind: a file call
  // on that path is the same flaw, reported once at the join
  const joinLines = new Set<number>();
  const joinedNames = new Set<string>();

  // Physical-line rules: injection shapes visible on one line.
  for (const { line, text: raw } of lines) {
    const text = rewrite(raw, line);
    const snippet = cutLine(raw.trim());

    if (/\bopen\s*\(|\bPath\s*\(|expanduser\s*\(/.test(text)) {
      for (const m of text.matchAll(STRING_LITERAL)) {
        const labels = classifySensitivePath(m[1]);
        if (labels.length > 0) {
          findings.push({ kind: 'fs-access', line, ...snippet, description: `reads ${labels[0]}` });
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
        findings.push({ kind: 'injection', line, ...snippet, description });
        injectedLines.add(line);
        break;
      }
    }

    if (touchesFiles) {
      const expr = PATH_JOIN_INPUT.exec(text)?.[1] ?? pathlibJoin(text, pathNames);
      const joined = expr?.split('.').pop() ?? '';
      // The name suggests input; whether it is: a name tool input reaches
      // (a tool's parameter, a helper parameter some call site passes tool
      // input to, a variable built from them). A helper parameter only its
      // own code calls with fixed values (`_file(f"{kind}_style.xml")`), and
      // a local built from a hash or a constant table, join nothing the
      // caller chose
      const si = stmtOfLine.get(line) ?? -1;
      const fnHere = si >= 0 ? fnAt(si) : undefined;
      const root = expr?.split('.')[0] ?? '';
      const fromInput = expr && (!fnHere || root === 'self' || tainted.get(fnHere)?.has(root) === true);
      const target = expr && si >= 0 ? /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)/.exec(stmts[si].text)?.[1] : undefined;
      // Confined when the joined path is checked afterwards (`full = realpath(join(BASE, name))`
      // then `full.startswith(BASE)`), or the name joined was checked before
      const joinConfined = !fnHere ? confined
        : (target !== undefined && confinedLater(fnHere, target, si))
          || confinedBefore(confinedIn.get(fnHere), root, tainted.get(fnHere)?.get(root), si);
      // A name tool input is traced into needn't sound like a path (`rp`)
      const traced = !!fnHere && root !== 'self' && tainted.get(fnHere)?.has(root) === true;
      if (expr && (INPUT_PATH_NAME.test(joined) || traced) && fromInput && !joinConfined) {
        joinLines.add(line);
        if (target) joinedNames.add(`${fnHere?.start ?? -1}:${target}`);
        findings.push({
          kind: 'injection',
          line,
          ...snippet,
          description: `Path joined from caller input (${joined}) with no containment check — "../" escapes the base directory (path traversal)`,
        });
      }
    }
  }

  // Statement-level: exec sinks (a call may span lines), with tool-input tracing.
  stmts.forEach((stmt, i) => {
    const text = rewrite(stmt.text, stmt.line);
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
        ...cutLine((lineText.get(stmt.line) ?? '').trim()),
        description: `${sink}() call detected`,
        ...(command ? { command } : {}),
        ...(dynamic ? { dynamic } : {}),
        ...(DECODES.test(args) ? { decoded: true } : {}),
        ...(from ? { toolInput: names.get(from) } : {}),
      };
      findings.push(finding);

      let covered = false;
      for (let l = stmt.line; l <= stmt.last && !covered; l++) covered = injectedLines.has(l);
      if (!covered) {
        const shell = /\bshell\s*=\s*True\b/.test(args) || /^(?:os\.(?:system|popen)|asyncio\.create_subprocess_shell|subprocess\.(?:getoutput|getstatusoutput)|commands\.getoutput)$/.test(sink);
        if (from) {
          findings.push({
            kind: 'injection',
            line: stmt.line,
            snippet: finding.snippet,
            ...(finding.sourceLine !== undefined ? { sourceLine: finding.sourceLine } : {}),
            description: `${sink}() runs a command built from tool input (${names.get(from)})${shell ? ' through a shell' : ''} — command injection`,
          });
        } else if (shell && stmt.last > stmt.line && /^\s*(?:f["']|(?![rRbBuU]?["'])[A-Za-z_])/.test(args)) {
          findings.push({ kind: 'injection', line: stmt.line, snippet: finding.snippet, ...(finding.sourceLine !== undefined ? { sourceLine: finding.sourceLine } : {}), description: 'Dynamic command run with shell=True — command injection' });
        }
      }
      break;
    }
  });

  // Statement-level: a file read, written or listed at a path tool input
  // names, unless that path was confined to a base directory before the call
  {
    const pathBound = new Set(pathNames);
    if (!touchesFiles) for (const m of code.matchAll(PATH_BINDING)) pathBound.add(m[1]);
    // Helpers that return a path already reported at its join: what comes
    // back through them is that flaw, reported once
    const joinReturners = new Set<string>();
    for (const fn of fns) {
      if (!passing.has(fn.name)) continue;
      for (let i = fn.start + 1; i < fn.end && !joinReturners.has(fn.name); i++) {
        if (fnAt(i) !== fn || !/^\s*return\b/.test(stmts[i].text)) continue;
        let joined = identifiersOf(stmts[i].text).some((n) => joinedNames.has(`${fn.start}:${n}`));
        for (let l = stmts[i].line; l <= stmts[i].last && !joined; l++) joined = joinLines.has(l);
        if (joined) joinReturners.add(fn.name);
      }
    }
    const unjoined = new Map([...passing].filter(([name]) => !joinReturners.has(name)));
    stmts.forEach((stmt, i) => {
      const fn = fnAt(i);
      const names = fn ? tainted.get(fn)! : undefined;
      if (!fn || !names || names.size === 0) return;
      for (let l = stmt.line; l <= stmt.last; l++) if (joinLines.has(l)) return;
      const text = rewrite(stmt.text, stmt.line);
      for (const call of pythonFileCalls(text, pathBound)) {
        const confinedHere = confinedIn.get(fn);
        const from = call.paths.map((p) => dataPart(p, unjoined)).flatMap((p) => [...names.keys()].filter((n) => mentions(p, n)))
          .find((n) => !confinedBefore(confinedHere, n, names.get(n), i));
        if (from === undefined) continue;
        // Derived from a path already reported at its join
        const chain = names.get(from)!.split(' ← ');
        if (chain.some((n) => joinedNames.has(`${fn.start}:${n}`) || (n.endsWith('()') && joinReturners.has(n.slice(0, -2))))) continue;
        // unlink/remove/rmdir/rmtree delete what they are given
        const deletes = call.op === 'write' && DELETE_CALL.test(call.sink);
        const verb = call.op === 'read' ? 'reads' : deletes ? 'deletes' : call.op === 'write' ? 'writes' : 'lists or stats';
        // the physical line of the call in a statement over several lines
        const method = call.sink.slice(call.sink.lastIndexOf('.') + 1);
        let line = stmt.line;
        for (let l = stmt.line; l <= stmt.last; l++) {
          if (new RegExp(String.raw`(?<![\w])${method}\s*\(`).test(blankStrings(lineText.get(l) ?? ''))) { line = l; break; }
        }
        findings.push({
          kind: 'file-path',
          fileOp: call.op,
          line,
          ...cutLine((lineText.get(line) ?? '').trim()),
          toolInput: names.get(from),
          description: call.op === 'meta'
            ? `${call.sink}() takes its path from tool input (${names.get(from)}) with no base-directory check — the tool reaches any path on the host`
            : `${call.sink}() ${verb} a path taken from tool input (${names.get(from)}) with no containment check — the caller can ${deletes ? 'delete' : call.op} any file the server can (path traversal)`,
        });
        break;
      }
    });
  }

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
  const lineText = new Map(lines.map((l) => [l.line, l.text]));
  for (const stmt of statements(lines)) {
    const text = rewrite(stmt.text, stmt.line);
    const snippet = (lineText.get(stmt.line) ?? '').trim().slice(0, 120);
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

const ENV_READ = /\bos\.(?:environ\s*\[\s*[rRuU]?(["'])([^"']+)\1\s*\]|environ\.get\s*\(\s*[rRuU]?(["'])([^"']+)\3|getenv\s*\(\s*[rRuU]?(["'])([^"']+)\5)/g;

/** `os.environ["KEY"]`, `os.environ.get("KEY")`, `os.getenv("KEY", …)` → KEY (the first). */
function inlineEnvName(text: string): string | undefined {
  return inlineEnvNames(text)[0];
}

/** Every environment name `text` reads, in order. */
function inlineEnvNames(text: string): string[] {
  return [...text.matchAll(ENV_READ)].map((m) => m[2] ?? m[4] ?? m[6]);
}

/** The name to judge a value read from several by: a credential whose home is known, else any credential, else the first. */
function sensitiveEnvName(names: string[]): string | undefined {
  return names.find((n) => ownedCredential(n)) ?? names.find((n) => credentialEnvName(n)) ?? names[0];
}

/**
 * `text` with string literals emptied except for the `{…}` parts an f-string
 * (or `.format` template) fills in: `"k"` in `params={"k": key}` is a dict
 * key, not the variable `k`; `f"…?k={key}"` sends `key`.
 */
function codeOnly(text: string): string {
  return mapStringLiterals(text, (lit) => {
    if (lit.length < 2) return lit;
    const holes = lit.slice(1, -1).match(/\{[^{}]*\}/g) ?? [];
    return lit[0] + holes.join(' ') + ' ' + lit[lit.length - 1];
  });
}

/**
 * What a name in a request URL stands for, by Python's scoping: a name bound
 * exactly once in its scope by a plain `name = value` — module-level
 * (`API_URL = "https://api.openai.com/v1"`) or inside the function
 * (`url = "https://api.openai.com/v1/" + path`) — stands for that value.
 * Any other binding of it in that scope makes it unknown: a second
 * assignment, `+=`, a tuple target (`API, X = …`), a walrus (`(API := …)`),
 * `for`/`as`/`import`/`del`, a parameter, a `global API` rebinding from a
 * function, or a module-level assignment nested in a block or class. Code
 * that rebinds names dynamically (`globals()`, `setattr`, `exec`) has no
 * module-level constants. Returns the value's expression text, looked up
 * from the functions around a statement (outermost first).
 */
type UrlConstants = ((name: string, enclosing: readonly PyFunction[]) => string | undefined) & {
  /** The scope whose binding of `name` a statement inside `enclosing` sees (undefined: module level). */
  scopeOf(name: string, enclosing: readonly PyFunction[]): PyFunction | undefined;
  /** The innermost function of each statement. */
  owner: ReadonlyArray<PyFunction | undefined>;
};

function scopedConstants(stmts: CodeLine[], fns: PyFunction[]): UrlConstants {
  // innermost function of each statement (a `def` line belongs to the scope around it)
  const owner: Array<PyFunction | undefined> = new Array(stmts.length).fill(undefined);
  for (const f of fns) for (let i = f.start + 1; i < f.end; i++) owner[i] = f;
  // per scope and name: the value of its only plain binding, or null once bound any other way or twice
  const bindings = new Map<PyFunction | undefined, Map<string, string | null>>();
  const bind = (scope: PyFunction | undefined, name: string, value: string | undefined) => {
    let m = bindings.get(scope);
    if (!m) bindings.set(scope, (m = new Map()));
    // undefined: a binding that isn't a plain `name = value`
    m.set(name, m.has(name) || value === undefined ? null : value);
  };
  const globals = new Map<PyFunction, Set<string>>();
  for (let i = 0; i < stmts.length; i++) {
    const f = owner[i];
    const g = /^\s*global\s+([\w\s,]+)$/.exec(stmts[i].text);
    if (g && f) for (const n of g[1].split(',')) globals.set(f, new Set([...(globals.get(f) ?? []), n.trim()]));
  }
  let dynamic = false;
  for (let i = 0; i < stmts.length; i++) {
    const text = stmts[i].text;
    const f = owner[i];
    const scopeOf = (name: string) => (f && globals.get(f)?.has(name) ? undefined : f);
    const code = blankStrings(text);
    if (/\b(?:globals|vars|locals)\s*\(|\bsetattr\s*\(|__dict__|\b__builtins__\b|(?<![\w.])exec\s*\(/.test(code)) dynamic = true;
    // (each pattern linear: a statement can be one 100 KB line)
    for (const w of code.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*:=/g)) bind(scopeOf(w[1]), w[1], undefined);
    const names = (t: string) => t.match(/(?<![\w.])[A-Za-z_]\w*/g) ?? [];
    for (const b of code.matchAll(/\bfor\b([^:\n]{0,200})/g)) {
      const at = b[1].search(/\sin\b/);
      for (const n of names(at < 0 ? '' : b[1].slice(0, at))) bind(scopeOf(n), n, undefined);
    }
    for (const b of code.matchAll(/\bas\s+\(?([\w, ]{1,200})/g)) for (const n of names(b[1])) bind(scopeOf(n), n, undefined);
    for (const b of code.matchAll(/^\s*(?:del|nonlocal|global)\s([\w\s,]*)/g)) for (const n of names(b[1])) bind(scopeOf(n), n, undefined);
    const imp = /^\s*(?:from\s+\S+\s+)?import\s+(.+)$/.exec(code);
    if (imp) for (const n of names(imp[1])) bind(scopeOf(n), n, undefined);
    const aug = /^\s*([A-Za-z_]\w*)\s*(?:\/\/|\*\*|>>|<<|[-+*\/%&|^@])=/.exec(code);
    if (aug) bind(scopeOf(aug[1]), aug[1], undefined);
    // `a = b = v`, `a, b = …`, `(a, b) = …`, `[a] = …`: every target bound, none a constant
    const plain = /^(\s*)([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]*)$/.exec(text);
    const eq = /(?<![=!<>])=(?!=)/.exec(code);
    const targets = eq ? code.slice(0, eq.index) : '';
    if (plain && !/^\s*[A-Za-z_]\w*\s*=(?!=)/.test(blankStrings(plain[3]))) {
      bind(scopeOf(plain[2]), plain[2], f || plain[1] === '' ? plain[3].trim() : undefined);
    } else if (!aug && /^[\w\s,()[\]*.]+$/.test(targets) && /^\s*[([]|,/.test(targets) && !/[\w.\]]\s*\(/.test(targets)) {
      for (const n of names(targets)) bind(scopeOf(n), n, undefined);
    }
  }
  for (const f of fns) for (const p of f.params) bind(f, p, undefined);
  const lookup = (name: string, enclosing: readonly PyFunction[]): string | undefined => {
    for (let i = enclosing.length - 1; i >= 0; i--) {
      const scope = bindings.get(enclosing[i]);
      if (scope?.has(name)) return scope.get(name) ?? undefined;
    }
    return dynamic ? undefined : bindings.get(undefined)?.get(name) ?? undefined;
  };
  const scopeOf = (name: string, enclosing: readonly PyFunction[]): PyFunction | undefined => {
    for (let i = enclosing.length - 1; i >= 0; i--) if (bindings.get(enclosing[i])?.has(name)) return enclosing[i];
    return undefined;
  };
  return Object.assign(lookup, { scopeOf, owner });
}

/**
 * Code that sends every request of the file somewhere else, whatever URL a
 * call names: a patched network module or client method
 * (`socket.getaddrinfo = …`, `requests.Session.send = …`), or proxy / CA
 * settings written to the environment (`os.environ["HTTPS_PROXY"] = …`,
 * `REQUESTS_CA_BUNDLE`). A vendor key in its own API's headers then goes
 * wherever that points.
 */
const PY_GLOBAL_REDIRECT = new RegExp([
  String.raw`^\s*(?:requests|httpx|urllib3?|urllib|socket|ssl|http|aiohttp|certifi|dns|httplib2)(?:\.\w+)+\s*=(?!=)`,
  String.raw`^\s*(?!self\b|cls\b)[A-Za-z_]\w*(?:\.\w+)*\.(?:send|request|urlopen|getaddrinfo|create_connection|_create_default_https_context|create_default_context|merge_environment_settings|get_adapter|rebuild_proxies|resolve|connect)\s*=(?!=)`,
  String.raw`\bsetattr\s*\(\s*(?:requests|httpx|urllib3?|urllib|socket|ssl|http|aiohttp)\b`,
  String.raw`\bos\.environ\s*\[\s*[rRuU]?["'][^"']*(?:PROXY|CA_BUNDLE|SSL_CERT|HTTPSVERIFY)[^"']*["']\s*\]\s*=(?!=)`,
  String.raw`\bos\.(?:environ\.(?:update|setdefault)|putenv)\s*\([^\n]*(?:PROXY|CA_BUNDLE|SSL_CERT|HTTPSVERIFY)`,
].join('|'), 'im');

/** Options that send a request elsewhere or through someone else, or hide what is passed (`**kwargs`). */
const PY_REDIRECT_KEYWORDS = /^(?:proxies|proxy|verify|transport|mounts|base_url|hooks|cert|unix_socket|connector)$/;

/**
 * A credential sent to the API it belongs to: an environment value named
 * for a vendor (`OPENAI_API_KEY`) that appears only in `headers=` or `auth=`
 * of a request to a literal https URL on that vendor's domain, with nothing
 * redirecting it. The same key in the URL, params, cookies or body, or sent
 * to any other host, is a leak.
 */
/**
 * A request to the API of the vendor `envName` names: its URL (literal,
 * constants, f-string) on that vendor's https host, nothing in the call
 * redirecting it. Undefined otherwise — and for a signing secret, which is
 * never how a request authenticates (`GITHUB_WEBHOOK_SECRET`).
 */
function vendorRequest(positional: string[], keywords: Map<string, string>, envName: string | undefined,
  urlConstant: (name: string) => string | undefined, urlIndex: number):
  { parts: Array<string | { code: string; before: string }>; prefix: string; computed: Array<{ code: string; before: string }> } | undefined {
  const domains = signingSecret(envName) ? undefined : vendorApiDomains(envName);
  if (!domains) return undefined;
  const parts = pyUrlParts((positional[urlIndex] ?? keywords.get('url') ?? '').trim(), urlConstant);
  // the static text before the first computed part (an interpolated constant is several strings)
  const firstComputed = parts.findIndex((x) => typeof x !== 'string');
  const prefix = (firstComputed < 0 ? parts : parts.slice(0, firstComputed)).join('');
  const computed = parts.filter((x): x is { code: string; before: string } => typeof x !== 'string');
  if (computed.length > 0) {
    const origin = staticOrigin(prefix);
    if (!origin || !onVendorHost(origin, domains)) return undefined;
  } else if (!onVendorHost(parts.join(''), domains)) return undefined;
  if (positional.some((p) => p.startsWith('*')) || [...keywords.keys()].some((k) => PY_REDIRECT_KEYWORDS.test(k))) return undefined;
  return { parts, prefix, computed };
}

function ownVendorApi(positional: string[], keywords: Map<string, string>, source: string, envName: string | undefined,
  urlConstant: (name: string) => string | undefined, urlIndex = 0): boolean {
  const urlKey = positional.length > urlIndex ? undefined : 'url';
  const target = vendorRequest(positional, keywords, envName, urlConstant, urlIndex);
  if (!target) return false;
  const { parts, prefix, computed } = target;
  const seen = (t: string) => (/^[A-Za-z_]\w*$/.test(source) ? mentions(codeOnly(t), source) : t.includes(source));
  // The value itself, maybe URL-quoted (`quote(key)`)
  const isSource = (t: string) => t.trim().replace(/^(?:urllib\.parse\.)?quote(?:_plus)?\s*\(([\s\S]*)\)$/, '$1').trim() === source;
  // Where the vendor takes its key: headers, auth, and the URL/query slots it documents
  const carrying = ['headers', 'auth'].map((k) => keywords.get(k) ?? '');
  // (`request(method, url)`: the method is a positional too)
  const rest = [...positional.slice(urlIndex + 1), ...positional.slice(0, urlIndex).filter((x) => !/^[rRuU]?(["'])[A-Za-z]+\1$/.test(x.trim())), ...[...keywords].filter(([k]) => !['headers', 'auth', 'params', urlKey].includes(k)).map(([, v]) => v)];
  for (const c of computed) (isSource(c.code) && vendorUrlSlot(envName, c.before) ? carrying : rest).push(c.code);
  const params = keywords.get('params')?.trim() ?? '';
  const dict = params.startsWith('{') && params.endsWith('}') ? topLevelParts(params.slice(1, -1)) : undefined;
  if (dict === undefined) rest.push(params);
  for (const entry of dict ?? []) {
    const kv = /^\s*[rRuU]?(["'])([^"']+)\1\s*:([\s\S]*)$/.exec(entry);
    // with the request's own origin, so a storage host's query (access logs) isn't a slot
    const origin = staticOrigin(prefix) ?? parts.join('');
    (kv && isSource(kv[3]) && vendorUrlSlot(envName, `${/^https:\/\/[^/?#@]+/i.exec(origin)?.[0] ?? ''}/?${kv[2]}=`) ? carrying : rest).push(kv ? kv[3] : entry);
  }
  return carrying.some(seen) && !rest.some(seen);
}

/**
 * A request URL as static text and computed parts (with the static text
 * before each): a string literal, an f-string's literal text and `{…}`
 * fields, a module-level string constant, or a `+` chain of them.
 */
function pyUrlParts(expr: string, urlConstant: (name: string) => string | undefined): Array<string | { code: string; before: string }> {
  const out: Array<string | { code: string; before: string }> = [];
  let before = '';
  const add = (part: string | { code: string }) => {
    if (typeof part === 'string') {
      before += part;
      out.push(part);
    } else out.push({ code: part.code, before });
  };
  walkUrl(expr, urlConstant, add, 0);
  return out;
}

function walkUrl(expr: string, urlConstant: (name: string) => string | undefined, add: (part: string | { code: string }) => void, level: number): void {
  // Split on top-level `+` (outside strings and brackets)
  const blank = blankStrings(expr);
  const pieces: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < blank.length; i++) {
    const c = blank[i];
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === '+' && depth === 0) {
      pieces.push(expr.slice(from, i));
      from = i + 1;
    }
  }
  pieces.push(expr.slice(from));
  for (const raw of pieces) {
    const piece = raw.trim();
    const lit = /^([rRuUfF]{0,2})(["'])([\s\S]*)\2$/.exec(piece);
    if (lit && !/[\n]/.test(lit[3]) && !lit[3].includes(lit[2])) {
      if (!/f/i.test(lit[1])) {
        add(lit[3]);
        continue;
      }
      // f-string: literal text and `{expr[!conv][:spec]}` fields
      let text = '';
      for (const m of lit[3].matchAll(/\{\{|\}\}|\{([^{}]*)\}|[^{}]+|[{}]/g)) {
        if (m[0] === '{{' || m[0] === '}}') text += m[0][0];
        else if (m[1] !== undefined) {
          if (text) add(text);
          text = '';
          // `f"{BASE}/models"`: a field resolved like a `+` operand
          const field = m[1].replace(/(?:![rsa])?(?::[^:]*)?$/, '');
          if (level < 8) walkUrl(field, urlConstant, add, level + 1);
          else add({ code: field });
        } else text += m[0];
      }
      if (text) add(text);
      continue;
    }
    // a name bound once to a value (`url = "https://…" + path`), followed a few levels
    const unparen = piece.replace(/^\(\s*([\s\S]*?)\s*\)$/, '$1');
    // (only a URL being built from text: a name holding a value read elsewhere — an env credential — is itself the part)
    const bound = /^[A-Za-z_]\w*$/.test(unparen) && level < 8 ? urlConstant(unparen) : undefined;
    const constant = bound !== undefined && /^\s*\(?\s*[rRuUfF]{0,2}["']|\+\s*[rRuUfF]{0,2}["']/.test(blankStrings(bound)) ? bound : undefined;
    if (constant !== undefined) walkUrl(constant, urlConstant, add, level + 1);
    else add({ code: piece });
  }
}

const SESSION_CTOR = /\b(?:requests\.(?:Session|session)|httpx\.(?:Async)?Client|aiohttp\.ClientSession|urllib3\.PoolManager)\s*\(/;
const SESSION_REDIRECT = /^(?:proxies|proxy|verify|mount|mounts|hooks|event_hooks|adapters|trust_env|cert|transport|base_url|connector)$/;

/**
 * Client sessions the file opens (`s = requests.Session()`, `with
 * httpx.Client() as c:`, `self.http = aiohttp.ClientSession()`), as a
 * pattern for their request calls (`s.get(…)` is a request like
 * `requests.get(…)`), and the ones sent elsewhere or unverified — by their
 * constructor (`proxies=`, `verify=`, `base_url=`, `transport=`) or later
 * (`s.proxies = …`, `s.verify = False`, `s.mount(…)`).
 */
function clientSessions(texts: string[], owner: ReadonlyArray<PyFunction | undefined>):
  { calls?: RegExp; redirected: Set<string>; scopes: Map<string, Set<PyFunction | undefined>> } {
  const names = new Set<string>();
  const redirected = new Set<string>();
  // where each session name is bound: a same-named variable in another scope is something else
  const scopes = new Map<string, Set<PyFunction | undefined>>();
  for (const [i, text] of texts.entries()) {
    const ctor = SESSION_CTOR.exec(text);
    if (!ctor) continue;
    const args = callArgs(text, ctor.index + ctor[0].length - 1);
    const assigned = /^\s*([A-Za-z_][\w.]*)\s*(?::[^=]+)?=(?!=)\s*(?:await\s+)?$/.exec(text.slice(0, ctor.index));
    const after = text.slice(ctor.index + ctor[0].length + args.length + 1);
    const name = assigned?.[1] ?? /^\s*as\s+([A-Za-z_]\w*)/.exec(after)?.[1];
    if (!name) continue;
    names.add(name);
    scopes.set(name, new Set([...(scopes.get(name) ?? []), owner[i]]));
    if ([...splitArgs(args).keywords.keys()].some((k) => SESSION_REDIRECT.test(k))) redirected.add(name);
  }
  if (names.size === 0) return { redirected, scopes };
  const alt = [...names].map((n) => n.replace(/\./g, '\\.')).join('|');
  const later = new RegExp(String.raw`^\s*(${alt})\s*\.\s*(\w+)\s*(?:=(?!=)|\()`);
  for (const text of texts) {
    const m = later.exec(text);
    if (m && SESSION_REDIRECT.test(m[2])) redirected.add(m[1]);
  }
  return { calls: new RegExp(String.raw`(?<![\w.])(?:${alt})\s*\.\s*(get|post|put|patch|delete|head|options|request|stream)\s*\(`), redirected, scopes };
}

/** Where a session carries credentials for every request: `s.headers.update(…)`, `s.headers[k] = …`, `s.auth = …`, `Client(headers=…)`. */
type SessionSlot = 'headers' | 'other';

/**
 * Patterns for a session `name`: a statement attaching values to it — its
 * headers or auth (`headers` slot), or its params/cookies (`other`) — and
 * one binding it (`s = …`, `as s`).
 */
function sessionPatterns(name: string): { attach: RegExp; binds: RegExp } {
  const n = name.replace(/\./g, '\\.');
  return {
    attach: new RegExp(String.raw`^\s*${n}\s*\.\s*(headers|auth|params|cookies)\s*(?:\[[^\]]*\]\s*)?(?:=(?!=)|\.\s*(?:update|set|setdefault|__setitem__)\s*\()\s*([\s\S]*)$`),
    binds: new RegExp(String.raw`(?:^\s*${n}\s*(?::[^=]+)?=|\bas\s+${n}\b)`),
  };
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
 * API it belongs to) is exfiltration only in a request body, in the argv of
 * a network program, or — when it is a vendor's key, a signing secret or a
 * database credential (ownedCredential) — anywhere in a request but the
 * vendor's own API headers, and for any other credential anywhere but the
 * request's headers and `auth`; file contents and the whole environment,
 * anywhere.
 */
export function analyzePythonDataFlow(code: string): DataFlowResult[] {
  const out: DataFlowResult[] = [];
  const rewrite = aliasRewriter(code);
  const lines = codeLines(code);
  const stmts = statements(lines);
  const fns = functionsOf(stmts);
  const constants = stringConstantNames(stmts, fns);
  const urlConstants = scopedConstants(stmts, fns);
  // the file redirects every request (patched client, proxy settings): no request is the vendor's own
  const rewritten = stmts.map((st) => rewrite(st.text, st.line));
  const redirectsAll = PY_GLOBAL_REDIRECT.test(rewritten.join('\n'));
  const sessions = clientSessions(rewritten, urlConstants.owner);
  // what each session carries into every request it makes (`s.headers.update({…})`, `Client(headers=…)`)
  const sessionCreds = new Map<string, Array<{ source: string; kind: SourceKind; envName?: string; slot: SessionSlot }>>();
  const sessionRes = new Map([...sessions.scopes.keys()].map((n) => [n, sessionPatterns(n)]));
  const scopes = new Map<PyFunction | undefined, Map<string, SourceKind>>([[undefined, new Map()]]);
  const scopeOf = (fn: PyFunction | undefined): Map<string, SourceKind> => {
    let m = scopes.get(fn);
    if (!m) scopes.set(fn, (m = new Map()));
    return m;
  };
  const report = (kind: SourceKind): 'file' | 'env' => (kind === 'file' ? 'file' : 'env');
  // The environment variable a tracked name was read from (`key = os.environ["OPENAI_API_KEY"]`), per scope
  const envNameScopes = new Map<PyFunction | undefined, Map<string, string>>([[undefined, new Map()]]);
  const envNameScope = (fn: PyFunction | undefined): Map<string, string> => {
    let m = envNameScopes.get(fn);
    if (!m) envNameScopes.set(fn, (m = new Map()));
    return m;
  };
  // Everything per statement is proportional to that statement: scanning all
  // lines, all functions or every tracked name each time made a file of
  // 40 000 statements take minutes.
  const lineText = new Map(lines.map((l) => [l.line, l.text]));
  const enclosing: PyFunction[] = []; // functions around the statement, outermost first
  let nextFn = 0;

  stmts.forEach((stmt, i) => {
    const text = rewrite(stmt.text, stmt.line);
    const snippet = cutLine((lineText.get(stmt.line) ?? '').trim());
    // Functions nest: leave the ones that ended, enter the ones whose `def` precedes
    while (enclosing.length > 0 && i >= enclosing[enclosing.length - 1].end) enclosing.pop();
    while (nextFn < fns.length && fns[nextFn].start < i) {
      const f = fns[nextFn++];
      if (i < f.end) enclosing.push(f);
    }
    // Tracked names this statement mentions — module level, then enclosing
    // functions, the innermost binding winning
    const visible = new Map<string, SourceKind>();
    const visibleEnvName = new Map<string, string>();
    for (const id of new Set(text.match(/[A-Za-z_]\w*/g) ?? [])) {
      let kind = scopes.get(undefined)?.get(id);
      let envName = kind === undefined ? undefined : envNameScopes.get(undefined)?.get(id);
      for (const f of enclosing) {
        const k = scopes.get(f)?.get(id);
        if (k !== undefined) {
          kind = k;
          envName = envNameScopes.get(f)?.get(id);
        }
      }
      if (kind !== undefined) visible.set(id, kind);
      if (envName !== undefined) visibleEnvName.set(id, envName);
    }
    const local = scopeOf(enclosing.at(-1));
    const localEnvNames = envNameScope(enclosing.at(-1));

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
        type: 'eval-exec', line: stmt.line, ...snippet, description: `${sink}() call detected`,
        ...(command ? { command } : {}), ...(dynamic ? { dynamic } : {}), ...(DECODES.test(args) ? { decoded: true } : {}),
        ...(noShell ? { noShell } : {}), ...(fixedCode ? { fixedCode } : {}),
      });
      if (sink !== 'eval' && sink !== 'exec') {
        // What the process gets: its argv and stdin, not env=/cwd=/timeout=
        const sent = [...positional, keywords.get('args') ?? '', keywords.get('input') ?? ''].join(',');
        const flows = [...[...visible].filter(([v]) => mentions(sent, v)), ...inlineSources(sent)];
        for (const [v, kind] of flows) {
          if (kind === 'env' && !(program && NETWORK_PROGRAM.test(program))) continue;
          out.push({ type: 'source-to-sink', source: v, sourceKind: report(kind), ...(kind === 'envall' ? { wholeEnv: true } : {}), sink, line: stmt.line, ...snippet, description: `Data flows from "${v}" into process execution "${sink}"` });
        }
      }
      break;
    }

    if (/\bopen\s*\(|\bPath\s*\(|expanduser\s*\(/.test(text)) {
      for (const m of text.matchAll(STRING_LITERAL)) {
        if (classifySensitivePath(m[1]).length > 0) {
          out.push({ type: 'fs-access', source: m[1], line: stmt.line, ...snippet, description: `Reading sensitive path: ${m[1]}` });
          break;
        }
      }
    }

    // Values attached to a session: by its constructor, or set on it later
    for (const [name, re] of sessionRes) {
      const attached: Array<{ slot: SessionSlot; expr: string }> = [];
      const set = re.attach.exec(text);
      if (set) attached.push({ slot: set[1] === 'headers' || set[1] === 'auth' ? 'headers' : 'other', expr: set[2] });
      const ctor = SESSION_CTOR.exec(text);
      if (ctor && re.binds.test(text)) {
        const kw = splitArgs(callArgs(text, ctor.index + ctor[0].length - 1)).keywords;
        for (const [k, v] of kw) if (/^(?:headers|auth|params|cookies)$/.test(k)) attached.push({ slot: k === 'headers' || k === 'auth' ? 'headers' : 'other', expr: v });
      }
      for (const { slot, expr } of attached) {
        const creds = sessionCreds.get(name) ?? [];
        for (const [v, kind] of visible) if (mentions(expr, v)) creds.push({ source: v, kind, envName: visibleEnvName.get(v), slot });
        for (const [v, kind] of inlineSources(expr)) creds.push({ source: v, kind, envName: kind === 'env' ? inlineEnvName(v) : undefined, slot });
        sessionCreds.set(name, creds);
      }
    }

    let net = NETWORK_CALLS.exec(text);
    if (!net && sessions.calls) {
      // a session call — of the session, not a same-named variable of another scope (`s = {}` in a function)
      const m = sessions.calls.exec(text);
      const name = m && /^([\w.]+?)\s*\.\s*\w+\s*\($/.exec(m[0])?.[1];
      if (m && name && (name.includes('.') || sessions.scopes.get(name)?.has(urlConstants.scopeOf(name, enclosing)))) net = m;
    }
    // Building a client or connection (`httpx.Client(base_url=url)`) sends nothing
    const constructs = net !== null && CLIENT_CONSTRUCTORS.test(net[1] ?? (/\w+/.exec(net[0])?.[0] ?? ''));
    if (net && !constructs) {
      // (sinkObject: the client the call goes through — `requests`, `smtplib`, a session `s`)
      const via = net[0].replace(/\s*\($/, '').replace(/\s+/g, '');
      const client = /^([\w.]+?)\.\w+$/.exec(via)?.[1] ?? via;
      let { positional, keywords } = splitArgs(callArgs(text, text.indexOf('(', net.index)));
      const all = [...positional, ...keywords.values()].join(',');
      // A request body, or the payload of a raw socket send
      const rawSend = /^(?:send|sendall|sendto|sendmail|write)$/.test(net[1] ?? '');
      // `urlopen(Request(url, data, headers=…))`: the request is the inner call
      const inner = rawSend ? null : /^(?:urllib\.request\.)?Request\s*\(/.exec(positional[0] ?? '');
      if (inner) ({ positional, keywords } = splitArgs(callArgs(positional[0], inner[0].length - 1)));
      // `request(method, url, …)`: the URL is the second argument
      const urlIndex = !inner && net[1] === 'request' && /^[rRuU]?(["'])[A-Za-z]+\1$/.test(positional[0]?.trim() ?? '') ? 1 : 0;
      const body = [...(rawSend ? positional : positional.slice(urlIndex + 1)), ...['data', 'json', 'files', 'content', 'body', 'msg'].map((k) => keywords.get(k) ?? '')].join(',');
      // Elsewhere in a request — its URL, headers, params, auth, cookies — a
      // single environment value counts when it is a credential whose home is
      // known (a vendor's key, a signing secret, a database credential),
      // unless it is the vendor's key in the headers of that vendor's own API
      // (ownVendorApi); a credential tied to no vendor (`API_KEY`, `MY_TOKEN`)
      // counts outside the headers and `auth` — there it is how the skill
      // authenticates to whatever API it calls
      const request = !rawSend && !/^(?:connect|login|starttls|ehlo|helo|quit|close)$/.test(net[1] ?? '');
      const outside = codeOnly(all);
      const outsideAuthRaw = [...positional, ...[...keywords].filter(([k]) => k !== 'headers' && k !== 'auth').map(([, v]) => v)].join(',');
      const outsideAuth = codeOnly(outsideAuthRaw);
      const urlConstant = (name: string) => urlConstants(name, enclosing);
      const own = (v: string, name: string | undefined) => !redirectsAll && !sessions.redirected.has(client) && ownVendorApi(positional, keywords, v, name, urlConstant, urlIndex);
      const outsideBody = (name: string | undefined, inOutside: boolean, inOutsideAuth: boolean, v: string): boolean => request
        && (ownedCredential(name) ? inOutside && !own(v, name) : name !== undefined && credentialEnvName(name) && inOutsideAuth);
      const flows: Array<[string, SourceKind]> = [
        ...[...visible].filter(([v, k]) => (k !== 'env' ? mentions(all, v)
          : mentions(body, v) || outsideBody(visibleEnvName.get(v), mentions(outside, v), mentions(outsideAuth, v), v))),
        ...inlineSources(all).filter(([, kind]) => kind !== 'env'),
        ...inlineSources(body).filter(([, kind]) => kind === 'env'),
        ...inlineSources(all).filter(([v, kind]) => kind === 'env' && !body.includes(v)
          && outsideBody(inlineEnvName(v), true, outsideAuthRaw.includes(v), v)),
      ];
      // What the session itself carries: judged like the same value in this request's headers (or params)
      for (const c of request ? sessionCreds.get(client) ?? [] : []) {
        if (flows.some(([v]) => v === c.source)) continue;
        if (c.kind === 'env') {
          if (ownedCredential(c.envName)) {
            if (c.slot === 'headers' && !redirectsAll && !sessions.redirected.has(client)
              && vendorRequest(positional, keywords, c.envName, urlConstant, urlIndex)) continue;
          } else if (c.envName === undefined || !credentialEnvName(c.envName) || c.slot === 'headers') continue;
        }
        flows.push([c.source, c.kind]);
      }
      for (const [v, kind] of flows) {
        out.push({
          type: 'source-to-sink', source: v, sourceKind: report(kind), ...(kind === 'envall' ? { wholeEnv: true } : {}),
          sink: net[1] ?? 'urlopen', sinkObject: client, line: stmt.line, ...snippet, description: `Data flows from "${v}" to network sink "${via}"`,
        });
      }
    }

    // Track what assignments hold: file contents, environment values, or
    // values derived from either; a plain reassignment clears the name.
    const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]+)$/.exec(text);
    if (assign) {
      const [, target, rhs] = assign;
      const values = rhs.replace(/\b[A-Za-z_]\w*\s*=(?!=)/g, ' ');
      localEnvNames.delete(target);
      if (FILE_READS.test(rhs)) local.set(target, 'file');
      else if (/\bos\.environ\b(?!\s*(?:\[|\.get\b|\.setdefault\b|\.pop\b))/.test(rhs)) local.set(target, 'envall');
      else if (/\bos\.(?:environ|getenv)\b/.test(rhs)) {
        local.set(target, 'env');
        // `os.environ.get("NOPE") or os.environ["AWS_SECRET_ACCESS_KEY"]`: the most sensitive of the names
        const name = sensitiveEnvName([...inlineEnvNames(rhs), ...[...visible.keys()].filter((v) => mentions(values, v)).flatMap((v) => visibleEnvName.get(v) ?? [])]);
        if (name !== undefined) localEnvNames.set(target, name);
      } else {
        const from = [...visible].filter(([v]) => mentions(values, v));
        if (from.length > 0) {
          local.set(target, from.find(([, k]) => k !== 'env')?.[1] ?? from[0][1]);
          const name = sensitiveEnvName(from.flatMap(([v]) => visibleEnvName.get(v) ?? []));
          if (name !== undefined) localEnvNames.set(target, name);
        } else local.delete(target);
      }
    }
    // `with open(p) as f:` binds a file handle
    const withOpen = /\bwith\s+open\s*\([^)]*\)\s+as\s+(\w+)/.exec(text);
    if (withOpen) local.set(withOpen[1], 'file');
  });
  return out;
}

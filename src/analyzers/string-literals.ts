/**
 * String contents of JavaScript source, line by line, with where each string
 * sits — for checks that judge *text* (MCP-034 directives) and must not read
 * code (`system: prompt.system` is an object key, not a role-spoofing prefix).
 */

import _traverse from '@babel/traverse';
import type { NodePath } from '@babel/traverse';
import { parseJs, sourceChunks } from './js-parse.js';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface StringLine {
  /** 1-based source line of this line of the string. */
  line: number;
  text: string;
  /**
   * The string is a tool/parameter description (`description: "…"`,
   * `.describe("…")`, the description argument of `server.tool(name, "…", …)`)
   * — read by the model when choosing tools, which is MCP-024's surface.
   */
  description: boolean;
  /** Prompt content (Python: assigned to a `*prompt*` name) — served by an MCP
   *  prompt the user selects, not returned by a tool call. */
  prompt?: boolean;
}

const TOOL_REGISTRARS = new Set(['tool', 'registerTool', 'prompt', 'registerPrompt']);

function isDescription(path: NodePath): boolean {
  const parent = path.parentPath;
  if (!parent) return false;
  if (parent.isObjectProperty() && parent.node.value === path.node) {
    const key = parent.node.key;
    const name = key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : '';
    return name === 'description';
  }
  if (parent.isCallExpression()) {
    const callee = parent.node.callee;
    if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return false;
    if (callee.property.name === 'describe') return true;
    // server.tool("name", "description", schema, handler)
    return TOOL_REGISTRARS.has(callee.property.name) && parent.node.arguments[1] === path.node;
  }
  return false;
}

/** Undefined when the source doesn't parse as JavaScript. */
export function stringLines(code: string): StringLine[] | undefined {
  const out: StringLine[] = [];
  let parsedAny = false;
  for (const chunk of sourceChunks(code)) {
    const ast = parseJs(chunk.code);
    if (!ast) continue;
    parsedAny = true;
    const offset = chunk.startLine - 1;
    const push = (text: string, startLine: number, description: boolean): void => {
      const parts = text.split('\n');
      for (let i = 0; i < parts.length; i++) {
        if (parts[i].trim()) out.push({ line: offset + startLine + i, text: parts[i], description });
      }
    };
    try {
      traverse(ast, {
        StringLiteral(path) {
          // Import specifiers and object keys are names, not text.
          if (path.parentPath.isImportDeclaration() || path.parentPath.isExportDeclaration()) return;
          if (path.parentPath.isObjectProperty() && path.parentPath.node.key === path.node) return;
          push(path.node.value, path.node.loc?.start.line ?? 0, isDescription(path));
        },
        TemplateLiteral(path) {
          // Tagged templates (sql`…`, html`…`) are data for a function, still text.
          const description = isDescription(path);
          for (const quasi of path.node.quasis) {
            push(quasi.value.cooked ?? quasi.value.raw, quasi.loc?.start.line ?? 0, description);
          }
        },
      });
    } catch {
      // keep what this chunk yielded
    }
  }
  return parsedAny ? out : undefined;
}

/**
 * `code` with the source text of every string and template literal whose
 * value `mask` selects replaced by spaces (line breaks kept, so lines and
 * columns still match). Literals are found by the parser, not by pairing
 * quotes on a line: a minified bundle's template literal that runs over a
 * line break, or a quote inside another literal, puts a per-line quote scan
 * out of phase for the rest of the line. A chunk the parser can't read is
 * tokenized by `lexJsLiterals`.
 */
export function maskJsLiterals(code: string, mask: (value: string) => boolean): string {
  const spans: Array<[number, number]> = [];
  let chunkOffset = 0;
  for (const chunk of sourceChunks(code)) {
    const base = chunkOffset;
    chunkOffset += chunk.code.length + 1;
    const add = (start: number | null | undefined, end: number | null | undefined, value: string): void => {
      if (start != null && end != null && end > start && mask(value)) spans.push([base + start, base + end]);
    };
    const ast = parseJs(chunk.code);
    if (!ast) {
      for (const [start, end] of lexJsLiterals(chunk.code)) add(start, end, chunk.code.slice(start + 1, end - 1));
      continue;
    }
    try {
      traverse(ast, {
        StringLiteral(path) { add(path.node.start, path.node.end, path.node.value); },
        TemplateElement(path) { add(path.node.start, path.node.end, path.node.value.cooked ?? path.node.value.raw); },
      });
    } catch {
      // keep what this chunk yielded
    }
  }
  if (spans.length === 0) return code;
  spans.sort((a, b) => a[0] - b[0]);
  let out = '';
  let last = 0;
  for (const [start, end] of spans) {
    if (start < last) continue;
    out += code.slice(last, start) + code.slice(start, end).replace(/[^\n]/g, ' ');
    last = end;
  }
  return out + code.slice(last);
}

const REGEX_AFTER_WORD = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await', 'instanceof']);

/**
 * String and template-literal pieces of JavaScript that doesn't parse (a
 * fragment, a bundle with syntax Babel rejects), as `[start, end)` offsets
 * whose inner text (`start + 1` to `end - 1`) is the piece's raw body. A
 * small lexer rather than quote pairing: comments and regex literals
 * (`/[^A-Za-z0-9'()]+/g`) hold quotes too, a template literal runs over
 * line breaks and nests `${…}` code. A quoted string never crosses its line;
 * an unterminated quote (stray, or in syntax this lexer doesn't know) is
 * skipped and the literals after it on the line are still read. Linear.
 */
export function lexJsLiterals(code: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const n = code.length;
  // Open `${` substitutions: the brace depth to return to the template at
  const templates: number[] = [];
  let depth = 0;
  let prev = ''; // last significant code character, or a word
  // Per quote: a quote of that kind before this index can't close on its line
  const dead: Record<string, number> = { '"': -1, "'": -1 };
  let i = 0;
  const template = (from: number): void => {
    // from: the backtick or the `}` closing a substitution
    let j = from + 1;
    while (j < n) {
      const c = code[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '`') { out.push([from, j + 1]); i = j + 1; prev = ')'; return; }
      if (c === '$' && code[j + 1] === '{') { out.push([from, j + 1]); templates.push(depth); depth++; i = j + 2; prev = '{'; return; }
      j++;
    }
    i = n; // unterminated: the rest is the template
  };
  // A fragment that begins inside a template literal (a line cut out of a
  // bundle's multi-line template): an escaped backtick before the first
  // unescaped one. From the line holding it to that backtick is the
  // template's tail; quotes in it are characters, not strings.
  {
    let j = 0;
    let escaped = -1;
    while (j < n && code[j] !== '`') {
      if (code[j] === '\\') {
        if (code[j + 1] === '`' && escaped < 0) escaped = j;
        j += 2;
        continue;
      }
      j++;
    }
    if (escaped >= 0 && j < n) {
      // the lines before it hold no backtick: lexed on their own
      const start = Math.max(0, code.lastIndexOf('\n', escaped));
      out.push(...lexJsLiterals(code.slice(0, start)), [start, j + 1]);
      i = j + 1;
      prev = ')';
    }
  }
  while (i < n) {
    const c = code[i];
    if (c === '/' && code[i + 1] === '/') { const e = code.indexOf('\n', i); i = e === -1 ? n : e; continue; }
    if (c === '/' && code[i + 1] === '*') { const e = code.indexOf('*/', i + 2); i = e === -1 ? n : e + 2; continue; }
    if ((c === '"' || c === "'") && i >= dead[c]) {
      let j = i + 1;
      while (j < n && code[j] !== c && code[j] !== '\n') j += code[j] === '\\' && code[j + 1] !== '\n' ? 2 : 1;
      if (j < n && code[j] === c) { out.push([i, j + 1]); prev = ')'; i = j + 1; continue; }
      // Unterminated: every quote of this kind up to j was escaped in the scan
      dead[c] = j;
      i++;
      continue;
    }
    if (c === '`') { template(i); continue; }
    if (c === '/' && (prev === '' || /^[(,=:[!&|?{};+\-%<>~^]$/.test(prev) || REGEX_AFTER_WORD.has(prev))) {
      // a regex literal: to the unescaped `/` outside a class, within its line
      // (not after `*`: in a fragment that is the end of a comment begun before it)
      let j = i + 1;
      let inClass = false;
      while (j < n && code[j] !== '\n') {
        const r = code[j];
        if (r === '\\') { j += 2; continue; }
        if (r === '[') inClass = true;
        else if (r === ']') inClass = false;
        else if (r === '/' && !inClass) break;
        j++;
      }
      if (j < n && code[j] === '/') { i = j + 1; prev = ')'; continue; }
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (templates.length > 0 && depth === templates[templates.length - 1]) { templates.pop(); template(i); continue; }
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < n && /[\w$]/.test(code[j])) j++;
      prev = code.slice(i, j);
      i = j;
      continue;
    }
    if (!/\s/.test(c)) prev = /[\d.]/.test(c) ? ')' : c;
    i++;
  }
  return out;
}

/**
 * String-literal contents of Python source, one entry per physical line, the
 * way `stringLines` reads JavaScript: an annotation (`instructions:
 * Annotated[str, …]`) or a name (`assistant: Assistant | None`) is code, not
 * text the server returns. A triple-quoted string in statement position — a
 * docstring — is marked `description`: it documents code (a tool's docstring
 * is its description, MCP-024's). Prefixes (r/b/f/u) are understood;
 * f-string `{…}` stays in the text. A single non-recursive pass.
 */
export function pythonStringLines(code: string): StringLine[] {
  const out: StringLine[] = [];
  let line = 1;
  let i = 0;
  let lineStart = true; // only whitespace so far on this logical line
  while (i < code.length) {
    const c = code[i];
    if (c === '\n') { line++; lineStart = true; i++; continue; }
    if (c === '#') { while (i < code.length && code[i] !== '\n') i++; continue; }
    const prefix = /^[rRbBuUfF]{0,2}(?=["'])/.exec(code.slice(i, i + 3));
    if (prefix && (i === 0 || !/[\w]/.test(code[i - 1]))) {
      const q0 = i + prefix[0].length;
      const triple = code.startsWith(code[q0].repeat(3), q0);
      const quote = triple ? code[q0].repeat(3) : code[q0];
      const raw = /[rR]/.test(prefix[0]);
      // A docstring, or a parameter/tool description (`Field(description='…')`)
      const docstring = (triple && lineStart) || /\bdescription\s*[=:]\s*$/.test(code.slice(Math.max(0, i - 40), i));
      // Prompt content: a string assigned to a name with "prompt" in it
      // (`CHDB_PROMPT = """…`), served by an MCP prompt the user picks
      const prompt = /\b\w*prompt\w*\s*[:=]\s*$/i.test(code.slice(Math.max(0, i - 60), i));
      let j = q0 + quote.length;
      let text = '';
      let textLine = line;
      while (j < code.length && !code.startsWith(quote, j)) {
        const ch = code[j];
        if (ch === '\n') {
          if (!triple) break; // unterminated single-quoted string
          out.push({ line: textLine, text, description: docstring, ...(prompt ? { prompt } : {}) });
          text = '';
          line++;
          textLine = line;
          j++;
          continue;
        }
        if (ch === '\\' && !raw && j + 1 < code.length) { text += ch + code[j + 1]; if (code[j + 1] === '\n') { line++; } j += 2; continue; }
        text += ch;
        j++;
      }
      out.push({ line: textLine, text, description: docstring, ...(prompt ? { prompt } : {}) });
      i = Math.min(code.length, j + quote.length);
      lineStart = false;
      continue;
    }
    if (c !== ' ' && c !== '\t' && c !== '\r') lineStart = false;
    i++;
  }
  return out.filter(u => u.text.trim().length > 0);
}

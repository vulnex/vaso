/**
 * Tool definitions read structurally from server source, ahead of the regex
 * patterns in `extractToolDefinitions` (which only see quoted string literals
 * on one registration call):
 *
 *  - JavaScript/TypeScript, from the AST: `server.tool(name, description, …)`,
 *    `registerTool(name, { description })` (config inline or in a const),
 *    FastMCP-TS `addTool({ name, description, execute })`, and tool objects in
 *    a `tools: [...]` list. Descriptions may be template literals, `+`
 *    concatenations, `[...].join()` or consts — the forms a poisoned
 *    description uses to slip past a quoted-string regex — and are returned
 *    cooked, so `​` escapes become the characters the model reads.
 *  - Python: `@mcp.tool()` functions (FastMCP / the official SDK), whose
 *    description is the `description=` argument or else the docstring, and
 *    low-level `Tool(name=…, description=…)` objects.
 */

import _traverse from '@babel/traverse';
import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { parseJs, sourceChunks } from '../analyzers/js-parse.js';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface ExtractedTool {
  name: string;
  description?: string;
}

const MAX_DEPTH = 6;
/** Calls that register one tool: the name first, then a description or config. */
const NAME_FIRST = new Set(['tool', 'registerTool']);
/** Keys that make an object with `name` + `description` a tool, not package metadata. */
const TOOL_SHAPE_KEYS = new Set(['inputSchema', 'input_schema', 'parameters', 'handler', 'execute', 'annotations', 'outputSchema']);

// ── JavaScript ──────────────────────────────────────────────────────────

/** Static text of a string-valued expression; undefined when it isn't one. */
function stringValue(path: NodePath | undefined, depth = 0): string | undefined {
  if (!path?.node || depth > MAX_DEPTH) return undefined;
  if (path.isStringLiteral()) return path.node.value;
  if (path.isTemplateLiteral()) {
    const exprs = path.get('expressions') as NodePath[];
    return path.node.quasis
      .map((q, i) => (q.value.cooked ?? q.value.raw) + (i < exprs.length ? (stringValue(exprs[i], depth + 1) ?? '${…}') : ''))
      .join('');
  }
  if (path.isTaggedTemplateExpression()) return stringValue(path.get('quasi') as NodePath, depth + 1); // dedent`…`
  if (path.isBinaryExpression() && path.node.operator === '+') {
    const left = stringValue(path.get('left') as NodePath, depth + 1);
    const right = stringValue(path.get('right') as NodePath, depth + 1);
    return left === undefined && right === undefined ? undefined : (left ?? '…') + (right ?? '…');
  }
  if (path.isTSAsExpression() || path.isParenthesizedExpression()) return stringValue(path.get('expression') as NodePath, depth + 1);
  if (path.isCallExpression()) {
    const callee = path.get('callee') as NodePath;
    if (!callee.isMemberExpression() || callee.node.property.type !== 'Identifier') return undefined;
    const method = callee.node.property.name;
    const object = callee.get('object') as NodePath;
    // ["line one", "line two"].join("\n")
    if (method === 'join' && object.isArrayExpression()) {
      const sepArg = (path.get('arguments') as NodePath[])[0];
      const sep = sepArg ? stringValue(sepArg, depth + 1) : ',';
      const parts = (object.get('elements') as NodePath[]).map((e) => stringValue(e, depth + 1) ?? '…');
      return parts.join(sep ?? '');
    }
    if (method === 'trim' || method === 'trimStart' || method === 'trimEnd' || method === 'concat') {
      const base = stringValue(object, depth + 1);
      if (base === undefined) return undefined;
      const rest = (path.get('arguments') as NodePath[]).map((a) => stringValue(a, depth + 1) ?? '').join('');
      return method === 'concat' ? base + rest : base.trim();
    }
    return undefined;
  }
  if (path.isIdentifier()) {
    const init = constInit(path);
    return init ? stringValue(init, depth + 1) : undefined;
  }
  return undefined;
}

/** The initializer of a `const` the identifier names. */
function constInit(path: NodePath): NodePath | undefined {
  if (!path.isIdentifier()) return undefined;
  const binding = path.scope.getBinding(path.node.name);
  if (!binding || !binding.constant) return undefined;
  const declarator = binding.path;
  if (!declarator.isVariableDeclarator() || declarator.node.id.type !== 'Identifier') return undefined;
  const init = declarator.get('init') as NodePath;
  return init.node ? init : undefined;
}

/** An object expression, directly or through a const. */
function objectOf(path: NodePath | undefined): NodePath | undefined {
  if (!path?.node) return undefined;
  if (path.isObjectExpression()) return path;
  if (path.isTSAsExpression() || path.isTSSatisfiesExpression()) return objectOf(path.get('expression') as NodePath);
  const init = constInit(path);
  return init?.isObjectExpression() ? init : undefined;
}

function propertyKey(node: Node): string | undefined {
  if (node.type !== 'ObjectProperty' && node.type !== 'ObjectMethod') return undefined;
  const key = node.key;
  if (key.type === 'Identifier') return key.name;
  if (key.type === 'StringLiteral') return key.value;
  return undefined;
}

function property(obj: NodePath, name: string): NodePath | undefined {
  for (const prop of obj.get('properties') as NodePath[]) {
    if (prop.isObjectProperty() && propertyKey(prop.node) === name) return prop.get('value') as NodePath;
  }
  return undefined;
}

function jsTools(code: string): ExtractedTool[] {
  const out: ExtractedTool[] = [];
  for (const chunk of sourceChunks(code)) {
    const ast = parseJs(chunk.code);
    if (!ast) continue;
    try {
      traverse(ast, {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
          const method = callee.property.name;
          const args = path.get('arguments') as NodePath[];
          if (NAME_FIRST.has(method)) {
            const name = stringValue(args[0]);
            if (!name) return;
            // tool(name, "description", schema, handler) or tool(name, { description, … }, handler)
            const description = stringValue(args[1]) ?? descriptionOf(objectOf(args[1]));
            out.push({ name, description });
          } else if (method === 'addTool') {
            const config = objectOf(args[0]);
            const name = config ? stringValue(property(config, 'name')) : undefined;
            if (config && name) out.push({ name, description: descriptionOf(config) });
          }
        },
        ObjectExpression(path) {
          const keys = new Set(path.node.properties.map(propertyKey));
          if (!keys.has('name') || !keys.has('description')) return;
          if (![...keys].some((k) => k && TOOL_SHAPE_KEYS.has(k)) && !path.parentPath.isArrayExpression()) return;
          const name = stringValue(property(path, 'name'));
          const description = descriptionOf(path);
          if (name && description !== undefined) out.push({ name, description });
        },
      });
    } catch {
      // keep what this chunk yielded
    }
  }
  return out;
}

function descriptionOf(obj: NodePath | undefined): string | undefined {
  return obj ? stringValue(property(obj, 'description')) : undefined;
}

// ── Python ─────────────────────────────────────────────────────────────

/** Python string literal at `i` (prefix, quotes): [value, index after it]. */
function pyStringAt(src: string, i: number): [string, number] | undefined {
  const m = /^([rRbBuUfF]{0,2})("""|'''|"|')/.exec(src.slice(i, i + 5));
  if (!m) return undefined;
  const raw = /r/i.test(m[1]);
  const quote = m[2];
  let j = i + m[0].length;
  let value = '';
  while (j < src.length) {
    if (src.startsWith(quote, j)) return [raw ? value : pyUnescape(value), j + quote.length];
    if (src[j] === '\\' && j + 1 < src.length) {
      value += src.slice(j, j + 2);
      j += 2;
      continue;
    }
    if (quote.length === 1 && src[j] === '\n') return undefined;
    value += src[j++];
  }
  return undefined;
}

function pyUnescape(s: string): string {
  return s.replace(/\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|(.))/gs, (m, u, U, x, c) => {
    const hex = u ?? U ?? x;
    if (hex) {
      const cp = parseInt(hex, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return ({ n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"', '\n': '' } as Record<string, string>)[c] ?? m;
  });
}

/**
 * A Python string expression at `i`: adjacent literals and `+` joins, inside
 * optional parentheses (`description=("a " "b")`).
 */
function pyStringExpr(src: string, i: number): string | undefined {
  let j = i;
  const skip = () => { while (j < src.length && /[\s\\]/.test(src[j])) j++; };
  skip();
  let parens = 0;
  while (src[j] === '(') { parens++; j++; skip(); }
  let value: string | undefined;
  for (;;) {
    const lit = pyStringAt(src, j);
    if (!lit) break;
    value = (value ?? '') + lit[0];
    j = lit[1];
    skip();
    if (src[j] === '+') { j++; skip(); }
  }
  return parens > 0 || value !== undefined ? value : undefined;
}

/** Text from `open` (an opening paren) to its matching close, strings skipped. */
function balanced(src: string, open: number): string | undefined {
  let depth = 0;
  for (let j = open; j < src.length; j++) {
    const c = src[j];
    if (c === '"' || c === "'") {
      const lit = pyStringAt(src, j);
      if (lit) { j = lit[1] - 1; continue; }
    }
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return src.slice(open + 1, j);
  }
  return undefined;
}

function kwarg(args: string, key: string): string | undefined {
  const m = new RegExp(String.raw`(?:^|[,(\s])${key}\s*=\s*`).exec(args);
  return m ? pyStringExpr(args, m.index + m[0].length) : undefined;
}

/** inspect.cleandoc: strip the common indentation and surrounding blank lines. */
function cleandoc(doc: string): string {
  const lines = doc.replace(/\t/g, '    ').split('\n');
  const indents = lines.slice(1).filter((l) => l.trim()).map((l) => l.length - l.trimStart().length);
  const margin = indents.length ? Math.min(...indents) : 0;
  return [lines[0].trim(), ...lines.slice(1).map((l) => l.slice(margin))].join('\n').trim();
}

const PY_TOOL_DECORATOR = /^[ \t]*@[ \t]*[\w.]*\btool\b[ \t]*(\()?/gm;
const PY_TOOL_CLASS = /\b(?:types\.)?Tool\s*\(/g;

function pythonTools(code: string): ExtractedTool[] {
  if (!/\bdef\s|\bTool\s*\(/.test(code)) return [];
  const out: ExtractedTool[] = [];

  for (const m of code.matchAll(PY_TOOL_DECORATOR)) {
    let pos = m.index + m[0].length;
    let args = '';
    if (m[1]) {
      const inner = balanced(code, pos - 1);
      if (inner === undefined) continue;
      args = inner;
      pos += inner.length + 1;
    }
    // Further decorators, then the def.
    const def = /^(?:[ \t]*\n|[ \t]*@[^\n]*\n)*?[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(/.exec(code.slice(pos).replace(/^[^\n]*\n/, ''));
    if (!def) continue;
    const afterLine = code.indexOf('\n', pos) + 1;
    const sigOpen = afterLine + def.index + def[0].length - 1;
    const sig = balanced(code, sigOpen);
    if (sig === undefined) continue;
    const colon = code.indexOf(':', sigOpen + sig.length + 2);
    const bodyStart = code.indexOf('\n', colon) + 1;
    const doc = bodyStart > 0 ? pyStringAt(code, bodyStart + (/^[ \t]*/.exec(code.slice(bodyStart))?.[0].length ?? 0)) : undefined;
    const name = kwarg(args, 'name') ?? def[1];
    const description = kwarg(args, 'description') ?? (doc ? cleandoc(doc[0]) : undefined);
    out.push({ name, description });
  }

  for (const m of code.matchAll(PY_TOOL_CLASS)) {
    const args = balanced(code, m.index + m[0].length - 1);
    if (!args) continue;
    const name = kwarg(args, 'name');
    if (name) out.push({ name, description: kwarg(args, 'description') });
  }
  return out;
}

/** Tools defined in `code`, JavaScript or Python. */
export function structuredToolDefinitions(code: string): ExtractedTool[] {
  return [...jsTools(code), ...pythonTools(code)];
}

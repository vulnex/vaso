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
      let j = q0 + quote.length;
      let text = '';
      let textLine = line;
      while (j < code.length && !code.startsWith(quote, j)) {
        const ch = code[j];
        if (ch === '\n') {
          if (!triple) break; // unterminated single-quoted string
          out.push({ line: textLine, text, description: docstring });
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
      out.push({ line: textLine, text, description: docstring });
      i = Math.min(code.length, j + quote.length);
      lineStart = false;
      continue;
    }
    if (c !== ' ' && c !== '\t' && c !== '\r') lineStart = false;
    i++;
  }
  return out.filter(u => u.text.trim().length > 0);
}

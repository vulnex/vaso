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

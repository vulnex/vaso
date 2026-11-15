import _traverse from '@babel/traverse';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { readSkillText, skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { mayBeJavaScript, parseJs } from '../../analyzers/js-parse.js';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

const COMPLEXITY_THRESHOLD = 15;

const FUNCTION_NODES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod']);

const DECISION_NODES = new Set([
  'IfStatement',
  'ConditionalExpression',
  'SwitchCase',
  'ForStatement',
  'ForInStatement',
  'ForOfStatement',
  'WhileStatement',
  'DoWhileStatement',
  'CatchClause',
  'LogicalExpression',
]);

export const skl012 = defineCheck({
  id: 'SKL-012',
  name: 'Code Complexity',
  category: 'skills',
  severity: 'info',
  description: 'Measure cyclomatic complexity per function via Babel AST; flag functions exceeding threshold',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
        // Shell, Python and data files aren't JavaScript; Babel's error
        // recovery would invent functions in them
        if (!mayBeJavaScript(file)) continue;
        const ast = parseJs(code);
        if (!ast) continue;

        // One pass: a decision point counts toward every function it sits in
        // (nested ones included). A sub-traversal per function made this
        // quadratic in nesting depth on large bundles.
        const open: Array<{ node: Record<string, unknown>; complexity: number; start: number; line: number }> = [];
        const found: Array<{ start: number; ev: Evidence }> = [];
        traverse(ast, {
          enter(path) {
            if (FUNCTION_NODES.has(path.node.type)) {
              open.push({ node: path.node as unknown as Record<string, unknown>, complexity: 1, start: path.node.start ?? 0, line: path.node.loc?.start.line ?? 0 });
            } else if (DECISION_NODES.has(path.node.type)) {
              for (const fn of open) fn.complexity++;
            }
          },
          exit(path) {
            if (!FUNCTION_NODES.has(path.node.type)) return;
            const fn = open.pop();
            if (!fn || fn.complexity <= COMPLEXITY_THRESHOLD) return;
            const id = fn.node.id as { name: string } | null | undefined;
            const key = fn.node.key as { name?: string; value?: string } | undefined;
            const funcName = id?.name ?? (key && 'name' in key ? key.name : undefined) ?? '<anonymous>';
            found.push({
              start: fn.start,
              ev: { file, line: fn.line, detail: `Function "${funcName}" has cyclomatic complexity ${fn.complexity} (threshold: ${COMPLEXITY_THRESHOLD})` },
            });
          },
        });
        // Source order, as before (exit order is innermost-first)
        evidence.push(...found.sort((a, b) => a.start - b.start).map(f => f.ev));
      } catch {
        // Skip unreadable files
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'All functions are within complexity threshold',
      failed: (n) => `Found ${n} function(s) exceeding complexity threshold of ${COMPLEXITY_THRESHOLD}`,
    });
  },
});

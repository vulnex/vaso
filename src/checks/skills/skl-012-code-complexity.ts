import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getSkillFiles } from '../../core/utils.js';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

const COMPLEXITY_THRESHOLD = 15;

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
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        let ast: ReturnType<typeof parse>;
        try {
          ast = parse(code, {
            sourceType: 'unambiguous',
            plugins: ['typescript', 'jsx', 'decorators'],
            errorRecovery: true,
          });
        } catch {
          continue;
        }

        traverse(ast, {
          'FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod'(path) {
            let complexity = 1;

            path.traverse({
              enter(innerPath) {
                if (DECISION_NODES.has(innerPath.node.type)) {
                  complexity++;
                }
              },
            });

            if (complexity > COMPLEXITY_THRESHOLD) {
              const node = path.node as unknown as Record<string, unknown>;
              const id = node.id as { name: string } | null | undefined;
              const key = node.key as { name?: string; value?: string } | undefined;
              const funcName =
                id?.name ??
                (key && 'name' in key ? key.name : undefined) ??
                '<anonymous>';
              const line = path.node.loc?.start.line ?? 0;

              evidence.push({
                file,
                line,
                detail: `Function "${funcName}" has cyclomatic complexity ${complexity} (threshold: ${COMPLEXITY_THRESHOLD})`,
              });
            }
          },
        });
      } catch {
        // Skip unreadable files
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All functions are within complexity threshold',
      failed: (n) => `Found ${n} function(s) exceeding complexity threshold of ${COMPLEXITY_THRESHOLD}`,
    });
  },
});

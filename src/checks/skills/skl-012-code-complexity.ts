import { readFile } from 'node:fs/promises';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
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

export const skl012: CheckModule = {
  id: 'SKL-012',
  name: 'Code Complexity',
  category: 'skills',
  severity: 'info',
  description: 'Measure cyclomatic complexity per function via Babel AST; flag functions exceeding threshold',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-012', name: 'Code Complexity', category: 'skills', severity: 'info', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
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

    return {
      id: 'SKL-012',
      name: 'Code Complexity',
      category: 'skills',
      severity: 'info',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All functions are within complexity threshold'
        : `Found ${evidence.length} function(s) exceeding complexity threshold of ${COMPLEXITY_THRESHOLD}`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

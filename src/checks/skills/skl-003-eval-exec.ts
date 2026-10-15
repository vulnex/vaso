import { extname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

export const skl003 = defineCheck({
  id: 'SKL-003',
  name: 'Eval/Exec Usage',
  category: 'skills',
  severity: 'critical',
  description: 'Detect eval(), new Function(), exec(), and other dynamic code execution',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
        const execFlows = flows.filter(f => f.type === 'eval-exec');

        for (const flow of execFlows) {
          // A fixed command (`execFileSync('git', ['status'])`) is a skill doing
          // its job; only commands built at runtime or decoded are dynamic
          // execution. Constant ones stay listed, informationally (as MCP-004).
          const constant = flow.command !== undefined && !flow.dynamic && !flow.decoded;
          // A program started directly (no shell, no interpreter given code)
          // runs with runtime arguments; it isn't code built at runtime
          const direct = !constant && flow.noShell === true && !flow.decoded;
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: constant
              ? `${flow.description} — constant command "${flow.command}"`
              : direct ? `${flow.description} — runs a program directly (no shell)` : flow.description,
            ...(constant || direct ? { mitigated: true } : {}),
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No eval/exec usage detected',
      failed: (n) => `Found ${n} dynamic code execution call(s)`,
    });
  },
});

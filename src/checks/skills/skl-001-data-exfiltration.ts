import { extname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

export const skl001 = defineCheck({
  id: 'SKL-001',
  name: 'Data Exfiltration Flow',
  category: 'skills',
  severity: 'critical',
  description: 'Detect data flows from file/env sources to network or process-execution sinks (AST-based)',

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
        const exfil = flows.filter(f => f.type === 'source-to-sink');

        for (const flow of exfil) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description,
          });
        }
      } catch {
        // Skip unreadable files
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No data exfiltration flows detected',
      failed: (n) => `Found ${n} data exfiltration flow(s) — data flowing from sources to network or process sinks`,
    });
  },
});

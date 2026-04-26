import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl001 = defineCheck({
  id: 'SKL-001',
  name: 'Data Exfiltration Flow',
  category: 'skills',
  severity: 'critical',
  description: 'Detect data flows from file/env sources to network sinks (AST-based)',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
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

    return h.fromEvidence(evidence, {
      passed: 'No data exfiltration flows detected',
      failed: (n) => `Found ${n} data exfiltration flow(s) — data flowing from sources to network sinks`,
    });
  },
});

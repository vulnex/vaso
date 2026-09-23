import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ws006 = defineCheck({
  id: 'WS-006',
  name: 'Windsurf Turbo Directive in Workflows',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect // turbo and // turbo-all directives in global workflow files, which auto-run commands without approval',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const workflowsDir = join(ctx.fs.homedir(), '.codeium', 'windsurf', 'global_workflows');
    if (!(await ctx.fs.access(workflowsDir))) {
      return h.passed('No Windsurf global workflows directory present');
    }

    let files: string[];
    try {
      files = await ctx.fs.readdir(workflowsDir);
    } catch {
      return h.passed('No Windsurf global workflows directory present');
    }

    const evidence: Evidence[] = [];
    for (const name of files) {
      if (!name.endsWith('.md')) continue;
      const filePath = join(workflowsDir, name);
      let content: string;
      try {
        content = await ctx.fs.readFile(filePath);
      } catch {
        continue;
      }

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.includes('// turbo')) continue;
        const isTurboAll = line.includes('// turbo-all');
        evidence.push({
          file: filePath,
          line: i + 1,
          snippet: line.trim().slice(0, 120),
          detail: isTurboAll
            ? "'// turbo-all' auto-runs EVERY command in this workflow without approval"
            : "'// turbo' auto-runs the annotated command without approval",
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No turbo auto-execution directives in Windsurf global workflows',
      failed: (n) => `Found ${n} turbo directive(s) in Windsurf global workflows`,
      fixDescription: 'Remove // turbo and // turbo-all lines from workflow files so commands require approval',
    });
  },
});

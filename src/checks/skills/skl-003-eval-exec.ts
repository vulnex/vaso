import { extname } from 'node:path';
import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { agentBypass } from '../../analyzers/agent-cli-flags.js';

export const skl003 = defineCheck({
  id: 'SKL-003',
  name: 'Eval/Exec Usage',
  category: 'skills',
  severity: 'critical',
  description: 'Detect eval(), new Function(), exec(), and other dynamic code execution',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const levels: Severity[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
        const execFlows = flows.filter(f => f.type === 'eval-exec');

        for (const flow of execFlows) {
          // An agent CLI started with its approvals off runs whatever its
          // prompt asks, outside this agent's permission rules — fixed
          // command or not
          const bypass = agentBypass(flow.command);
          if (bypass) {
            levels.push(bypass.level);
            evidence.push({
              file,
              line: flow.line,
              snippet: flow.snippet,
              detail: bypass.level === 'critical'
                ? `${flow.description} — starts the ${bypass.agent} agent with ${bypass.flag}: it runs every tool without asking, outside this agent's permission rules`
                : `${flow.description} — starts the ${bypass.agent} agent with ${bypass.flag}: part of its work is approved without asking, or its sandbox is off`,
            });
            continue;
          }
          // A fixed command (`execFileSync('git', ['status'])`) is a skill doing
          // its job; only commands built at runtime or decoded are dynamic
          // execution. Constant ones stay listed, informationally (as MCP-004).
          const constant = flow.command !== undefined && !flow.dynamic && !flow.decoded;
          // A program started directly (no shell, no interpreter given code)
          // runs with runtime arguments; it isn't code built at runtime
          const direct = !constant && flow.noShell === true && !flow.decoded;
          // An interpreter given literal code (`python -c "import sys; …"`)
          // runs fixed code, whichever interpreter path it is
          const fixedCode = !constant && !direct && flow.fixedCode === true && !flow.decoded;
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: constant
              ? `${flow.description} — constant command "${flow.command}"`
              : direct ? `${flow.description} — runs a program directly (no shell)`
                : fixedCode ? `${flow.description} — runs fixed code through -c` : flow.description,
            ...(constant || direct || fixedCode ? { mitigated: true } : {}),
          });
          levels.push('critical');
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    const live = evidence.map((e, i) => (e.mitigated ? undefined : levels[i])).filter(Boolean);
    return h.fromEvidence(evidence, {
      passed: 'No eval/exec usage detected',
      failed: (n) => `Found ${n} dynamic code execution call(s)`,
      severity: live.length === 0 || live.includes('critical') ? 'critical' : 'warning',
    });
  },
});

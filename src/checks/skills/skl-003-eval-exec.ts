import { dirname, join } from 'node:path';
import type { Evidence, Severity } from '../../core/types.js';
import type { DataFlowResult } from '../../analyzers/ast-analyzer.js';
import { defineCheck } from '../../core/check-builder.js';
import { skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { analyzeSkillSource, readSkillSource } from './skill-source.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { agentBypass } from '../../analyzers/agent-cli-flags.js';

export const skl003 = defineCheck({
  id: 'SKL-003',
  name: 'Eval/Exec Usage',
  category: 'skills',
  severity: 'critical',
  description: 'Detect eval(), new Function(), exec(), and other dynamic code execution',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const levels: Severity[] = [];
    const files = await skillFilesOf(ctx);
    const shipped = new Set(files);
    const analyzed: Array<{ file: string; flows: DataFlowResult[] }> = [];
    for (const file of files) {
      try {
        const src = await readSkillSource(ctx, file, 'code');
        if (src === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        analyzed.push({ file, flows: analyzeSkillSource(src) });
      } catch {}
    }
    // Files the skill's code writes into its own folders (downloaded, decoded,
    // copied in), and folders it writes files of runtime-chosen names into
    const writtenFiles = new Set<string>();
    const writtenDirs = new Set<string>();
    for (const { file, flows } of analyzed) {
      for (const f of flows) {
        if (f.type !== 'own-write' || !f.resolvedPath?.startsWith('<skill>/')) continue;
        const rel = f.resolvedPath.slice('<skill>/'.length);
        if (rel === '*') writtenDirs.add(dirname(file));
        else writtenFiles.add(join(dirname(file), rel));
      }
    }
    // A script run from the skill's own folder is never a fixed command: the
    // skill (or anything it runs) can replace it before it runs, and no list
    // of ways to write a file is complete (dt25 D4: back to the 1.4.2 rule)
    const notShipped = async (file: string, flow: DataFlowResult): Promise<string | undefined> => {
      const helpers = flow.ownHelpers ?? [];
      for (const rel of helpers) {
        const path = join(dirname(file), rel);
        if (writtenFiles.has(path) || writtenDirs.has(dirname(path))) {
          return `runs <skill>/${rel}, a file the skill writes itself (downloaded or decoded code, not a shipped helper)`;
        }
        if (!shipped.has(path)) return `runs <skill>/${rel}, which the skill doesn't ship`;
      }
      if (helpers.length > 0) return `runs <skill>/${helpers[0]} from the skill's own folder, which the skill or what it runs can replace`;
      return undefined;
    };

    for (const { file, flows } of analyzed) {
      try {
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
          const helper = await notShipped(file, flow);
          const constant = flow.command !== undefined && !flow.dynamic && !flow.decoded && !helper;
          // A program started directly (no shell, no interpreter given code)
          // runs with runtime arguments; it isn't code built at runtime
          // …and one whose program is chosen at runtime (a CLI argument, a
          // discovered path) is worth a look, not critical: no shell syntax
          // can be injected, but whoever picks the program decides what runs
          const runtime = !constant && !helper && !flow.decoded && flow.runtimeProgram === true;
          const direct = !constant && !helper && !runtime && flow.noShell === true && !flow.decoded;
          // An interpreter given literal code (`python -c "import sys; …"`)
          // runs fixed code, whichever interpreter path it is
          const fixedCode = !constant && !direct && !runtime && !helper && flow.fixedCode === true && !flow.decoded;
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: constant
              ? `${flow.description} — constant command "${flow.command}"`
              : direct ? `${flow.description} — runs a program directly (no shell)`
                : runtime ? `${flow.description} — runs a program chosen at runtime, without a shell: review where the program path comes from`
                : fixedCode ? `${flow.description} — runs fixed code through -c`
                  : helper ? `${flow.description} — ${helper}`
                    : flow.shellOption ? `${flow.description} — its options can turn the shell on (set here or passed in by a caller), so the command line may be parsed by a shell`
                      : flow.description,
            ...(constant || direct || fixedCode ? { mitigated: true } : {}),
          });
          levels.push(runtime ? 'warning' : 'critical');
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

import { dirname, extname, join, normalize } from 'node:path';
import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode, type DataFlowResult } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

/**
 * How serious a flow is by what it carries. A credential store, the
 * environment, or host identity in a DNS name is exfiltration; a file from
 * elsewhere on the machine (outside the skill and the workspace) is a
 * warning; the skill's own files, workspace files and files chosen at runtime
 * (an upload skill sending the file it was given) are listed as info. Flows
 * whose path wasn't classified (Python, line scan) stay critical.
 */
function flowTier(f: DataFlowResult): { level: Severity; note?: string } {
  if (f.sourceKind !== 'file' || f.sourcePath === undefined || f.sourcePath === 'credential') return { level: 'critical' };
  if (f.sourcePath === 'outside') return { level: 'warning', note: 'a file outside the skill and workspace' };
  return {
    level: 'info',
    note: f.sourcePath === 'own' ? "the skill's own file" : f.sourcePath === 'workspace' ? 'a workspace file' : 'a file chosen at runtime',
  };
}

/** Candidate files a relative module specifier names (`./lib/upload` → `lib/upload.js`, …). */
function moduleFiles(from: string, spec: string): string[] {
  const base = normalize(join(dirname(from), spec));
  return [base, ...['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'].map(e => base + e), ...['index.js', 'index.mjs', 'index.ts'].map(i => join(base, i))];
}

export const skl001 = defineCheck({
  id: 'SKL-001',
  name: 'Data Exfiltration Flow',
  category: 'skills',
  severity: 'critical',
  description: 'Detect data flows from file/env sources to network or process-execution sinks (AST-based)',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const levels: Severity[] = [];
    const files = await skillFilesOf(ctx);
    const moduleCalls: Array<{ file: string; flow: DataFlowResult }> = [];
    const paramSinks = new Map<string, DataFlowResult[]>();

    const add = (file: string, flow: DataFlowResult, detail: string): void => {
      const { level, note } = flowTier(flow);
      levels.push(level);
      evidence.push({
        file,
        line: flow.line,
        snippet: flow.snippet,
        detail: note ? `${detail} — ${note}` : detail,
        ...(level === 'info' ? { mitigated: true } : {}),
      });
    };

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
        for (const flow of flows) {
          if (flow.type === 'source-to-sink') add(file, flow, flow.description);
          else if (flow.type === 'module-call') moduleCalls.push({ file, flow });
          else if (flow.type === 'param-sink') paramSinks.set(file, [...(paramSinks.get(file) ?? []), flow]);
        }
      } catch {
        // Skip unreadable files
      }
    }

    // A value handed to a helper module of the skill that sends it
    // (`require('./lib/upload')(secret)`), reported at the call
    for (const { file, flow } of moduleCalls) {
      const target = moduleFiles(file, flow.module ?? '').find(f => paramSinks.has(f));
      const sink = target && paramSinks.get(target)!.find(p => p.exportName === flow.exportName && p.argIndex === flow.argIndex);
      if (sink) add(file, flow, `${flow.description}, which sends it to ${sink.sink} (${target}:${sink.line})`);
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    const live = evidence.map((e, i) => (e.mitigated ? undefined : levels[i])).filter(Boolean);
    return h.fromEvidence(evidence, {
      passed: 'No data exfiltration flows detected',
      failed: (n) => `Found ${n} data exfiltration flow(s) — data flowing from sources to network or process sinks`,
      severity: live.length === 0 || live.includes('critical') ? 'critical' : 'warning',
    });
  },
});

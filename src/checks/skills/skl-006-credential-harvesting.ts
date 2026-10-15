import { extname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { isSourceFile, readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const CRED_HARVEST_RULES = SECURITY_PATTERNS.filter(r => r.category === 'credential-harvest');

export const skl006 = defineCheck({
  id: 'SKL-006',
  name: 'Credential Harvesting',
  category: 'skills',
  severity: 'critical',
  description: 'Detect access to .ssh, .aws, .env, and other credential stores',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;

        // Pattern-based detection
        const matches = scanWithPatterns(code, CRED_HARVEST_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description,
          });
        }

        // AST-based detection (source files only — not SKILL.md code blocks)
        if (!isSourceFile(file)) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
        const fsAccess = flows.filter(f => f.type === 'fs-access');
        for (const flow of fsAccess) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description,
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No credential harvesting patterns detected',
      failed: (n) => `Found ${n} credential harvesting indicator(s)`,
    });
  },
});

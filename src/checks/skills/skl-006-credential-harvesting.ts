import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CRED_HARVEST_RULES = SECURITY_PATTERNS.filter(r => r.category === 'credential-harvest');

export const skl006 = defineCheck({
  id: 'SKL-006',
  name: 'Credential Harvesting',
  category: 'skills',
  severity: 'critical',
  description: 'Detect access to .ssh, .aws, .env, and other credential stores',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);

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

        // AST-based detection
        const flows = analyzeCode(code, file);
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

    return h.fromEvidence(evidence, {
      passed: 'No credential harvesting patterns detected',
      failed: (n) => `Found ${n} credential harvesting indicator(s)`,
    });
  },
});

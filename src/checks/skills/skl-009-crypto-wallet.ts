import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CRYPTO_RULES = SECURITY_PATTERNS.filter(r => r.category === 'crypto-wallet');

export const skl009 = defineCheck({
  id: 'SKL-009',
  name: 'Crypto Wallet Targeting',
  category: 'skills',
  severity: 'warning',
  description: 'Detect crypto wallet address patterns and API targeting',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(code, CRYPTO_RULES);

        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No crypto wallet targeting patterns detected',
      failed: (n) => `Found ${n} crypto wallet targeting pattern(s)`,
    });
  },
});

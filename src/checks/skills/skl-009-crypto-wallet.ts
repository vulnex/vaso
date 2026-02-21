import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CRYPTO_RULES = SECURITY_PATTERNS.filter(r => r.category === 'crypto-wallet');

export const skl009: CheckModule = {
  id: 'SKL-009',
  name: 'Crypto Wallet Targeting',
  category: 'skills',
  severity: 'warning',
  description: 'Detect crypto wallet address patterns and API targeting',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-009', name: 'Crypto Wallet Targeting', category: 'skills', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
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

    return {
      id: 'SKL-009',
      name: 'Crypto Wallet Targeting',
      category: 'skills',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No crypto wallet targeting patterns detected'
        : `Found ${evidence.length} crypto wallet targeting pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

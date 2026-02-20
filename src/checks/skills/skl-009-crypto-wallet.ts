import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';

const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts']);
const CRYPTO_RULES = SECURITY_PATTERNS.filter(r => r.category === 'crypto-wallet');

async function getSkillFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true, recursive: true });
    for (const entry of entries) {
      if (entry.isFile() && CODE_EXTENSIONS.has(extname(entry.name))) {
        const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
        files.push(fullPath);
      }
    }
  } catch {}
  return files;
}

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

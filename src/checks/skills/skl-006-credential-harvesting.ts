import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CRED_HARVEST_RULES = SECURITY_PATTERNS.filter(r => r.category === 'credential-harvest');

export const skl006: CheckModule = {
  id: 'SKL-006',
  name: 'Credential Harvesting',
  category: 'skills',
  severity: 'critical',
  description: 'Detect access to .ssh, .aws, .env, and other credential stores',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-006', name: 'Credential Harvesting', category: 'skills', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');

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

    return {
      id: 'SKL-006',
      name: 'Credential Harvesting',
      category: 'skills',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No credential harvesting patterns detected'
        : `Found ${evidence.length} credential harvesting indicator(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

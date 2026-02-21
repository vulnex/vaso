import type { CheckModule, ScanContext, CheckResult, Evidence, FixResult } from '../../core/types.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

const PLACEHOLDER_HINTS = ['your-', 'xxx', 'placeholder', 'changeme', 'TODO', 'REPLACE', '<', 'example'];

function looksLikePlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_HINTS.some(hint => lower.includes(hint.toLowerCase()));
}

export const nb002: CheckModule = {
  id: 'NB-002',
  name: 'Plaintext Secrets in Config',
  category: 'nanobot',
  severity: 'critical',
  description: 'Scan config files for plaintext API keys, tokens, and passwords',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const raw = config.raw;
      if (!raw) continue;

      for (const { pattern, name } of API_KEY_PATTERNS) {
        const matches = raw.match(new RegExp(pattern.source, 'g'));
        if (!matches) continue;

        for (const match of matches) {
          if (looksLikePlaceholder(match)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `${match.slice(0, 8)}${'*'.repeat(Math.max(0, match.length - 8))}`,
            detail: `Plaintext ${name} found in config`,
          });
        }
      }
    }

    return {
      id: 'NB-002', name: 'Plaintext Secrets in Config', category: 'nanobot',
      severity: 'critical', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No plaintext secrets found in nanobot configs'
        : `Found ${evidence.length} plaintext secret(s) in nanobot configs`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Move secrets to environment variables or a secrets manager',
    };
  },

  async fix(_ctx: ScanContext): Promise<FixResult> {
    return { checkId: 'NB-002', applied: false, message: 'Manual action required: move plaintext secrets to environment variables or a secrets manager' };
  },
};

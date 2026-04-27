import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

const PLACEHOLDER_HINTS = ['your-', 'xxx', 'placeholder', 'changeme', 'TODO', 'REPLACE', '<', 'example'];

function looksLikePlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_HINTS.some(hint => lower.includes(hint.toLowerCase()));
}

export const nb002 = defineCheck({
  id: 'NB-002',
  name: 'Plaintext Secrets in Config',
  category: 'nanobot',
  severity: 'critical',
  description: 'Scan config files for plaintext API keys, tokens, and passwords',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets found in nanobot configs',
      failed: (n) => `Found ${n} plaintext secret(s) in nanobot configs`,
      fixable: true,
      fixDescription: 'Move secrets to environment variables or a secrets manager',
    });
  },

  async fix() {
    return { checkId: 'NB-002', applied: false, message: 'Manual action required: move plaintext secrets to environment variables or a secrets manager' };
  },
});

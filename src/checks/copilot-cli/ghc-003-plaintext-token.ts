import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const GITHUB_TOKEN_PATTERNS = [
  { pattern: /\bgho_[A-Za-z0-9]{20,}/, name: 'GitHub OAuth token' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bghs_[A-Za-z0-9]{20,}/, name: 'GitHub server token' },
  { pattern: /\bghu_[A-Za-z0-9]{20,}/, name: 'GitHub user-to-server token' },
  { pattern: /\bghr_[A-Za-z0-9]{20,}/, name: 'GitHub refresh token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
];

export const ghc003 = defineCheck({
  id: 'GHC-003',
  name: 'Copilot CLI Plaintext GitHub Token',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.copilot/{config,settings}.json for inline GitHub tokens (gho_, ghp_, etc.)',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.raw) continue;
      for (const { pattern, name } of GITHUB_TOKEN_PATTERNS) {
        const m = pattern.exec(config.raw);
        if (m) {
          evidence.push({
            file: config.filePath,
            snippet: `${m[0].slice(0, 8)}…`,
            detail: `Plaintext ${name} in Copilot config — rotate immediately and rely on the OS keychain or gh CLI's hosts.yml`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext GitHub tokens detected in Copilot CLI config files',
      failed: (n) => `Found ${n} plaintext GitHub token(s) in Copilot CLI config`,
      fixDescription: 'Revoke the token at https://github.com/settings/tokens; let Copilot store auth via keychain or gh CLI integration',
    });
  },
});

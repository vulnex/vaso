import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const API_KEY_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI API key' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, name: 'Anthropic API key' },
  { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub PAT' },
  { pattern: /gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth token' },
  { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/, name: 'GitLab PAT' },
  { pattern: /xoxb-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack Bot token' },
  { pattern: /xoxp-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack User token' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: 'Private key' },
];

export const cfg002: CheckModule = {
  id: 'CFG-002',
  name: 'API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check for exposed API keys and secrets in config files',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Skip .env files — they're expected to contain keys
      if (config.format === 'env') continue;

      const lines = config.raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          if (pattern.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 80) + (lines[i].trim().length > 80 ? '...' : ''),
              detail: `Found ${name}`,
            });
          }
        }
      }
    }

    return {
      id: 'CFG-002',
      name: 'API Key Exposure',
      category: 'config',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No API keys found in config files'
        : `Found ${evidence.length} exposed API key(s) in config files`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

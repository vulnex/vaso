import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';

const XOR_CIPHER_PATTERN = /\benc:[A-Za-z0-9+\/=]+/g;

export const zc002: CheckModule = {
  id: 'ZC-002',
  name: 'XOR Encryption',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect values using legacy XOR cipher (enc: prefix), which is trivially reversible',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const lines = config.raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(XOR_CIPHER_PATTERN);
        if (matches) {
          for (const match of matches) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 120),
              detail: `Legacy XOR-encrypted value found: ${match.slice(0, 20)}... — trivially reversible`,
            });
          }
        }
      }
    }

    return {
      id: 'ZC-002',
      name: 'XOR Encryption',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No legacy XOR-encrypted values found'
        : `Found ${evidence.length} value(s) using trivially reversible XOR cipher`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Re-encrypt secrets using zeroclaw secrets encrypt with AES-256',
    };
  },

  async fix(_ctx: ScanContext): Promise<FixResult> {
    return { checkId: 'ZC-002', applied: false, message: 'Manual action required: re-encrypt secrets using "zeroclaw secrets encrypt" with AES-256 to replace XOR-encrypted values' };
  },
};

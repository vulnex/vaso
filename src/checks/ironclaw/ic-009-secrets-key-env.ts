import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic009: CheckModule = {
  id: 'IC-009',
  name: 'Secrets Master Key in .env',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if SECRETS_MASTER_KEY is stored in a .env file instead of a keychain or vault',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const masterKey =
        (config.data.SECRETS_MASTER_KEY as string | undefined) ??
        (getNestedValue(config.data, 'secrets.master_key') as string | undefined) ??
        (getNestedValue(config.data, 'secrets.masterKey') as string | undefined);

      if (masterKey && masterKey.trim() !== '') {
        // Only flag if the value is in a file (not just referencing an env var placeholder)
        const isPlaceholder = /^\$\{?[A-Z_]+\}?$/.test(masterKey.trim());
        if (!isPlaceholder) {
          evidence.push({
            file: config.filePath,
            detail: `SECRETS_MASTER_KEY found in config file — should use system keychain or vault instead`,
          });
        }
      }

      // Also check raw content for .env files specifically
      if (config.format === 'env' && config.raw.includes('SECRETS_MASTER_KEY')) {
        const lines = config.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line.startsWith('SECRETS_MASTER_KEY') && line.includes('=')) {
            const value = line.split('=').slice(1).join('=').trim().replace(/^["']|["']$/g, '');
            if (value && !/^\$\{?[A-Z_]+\}?$/.test(value)) {
              const alreadyCaught = evidence.some(e => e.file === config.filePath);
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  line: i + 1,
                  snippet: `SECRETS_MASTER_KEY=${value.slice(0, 4)}${'*'.repeat(Math.max(0, value.length - 4))}`,
                  detail: 'Plaintext secrets master key in .env file',
                });
              }
            }
          }
        }
      }
    }

    return {
      id: 'IC-009',
      name: 'Secrets Master Key in .env',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No plaintext secrets master key found in config files'
        : 'SECRETS_MASTER_KEY found in config file — should use keychain/vault',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Remove SECRETS_MASTER_KEY from .env and store it in the system keychain or a secrets vault',
    };
  },
};

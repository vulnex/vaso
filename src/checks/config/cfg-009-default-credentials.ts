import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const WEAK_PATTERNS = [
  /\bpassword\b/i,
  /\b(admin|root|test|demo|default|changeme|password123|12345|qwerty)\b/i,
];

const CREDENTIAL_KEYS = ['password', 'secret', 'token', 'api_key', 'apiKey', 'auth_token'];

import { getNestedValue } from '../../core/utils.js';

export const cfg009 = defineCheck({
  id: 'CFG-009',
  name: 'Default/Weak Credentials',
  category: 'config',
  severity: 'critical',
  description: 'Check for default or weak credentials in config files',

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Check structured data for known credential keys
      for (const key of CREDENTIAL_KEYS) {
        const paths = [key, `auth.${key}`, `gateway.auth.${key}`, `security.${key}`];
        for (const path of paths) {
          const value = getNestedValue(config.data, path);
          if (typeof value === 'string') {
            for (const pattern of WEAK_PATTERNS) {
              if (pattern.test(value)) {
                evidence.push({
                  file: config.filePath,
                  detail: `Weak credential in "${path}": value matches common default pattern`,
                });
                break;
              }
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No default or weak credentials found',
      failed: (n) => `Found ${n} default/weak credential(s)`,
    });
  },
});

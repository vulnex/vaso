import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const WEAK_PATTERNS = [
  /\bpassword\b/i,
  /\b(admin|root|test|demo|default|changeme|password123|12345|qwerty)\b/i,
];

const CREDENTIAL_KEYS = ['password', 'secret', 'token', 'api_key', 'apiKey', 'auth_token'];

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

export const cfg009: CheckModule = {
  id: 'CFG-009',
  name: 'Default/Weak Credentials',
  category: 'config',
  severity: 'critical',
  description: 'Check for default or weak credentials in config files',

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'CFG-009',
      name: 'Default/Weak Credentials',
      category: 'config',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No default or weak credentials found'
        : `Found ${evidence.length} default/weak credential(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

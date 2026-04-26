import { homedir } from 'node:os';
import { join, normalize } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const HOME = homedir();

interface SensitiveTarget {
  path: string;
  reason: string;
}

const SENSITIVE_TARGETS: SensitiveTarget[] = [
  { path: join(HOME, '.ssh'), reason: 'contains SSH private keys' },
  { path: join(HOME, '.aws'), reason: 'contains AWS credentials' },
  { path: join(HOME, '.gnupg'), reason: 'contains GPG private keys' },
  { path: join(HOME, '.kube'), reason: 'contains Kubernetes credentials' },
  { path: join(HOME, '.docker'), reason: 'contains Docker registry credentials' },
  { path: join(HOME, '.netrc'), reason: 'contains plaintext FTP/HTTP credentials' },
  { path: '/etc', reason: 'system configuration directory' },
  { path: '/var', reason: 'system runtime/log directory' },
  { path: '/root', reason: 'root user home directory' },
];

function expandHome(p: string): string {
  if (p === '~') return HOME;
  if (p.startsWith('~/')) return join(HOME, p.slice(2));
  return p;
}

function matchesSensitive(dir: string): SensitiveTarget | undefined {
  const normalized = normalize(expandHome(dir));
  return SENSITIVE_TARGETS.find(t => normalized === t.path || normalized.startsWith(t.path + '/'));
}

export const cc009: CheckModule = {
  id: 'CC-009',
  name: 'Sensitive Additional Directories',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when permissions.additionalDirectories grants Claude Code access to credential or system directories',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const dirs = getNestedValue(config.data, 'permissions.additionalDirectories') as unknown;
      if (!Array.isArray(dirs)) continue;

      for (const entry of dirs) {
        if (typeof entry !== 'string') continue;
        const match = matchesSensitive(entry);
        if (match) {
          evidence.push({
            file: config.filePath,
            snippet: entry,
            detail: `Grants access to ${match.path} — ${match.reason}`,
          });
        }
      }
    }

    return {
      id: 'CC-009',
      name: 'Sensitive Additional Directories',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No sensitive paths in permissions.additionalDirectories'
        : `Found ${evidence.length} sensitive path(s) in permissions.additionalDirectories`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Remove credential/system directories from permissions.additionalDirectories',
    };
  },
};

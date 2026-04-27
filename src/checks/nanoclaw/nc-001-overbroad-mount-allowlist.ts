import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SENSITIVE_LITERALS = new Set([
  '/',
  '/etc',
  '/etc/',
  '/root',
  '/root/',
  '/var',
  '/var/log',
  '/usr',
  '/boot',
  '/proc',
  '/sys',
]);

const SENSITIVE_HOME_SUFFIXES = [
  '.ssh',
  '.aws',
  '.gnupg',
  '.config',
  '.kube',
  '.docker',
  '.npmrc',
  '.netrc',
  '.git-credentials',
];

const ROOT_GLOBS = new Set(['/*', '/**', '*', '**']);

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return home + p.slice(1);
  return p;
}

function classify(rawPath: string, home: string): string | null {
  const expanded = expandHome(rawPath, home);
  const trimmed = expanded.replace(/\/+$/, '');

  if (ROOT_GLOBS.has(rawPath)) return `Root glob "${rawPath}" grants the entire filesystem`;
  if (SENSITIVE_LITERALS.has(rawPath) || SENSITIVE_LITERALS.has(rawPath + '/')) {
    return `Path "${rawPath}" exposes a sensitive system directory`;
  }
  if (trimmed === home) return `Path "${rawPath}" exposes the entire user home directory`;

  for (const suffix of SENSITIVE_HOME_SUFFIXES) {
    if (trimmed === `${home}/${suffix}` || trimmed === `/home/${suffix}` || rawPath === `~/${suffix}`) {
      return `Path "${rawPath}" exposes credentials directory ~/${suffix}`;
    }
  }
  return null;
}

export const nc001 = defineCheck({
  id: 'NC-001',
  name: 'Overbroad Mount Allowlist',
  category: 'nanoclaw',
  severity: 'critical',
  description: 'Detect mount-allowlist.json entries that grant the agent access to the entire filesystem, system directories (/etc, /root), or credential locations (~/.ssh, ~/.aws, ~/.gnupg).',
  supportedAgents: ['nanoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('mount-allowlist.json')) continue;

      const data = config.data;
      const candidates = [
        data.allowedPaths,
        data.allowed_paths,
        data.mounts,
        data.paths,
      ].find(v => Array.isArray(v)) as unknown[] | undefined;

      if (!candidates) continue;

      for (const entry of candidates) {
        const path = typeof entry === 'string'
          ? entry
          : (entry && typeof entry === 'object' && 'path' in entry ? (entry as { path: string }).path : undefined);
        if (!path) continue;

        const issue = classify(path, home);
        if (issue) {
          evidence.push({ file: config.filePath, detail: issue });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Mount allowlist contains no overbroad or sensitive paths',
      failed: (n) => `Mount allowlist grants ${n} overbroad / sensitive path${n === 1 ? '' : 's'}`,
    });
  },
});

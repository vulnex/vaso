import { join, normalize } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';

interface SensitiveTarget {
  path: string;
  reason: string;
  /** Sensitive only as a whole: a folder inside it (`~/src/app`) is fine. */
  broad?: boolean;
}

function buildSensitiveTargets(home: string): SensitiveTarget[] {
  return [
    { path: '/', reason: 'root of the filesystem — covers every credential directory', broad: true },
    { path: home, reason: 'entire user home directory — covers ~/.ssh, ~/.aws and every other credential store', broad: true },
    { path: join(home, '.ssh'), reason: 'contains SSH private keys' },
    { path: join(home, '.aws'), reason: 'contains AWS credentials' },
    { path: join(home, '.gnupg'), reason: 'contains GPG private keys' },
    { path: join(home, '.kube'), reason: 'contains Kubernetes credentials' },
    { path: join(home, '.docker'), reason: 'contains Docker registry credentials' },
    { path: join(home, '.netrc'), reason: 'contains plaintext FTP/HTTP credentials' },
    { path: '/etc', reason: 'system configuration directory' },
    { path: '/var', reason: 'system runtime/log directory' },
    { path: '/root', reason: 'root user home directory' },
  ];
}

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

function isWithin(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir.endsWith('/') ? dir : dir + '/');
}

/** A grant covers a sensitive path when it is that path, one of its parents
 *  (`/`, `~`, `/Users` all expose `~/.ssh`), or — except for broad ones —
 *  inside it. Same rule as CD-007. */
function matchesSensitive(dir: string, targets: SensitiveTarget[], home: string): SensitiveTarget | undefined {
  const normalized = normalize(expandHome(dir, home)).replace(/(.)\/+$/, '$1');
  return targets.find(t => isWithin(t.path, normalized) || (!t.broad && isWithin(normalized, t.path)));
}

export const cc009 = defineCheck({
  id: 'CC-009',
  name: 'Sensitive Additional Directories',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when permissions.additionalDirectories or sandbox.filesystem.allowWrite grants Claude Code access to credential or system directories',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const sensitiveTargets = buildSensitiveTargets(home);

    for (const config of ctx.configs) {
      const dirs = getNestedValue(config.data, 'permissions.additionalDirectories') as unknown;
      if (!Array.isArray(dirs)) continue;

      for (const entry of dirs) {
        if (typeof entry !== 'string') continue;
        const match = matchesSensitive(entry, sensitiveTargets, home);
        if (match) {
          evidence.push({
            file: config.filePath,
            snippet: entry,
            detail: `Grants access to ${match.path} — ${match.reason}`,
          });
        }
      }
    }

    // sandbox.filesystem.allowWrite: paths sandboxed commands may write —
    // and with sandbox.autoAllowBashIfSandboxed those commands run without a
    // prompt. Write access to the home or filesystem root, SSH config or a
    // shell startup file is code execution outside the sandbox (critical);
    // to another credential store, a warning (the settings reference's own
    // example opens ~/.kube).
    let critical = evidence.length > 0;
    for (const config of ctx.configs) {
      const paths = getNestedValue(config.data, 'sandbox.filesystem.allowWrite') as unknown;
      if (!Array.isArray(paths)) continue;
      for (const entry of paths) {
        if (typeof entry !== 'string') continue;
        const abs = normalize(expandHome(entry, home)).replace(/(.)\/+$/, '$1');
        // /var holds build caches and temp dirs (macOS /var/folders) — writing there is routine
        const found = matchesSensitive(entry, sensitiveTargets, home);
        const match = found?.path === '/var' ? undefined : found;
        const startup = classifySensitivePath(abs).find(l => l.startsWith('shell startup'));
        if (!match && !startup) continue;
        const severe = !!startup || match!.broad === true || match!.path === join(home, '.ssh') || match!.path === '/etc' || match!.path === '/root';
        if (severe) critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.filesystem.allowWrite: ${entry}`,
          detail: `Sandboxed commands may write ${startup ? `a ${startup}` : `${match!.path} — ${match!.reason}`}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      severity: critical ? 'critical' : 'warning',
      passed: 'No sensitive paths in permissions.additionalDirectories',
      failed: (n) => `Found ${n} sensitive path(s) in permissions.additionalDirectories / sandbox.filesystem.allowWrite`,
      fixDescription: 'Remove credential/system directories from permissions.additionalDirectories and sandbox.filesystem.allowWrite',
    });
  },
});

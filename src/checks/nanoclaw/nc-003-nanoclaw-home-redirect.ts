import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const WORLD_WRITABLE_PREFIXES = ['/tmp/', '/var/tmp/', '/private/tmp/', '/dev/shm/'];

function isWorldWritable(path: string): boolean {
  return WORLD_WRITABLE_PREFIXES.some(p => path.startsWith(p)) || path === '/tmp' || path === '/var/tmp';
}

export const nc003 = defineCheck({
  id: 'NC-003',
  name: 'NANOCLAW_HOME Redirected to Risky Location',
  category: 'nanoclaw',
  severity: 'warning',
  description: 'Detect when NANOCLAW_HOME (in `.nanoclaw.env` or the process environment) points the agent\'s runtime directory outside the user home, especially into world-writable locations where any local user can tamper with state and skills.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const userHome = ctx.fs.homedir();

    const sources: { value: string; file: string }[] = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('.nanoclaw.env')) continue;
      const v = config.data.NANOCLAW_HOME;
      if (typeof v === 'string' && v.trim()) {
        sources.push({ value: v.trim(), file: config.filePath });
      }
    }
    if (process.env.NANOCLAW_HOME) {
      sources.push({ value: process.env.NANOCLAW_HOME, file: '<process env>' });
    }

    let highest: 'warning' | 'critical' = 'warning';
    for (const { value, file } of sources) {
      const insideHome = value.startsWith(userHome + '/') || value === userHome;
      const worldWritable = isWorldWritable(value);
      if (insideHome && !worldWritable) continue;

      if (worldWritable) {
        highest = 'critical';
        evidence.push({
          file,
          detail: `NANOCLAW_HOME=${value} — world-writable directory; any local user can tamper with agent state`,
        });
      } else {
        evidence.push({
          file,
          detail: `NANOCLAW_HOME=${value} — outside user home (${userHome}); review whether the redirect is intended`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'NANOCLAW_HOME is unset or points inside the user home',
      failed: () => 'NANOCLAW_HOME redirects the agent runtime to a risky location',
      severity: highest,
    });
  },
});

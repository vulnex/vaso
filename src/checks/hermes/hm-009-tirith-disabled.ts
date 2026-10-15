import { join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { isTruthy } from '../../adapters/hermes-api-server.js';

/**
 * TIRITH_ENABLED / TIRITH_FAIL_OPEN override security.tirith_enabled /
 * tirith_fail_open (hermes-agent tools/tirith_security.py): a non-blank value
 * is true only when in the truthy set (1/true/yes/on), so TIRITH_ENABLED=false
 * turns scanning off; blank values fall back to config.yaml (PR #133910).
 * Hermes loads ~/.hermes/.env into its environment, so both places count.
 */
function envOverride(ctx: ScanContext, name: string): { value: boolean; source: string; file?: string } | undefined {
  for (const c of ctx.configs) {
    if (c.format !== 'env') continue;
    const v = c.data[name];
    if (typeof v === 'string' && v.trim()) return { value: isTruthy(v.trim()), source: `${name}=${v.trim()}`, file: c.filePath };
  }
  const v = ctx.fs.getEnv(name)?.trim();
  return v ? { value: isTruthy(v), source: `${name}=${v} (process environment)` } : undefined;
}

function expandHome(p: string, ctx: ScanContext): string {
  if (p === '~') return ctx.fs.homedir();
  if (p.startsWith('~/')) return join(ctx.fs.homedir(), p.slice(2));
  return p;
}

/**
 * Whether the tirith binary is available: security.tirith_path when set, the
 * copy Hermes auto-installs at $HERMES_HOME/bin/tirith (not on PATH), or PATH.
 */
async function tirithPresent(ctx: ScanContext, config: ParsedConfig): Promise<boolean> {
  const configured = getNestedValue(config.data, 'security.tirith_path');
  const candidates = [
    ...(typeof configured === 'string' && configured.trim() && configured.trim() !== 'tirith'
      ? [expandHome(configured.trim(), ctx)]
      : []),
    join(ctx.installation.installDir, 'bin', 'tirith'),
  ];
  for (const c of candidates) {
    try {
      if (await ctx.fs.access(c)) return true;
    } catch {
      // not visible — try the next location
    }
  }
  try {
    return ctx.fs.execSync('which', ['tirith'], { timeout: 3000 }).trim().length > 0;
  } catch {
    return false;
  }
}

export const hm009 = defineCheck({
  id: 'HM-009',
  name: 'Hermes Tirith Pre-Exec Scanner Disabled or Fail-Open',
  category: 'hermes',
  severity: 'warning',
  description: 'security.tirith_enabled is false (or TIRITH_ENABLED=false), OR tirith_fail_open is true (default) and the tirith binary is missing — pre-execution dangerous-command scanning is silently disabled.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const enabledEnv = envOverride(ctx, 'TIRITH_ENABLED');
    const failOpenEnv = envOverride(ctx, 'TIRITH_FAIL_OPEN');
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('cli-config.yaml') && !config.filePath.endsWith('config.yaml')) continue;

      const enabled = getNestedValue(config.data, 'security.tirith_enabled');
      if (enabledEnv ? !enabledEnv.value : enabled === false) {
        evidence.push({
          file: enabledEnv?.file ?? config.filePath,
          snippet: enabledEnv ? enabledEnv.source : 'security.tirith_enabled: false',
          detail: 'Tirith pre-exec scanner explicitly disabled — agent-suggested commands run unscanned',
        });
        continue;
      }

      // Default is fail_open: true. If the binary is missing, scanning silently no-ops.
      const failOpen = getNestedValue(config.data, 'security.tirith_fail_open');
      const failOpenEffective = failOpenEnv ? failOpenEnv.value : failOpen !== false;
      if (failOpenEffective && !(await tirithPresent(ctx, config))) {
        evidence.push({
          file: config.filePath,
          snippet: `${failOpenEnv ? failOpenEnv.source : `security.tirith_fail_open: ${failOpen ?? '<default true>'}`} (binary missing)`,
          detail: 'Tirith fail-open is enabled and no tirith binary was found (tirith_path, $HERMES_HOME/bin/tirith or PATH) — pre-exec scanning silently does nothing',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Tirith pre-exec scanner is enabled and reachable',
      failed: (n) => `Found ${n} Tirith configuration issue(s) — dangerous-command scanning may be inactive`,
      fixDescription: 'Set security.tirith_enabled: true and security.tirith_fail_open: false (and remove TIRITH_ENABLED=false from the environment / .env); install tirith ($HERMES_HOME/bin or PATH)',
    });
  },
});

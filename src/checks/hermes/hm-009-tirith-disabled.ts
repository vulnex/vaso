import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isTruthy } from '../../adapters/hermes-api-server.js';
import { byHermesPrecedence, hermesYamlSetting } from '../../adapters/hermes-managed.js';
import { hermesConfigAsWritten } from '../../adapters/hermes-config.js';
import { compareVersions } from '../../core/semver.js';

/**
 * TIRITH_ENABLED / TIRITH_FAIL_OPEN override security.tirith_enabled /
 * tirith_fail_open (hermes-agent tools/tirith_security.py): a non-blank value
 * is true only when in the truthy set (1/true/yes/on), so TIRITH_ENABLED=false
 * turns scanning off; blank values fall back to config.yaml (PR #133910).
 * Hermes loads ~/.hermes/.env into its environment — and the administrator-
 * managed .env over it — so all of them count, managed first.
 */
function envOverride(ctx: ScanContext, name: string): { value: boolean; source: string; file?: string } | undefined {
  for (const c of byHermesPrecedence(ctx.configs)) {
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
async function tirithPresent(ctx: ScanContext, configured: unknown): Promise<boolean> {
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

/** Config version whose migration removed tirith (hermes-agent commit 911da42). */
const TIRITH_REMOVED_CONFIG_VERSION = 50;
/** The first release without it. */
const TIRITH_REMOVED_RELEASE = '0.21.6';

function isAtLeast(version: string | undefined, release: string): boolean {
  return !!version && /^v?\d+\.\d+\.\d+/.test(version) && compareVersions(version.replace(/^v/, ''), release) >= 0;
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
    // One effective config: the user's config.yaml with the administrator-
    // managed one merged over it (each setting from the file that wins)
    const yamls = ctx.configs.filter(c => c.filePath.endsWith('cli-config.yaml') || c.filePath.endsWith('config.yaml'));
    const primary = yamls.find(c => !c.managed) ?? yamls[0];
    // Hermes removed the bundled tirith scanner (hermes-agent 911da42,
    // 2026-10-06, first released in 0.21.6): config migration 50 drops
    // security.tirith_*. A config at v50+ — written by such a release, also
    // when that release now rejects the file and runs on defaults — or the
    // release itself has no scanner to disable or fail open.
    const version = Number(primary
      ? hermesYamlSetting(yamls, '_config_version')?.value ?? hermesConfigAsWritten(primary)._config_version
      : undefined);
    const removed = (Number.isFinite(version) && version >= TIRITH_REMOVED_CONFIG_VERSION)
      || isAtLeast(ctx.installation.version, TIRITH_REMOVED_RELEASE);
    if (primary && !removed) {
      const enabled = hermesYamlSetting(yamls, 'security.tirith_enabled');
      const failOpen = hermesYamlSetting(yamls, 'security.tirith_fail_open');
      if (enabledEnv ? !enabledEnv.value : enabled?.value === false) {
        evidence.push({
          file: enabledEnv?.file ?? enabled?.file ?? primary.filePath,
          snippet: enabledEnv ? enabledEnv.source : 'security.tirith_enabled: false',
          detail: 'Tirith pre-exec scanner explicitly disabled — agent-suggested commands run unscanned',
        });
      } else if ((failOpenEnv ? failOpenEnv.value : failOpen?.value !== false)
          // Default is fail_open: true. If the binary is missing, scanning silently no-ops.
          && !(await tirithPresent(ctx, hermesYamlSetting(yamls, 'security.tirith_path')?.value))) {
        evidence.push({
          file: failOpenEnv?.file ?? failOpen?.file ?? primary.filePath,
          snippet: `${failOpenEnv ? failOpenEnv.source : `security.tirith_fail_open: ${failOpen?.value ?? '<default true>'}`} (binary missing)`,
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

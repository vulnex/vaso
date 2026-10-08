import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

const BYPASS_KEYS = ['auth.bypass', 'gateway.auth.bypass', 'security.authBypass', 'noAuth'];

function bypassKey(data: Record<string, unknown>): string | undefined {
  return BYPASS_KEYS.find(k => getNestedValue(data, k) !== undefined);
}

function isTrue(v: unknown): boolean {
  return v === true || v === 'true' || v === 1;
}

export const cfg012 = defineCheck({
  id: 'CFG-012',
  name: 'Auth Bypass Enabled',
  category: 'config',
  severity: 'critical',
  description: 'Check if authentication bypass is enabled in configuration',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let bypassFlag = false;

    for (const config of ctx.configs) {
      const authBypass = bypassKey(config.data) !== undefined ? getNestedValue(config.data, bypassKey(config.data)!) : undefined;

      if (isTrue(authBypass)) {
        bypassFlag = true;
        evidence.push({
          file: config.filePath,
          detail: 'Authentication bypass is enabled',
        });
      }

      const authMode = getNestedValue(config.data, 'gateway.auth.mode') ??
                       getNestedValue(config.data, 'auth.mode');

      if (authMode === 'none' || authMode === 'disabled') {
        evidence.push({
          file: config.filePath,
          detail: `Auth mode set to "${authMode}"`,
        });
      }
    }

    return h.result({
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Authentication bypass is not enabled'
        : 'Authentication bypass is enabled — anyone can access the agent',
      evidence,
      // Only an explicit bypass flag can be switched off safely; an auth mode
      // of "none" needs a real token or password (OpenClaw: gateway.auth.mode
      // "token" plus gateway.auth.token), which a fix can't invent.
      fixable: bypassFlag,
      fixDescription: bypassFlag
        ? 'Turn the auth bypass flag off'
        : 'Set an auth mode with a credential (e.g. OpenClaw: `openclaw config set gateway.auth.mode token` and a gateway.auth.token)',
    });
  },

  async fix(ctx) {
    // Flip the flag that is set, in the file it is in — never add a new key
    for (const config of ctx.configs) {
      const key = bypassKey(config.data);
      if (key && isTrue(getNestedValue(config.data, key))) {
        return fixFirstConfig([config], { checkId: 'CFG-012', path: key, value: false, message: `Set ${key} to false` });
      }
    }
    return { checkId: 'CFG-012', applied: false, message: 'No auth bypass flag is set (auth mode "none" needs a credential configured by hand)' };
  },
});

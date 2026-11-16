import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

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

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let bypassFlag = false;

    // An OpenClaw sub-agent's own file can't change the host-wide gateway
    // (2026.9.4 reads gateway settings from openclaw.json only); a weaker
    // gateway section there is OC-001's sub-agent downgrade finding
    const subAgentFile = (file: string) => ctx.installation.agent === 'openclaw' && Boolean(ctx.installation.agentName)
      && file.startsWith(ctx.installation.installDir + '/');
    const gatewayKey = (key: string) => key.startsWith('gateway.');

    for (const config of ctx.configs) {
      const ownFile = subAgentFile(config.filePath);
      const key = bypassKey(config.data);
      const authBypass = key !== undefined && !(ownFile && gatewayKey(key)) ? getNestedValue(config.data, key) : undefined;

      if (isTrue(authBypass)) {
        bypassFlag = true;
        evidence.push({
          file: config.filePath,
          detail: 'Authentication bypass is enabled',
        });
      }

      const authMode = (ownFile ? undefined : getNestedValue(config.data, 'gateway.auth.mode')) ??
                       getNestedValue(config.data, 'auth.mode');

      if (authMode === 'none' || authMode === 'disabled') {
        evidence.push({
          file: config.filePath,
          detail: `Auth mode set to "${authMode}"`,
        });
      }

      // OpenClaw 2026.x: skips the Control UI's device pairing/identity check
      // (2026.9.4 schema gateway.controlUi.dangerouslyDisableDeviceAuth), so
      // the gateway credential alone admits a browser.
      if (!ownFile && getNestedValue(config.data, 'gateway.controlUi.dangerouslyDisableDeviceAuth') === true
          && getNestedValue(config.data, 'gateway.controlUi.enabled') !== false) {
        evidence.push({
          file: config.filePath,
          detail: 'gateway.controlUi.dangerouslyDisableDeviceAuth: true — Control UI device authentication is off',
        });
      }
    }

    return h.result({
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Authentication bypass is not enabled'
        : evidence.every(e => e.detail?.startsWith('gateway.controlUi.dangerouslyDisableDeviceAuth'))
          ? 'Control UI device authentication is disabled — the gateway credential alone admits any browser'
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
      if (key && isTrue(getNestedValue(config.data, key))
          && !(ctx.installation.agent === 'openclaw' && ctx.installation.agentName
            && config.filePath.startsWith(ctx.installation.installDir + '/') && key.startsWith('gateway.'))) {
        return fixFirstConfig([config], { checkId: 'CFG-012', path: key, value: false, message: `Set ${key} to false` });
      }
    }
    return { checkId: 'CFG-012', applied: false, message: 'No auth bypass flag is set (auth mode "none" needs a credential configured by hand)' };
  },
});

import { defineCheck, type CheckHelpers } from '../../core/check-builder.js';
import type { ScanContext } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { NATIVE_POLICY_FRAMEWORKS } from './native-policy-frameworks.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

/**
 * OpenClaw 2026.x: host exec policy is `tools.exec.mode` (deny | allowlist |
 * ask | auto | full), or the legacy `tools.exec.security` it replaces. Unset
 * means "full" on gateway/node hosts — any command runs. Its schema rejects
 * unknown keys and mixed mode/legacy objects, so this is guidance only:
 * `openclaw config set` validates the change.
 */
function openclawExecPolicy(ctx: ScanContext, h: CheckHelpers) {
  let effective = 'full';
  let source = 'default';
  for (const config of ctx.configs) {
    const mode = getNestedValue(config.data, 'tools.exec.mode');
    const legacy = getNestedValue(config.data, 'tools.exec.security');
    if (typeof mode === 'string') { effective = mode; source = 'tools.exec.mode'; break; }
    if (typeof legacy === 'string') { effective = legacy; source = 'tools.exec.security'; break; }
  }
  const unrestricted = effective === 'full';
  return h.result({
    passed: !unrestricted,
    message: unrestricted
      ? `Host exec policy is "full" (${source === 'default' ? 'OpenClaw default' : source}) — the agent can run any command without an allowlist`
      : `Host exec policy is "${effective}" (${source})`,
    fixable: false,
    fixDescription: 'Run `openclaw config set tools.exec.mode ask` (allowlist, ask on misses) or `allowlist`; replace any legacy tools.exec.security/ask in the same object',
  });
}

export const cfg005 = defineCheck({
  id: 'CFG-005',
  name: 'Missing Shell Allowlist',
  category: 'config',
  severity: 'warning',
  description: 'Check if a shell command allowlist (safeBins) is configured',
  // Atomic Agent has no shell allowlist key — its shell gate is the approval ladder (AT-001).
  // The other frameworks listed gate commands in their own schemas (framework checks);
  // writing security.safeBins into them makes strict config loaders reject the file.
  // Hermes gates commands through approvals (HM-008; its command_allowlist
  // auto-approves rather than restricts) and NemoClaw through sandbox policy.
  excludedAgents: [...CODING_AGENTS, ...NATIVE_POLICY_FRAMEWORKS, 'hermes', 'nemoclaw'],

  async run(ctx, h) {
    if (ctx.installation.agent === 'openclaw') return openclawExecPolicy(ctx, h);
    let found = false;

    for (const config of ctx.configs) {
      const safeBins = getNestedValue(config.data, 'security.safeBins') ??
                       getNestedValue(config.data, 'safeBins') ??
                       getNestedValue(config.data, 'shell.allowlist') ??
                       config.data.SAFE_BINS;

      if (safeBins && (Array.isArray(safeBins) ? safeBins.length > 0 : true)) {
        found = true;
        break;
      }
    }

    return h.result({
      passed: found,
      message: found
        ? 'Shell command allowlist (safeBins) is configured'
        : 'No shell command allowlist — agents can execute any command',
      // The fix writes into the first config file; without one there is nothing to fix
      fixable: ctx.configs.length > 0,
      fixDescription: 'Add safeBins allowlist to config',
    });
  },

  async fix(ctx) {
    const safeBins = ['ls', 'cat', 'grep', 'head', 'tail', 'wc', 'echo', 'date'];
    return fixFirstConfig(ctx.configs, {
      checkId: 'CFG-005',
      env: 'SAFE_BINS',
      path: 'security.safeBins',
      value: safeBins,
      envValue: safeBins.join(','),
      message: 'Added safeBins allowlist with safe defaults',
      noConfigMessage: 'No config file found',
    });
  },
});

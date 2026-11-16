import { defineCheck, type CheckHelpers } from '../../core/check-builder.js';
import type { Evidence, ScanContext } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { NATIVE_POLICY_FRAMEWORKS } from './native-policy-frameworks.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import { openclawAgentEntries } from './openclaw-agents.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

/** The exec policy one OpenClaw `tools.exec` object selects: `mode`, else the legacy `security`. */
function execPolicy(exec: unknown): { value: string; key: string } | undefined {
  if (!exec || typeof exec !== 'object') return undefined;
  const { mode, security } = exec as Record<string, unknown>;
  if (typeof mode === 'string') return { value: mode, key: 'mode' };
  if (typeof security === 'string') return { value: security, key: 'security' };
  return undefined;
}

/**
 * OpenClaw 2026.x: host exec policy is `tools.exec.mode` (deny | allowlist |
 * ask | auto | full), or the legacy `tools.exec.security` it replaces, and an
 * agent entry (`agents.entries.<id>.tools.exec`) overrides it for that agent.
 * Unset means "full" on gateway/node hosts — any command runs. Every file and
 * entry is read (a sub-agent's file or one entry set to "full" exposes that
 * agent even when openclaw.json is strict). Its schema rejects unknown keys
 * and mixed mode/legacy objects, so this is guidance only: `openclaw config
 * set` validates the change.
 */
function openclawExecPolicy(ctx: ScanContext, h: CheckHelpers) {
  const evidence: Evidence[] = [];
  const set: string[] = [];
  for (const config of ctx.configs) {
    const policy = execPolicy(getNestedValue(config.data, 'tools.exec'));
    if (!policy) continue;
    set.push(`${policy.value} (tools.exec.${policy.key})`);
    if (policy.value === 'full') {
      evidence.push({ file: config.filePath, detail: `tools.exec.${policy.key}: full` });
    }
  }
  for (const entry of openclawAgentEntries(ctx.configs)) {
    const policy = execPolicy(getNestedValue(entry.data, 'tools.exec'));
    if (policy?.value === 'full') {
      evidence.push({ file: entry.config.filePath, detail: `agents.entries.${entry.id}.tools.exec.${policy.key}: full` });
    }
  }
  if (set.length === 0) {
    evidence.push({
      file: ctx.configs[0]?.filePath ?? ctx.installation.installDir,
      detail: 'tools.exec.mode not set — OpenClaw default is "full"',
    });
  }
  return h.result({
    passed: evidence.length === 0,
    message: evidence.length === 0
      ? `Host exec policy is ${set.join(', ')}`
      : `Host exec policy is "full" (${evidence.map(e => e.detail).join('; ')}) — the agent can run any command without an allowlist`,
    evidence,
    fixable: false,
    fixDescription: 'Run `openclaw config set tools.exec.mode ask` (allowlist, ask on misses) or `allowlist` (and for each agent entry set to "full"); replace any legacy tools.exec.security/ask in the same object',
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

  fixTargets: configFixTargets,

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

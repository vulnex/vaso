import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import { openclawAgentEntries } from './openclaw-agents.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

function sandboxKey(data: Record<string, unknown>): string | undefined {
  // agents.defaults.sandbox.mode: OpenClaw 2026.x (off | non-main | all)
  return ['sandbox', 'security.sandbox', 'isolation', 'agents.defaults.sandbox.mode'].find(k => getNestedValue(data, k) !== undefined);
}

function isOff(v: unknown): boolean {
  return v === false || v === 'disabled' || v === 'off' || v === 'none';
}

export const cfg008 = defineCheck({
  id: 'CFG-008',
  name: 'Sandbox Disabled',
  category: 'config',
  severity: 'critical',
  description: 'Check if code sandbox/isolation is disabled',
  excludedAgents: CODING_AGENTS,

  fixTargets: configFixTargets,

  async run(ctx, h) {
    for (const config of ctx.configs) {
      const key = sandboxKey(config.data);
      const sandbox = key ? getNestedValue(config.data, key) : undefined;

      if (isOff(sandbox)) {
        return h.result({
          passed: false,
          message: 'Code sandbox is explicitly disabled — skills run without isolation',
          evidence: [{ file: config.filePath, detail: `${key}: ${String(sandbox)}` }],
          // A boolean switch can be flipped in place; a string mode's enabled
          // value differs per framework, so that is left to the user
          fixable: sandbox === false,
          fixDescription: `Enable sandbox mode (${key}), then give the sandbox at least two constraints (exec, filesystem, network) — POL-004 reports an enabled sandbox without them`,
        });
      }
    }

    // OpenClaw: agents.entries.<id>.sandbox.mode overrides agents.defaults for that agent
    const entries = openclawAgentEntries(ctx.configs)
      .filter(e => isOff(getNestedValue(e.data, 'sandbox.mode')));
    if (entries.length > 0) {
      return h.result({
        passed: false,
        message: `Code sandbox is disabled for agent ${entries.map(e => `"${e.id}"`).join(', ')} — its tools run without isolation`,
        evidence: entries.map(e => ({ file: e.config.filePath, detail: `agents.entries.${e.id}.sandbox.mode: off` })),
        fixable: false,
        fixDescription: 'Set agents.entries.<id>.sandbox.mode to "non-main" or "all" (`openclaw config set`)',
      });
    }

    return h.passed('Sandbox is not explicitly disabled');
  },

  // Flip the switch that is off, in the file it is in — never add a key
  async fix(ctx) {
    for (const config of ctx.configs) {
      const key = sandboxKey(config.data);
      if (key && getNestedValue(config.data, key) === false) {
        return fixFirstConfig([config], { checkId: 'CFG-008', path: key, value: true, message: `Set ${key} to true — add sandbox constraints by hand (POL-004 checks them)` });
      }
    }
    return { checkId: 'CFG-008', applied: false, message: 'No boolean sandbox switch is turned off' };
  },
});

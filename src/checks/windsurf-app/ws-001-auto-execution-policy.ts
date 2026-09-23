import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

/** Read a windsurf.* editor setting — flat VS Code key or nested object form. */
function windsurfSetting(data: Record<string, unknown>, key: string): unknown {
  const flat = data[`windsurf.${key}`];
  if (flat !== undefined) return flat;
  const ns = data.windsurf;
  if (ns && typeof ns === 'object') return (ns as Record<string, unknown>)[key];
  return undefined;
}

export const ws001 = defineCheck({
  id: 'WS-001',
  name: 'Windsurf Auto-Execution Policy',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Cascade auto-execution policy set to turbo or auto, which runs terminal commands without approval',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let hasTurbo = false;

    for (const config of ctx.configs) {
      const policy = windsurfSetting(config.data, 'autoExecutionPolicy');
      if (typeof policy !== 'string') continue;
      const value = policy.toLowerCase();
      if (value === 'turbo') {
        hasTurbo = true;
        evidence.push({
          file: config.filePath,
          snippet: `windsurf.autoExecutionPolicy: "${policy}"`,
          detail: 'Turbo mode auto-executes ALL terminal commands Cascade proposes — no human approval gate at all',
        });
      } else if (value === 'auto') {
        evidence.push({
          file: config.filePath,
          snippet: `windsurf.autoExecutionPolicy: "${policy}"`,
          detail: 'Auto mode lets Cascade decide which commands run without approval — prompt-injected commands can self-approve',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Windsurf auto-execution policy requires approval for commands',
      failed: (n) => `Found ${n} config(s) with unsafe Windsurf auto-execution policy`,
      // 'turbo' is unconditional execution → critical; 'auto' alone → warning.
      severity: hasTurbo ? 'critical' : 'warning',
      fixDescription: 'Set windsurf.autoExecutionPolicy to "off" (or "allowlist" with a narrow deny-first list) in settings.json',
    });
  },
});

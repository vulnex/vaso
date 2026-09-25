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
  description: 'Detect Cascade auto-execution policy set to turbo or auto (settings.json, or user_settings.pb on 3.x), and turbo web-request auto-execution — both run actions without approval',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let hasTurbo = false;
    let policyFound = false;

    // Sources: legacy editor settings.json (`windsurf.autoExecutionPolicy`) and,
    // on 3.x, ~/.codeium/windsurf/user_settings.pb projected onto the same keys.
    for (const config of ctx.configs) {
      const policy = windsurfSetting(config.data, 'autoExecutionPolicy');
      if (typeof policy === 'string') {
        policyFound = true;
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

      const webPolicy = windsurfSetting(config.data, 'webRequestsAutoExecutionPolicy');
      if (typeof webPolicy === 'string' && webPolicy.toLowerCase() === 'turbo') {
        evidence.push({
          file: config.filePath,
          snippet: `windsurf.webRequestsAutoExecutionPolicy: "${webPolicy}"`,
          detail: 'Web requests auto-execute for any origin — an injected prompt can fetch attacker URLs (data exfiltration via query strings) without approval',
        });
      }
    }

    if (evidence.length === 0 && !policyFound) {
      return h.passed('No explicit Cascade auto-execution policy set (settings.json / user_settings.pb) — product default applies');
    }

    return h.fromEvidence(evidence, {
      passed: 'Windsurf auto-execution policy requires approval for commands',
      failed: (n) => `Found ${n} unsafe Windsurf auto-execution setting(s)`,
      // 'turbo' is unconditional execution → critical; 'auto' / web turbo → warning.
      severity: hasTurbo ? 'critical' : 'warning',
      fixDescription: 'Set Cascade auto-execution to "Off" or "Auto" with a narrow allowlist (Settings → Cascade → Auto Execution; windsurf.autoExecutionPolicy on legacy builds), and keep web-request auto-execution on an allowlist',
    });
  },
});

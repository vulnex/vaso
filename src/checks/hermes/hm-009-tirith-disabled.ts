import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const hm009 = defineCheck({
  id: 'HM-009',
  name: 'Hermes Tirith Pre-Exec Scanner Disabled or Fail-Open',
  category: 'hermes',
  severity: 'warning',
  description: 'security.tirith_enabled is false, OR tirith_fail_open is true (default) and the tirith binary is missing — pre-execution dangerous-command scanning is silently disabled.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('cli-config.yaml') && !config.filePath.endsWith('config.yaml')) continue;

      const enabled = getNestedValue(config.data, 'security.tirith_enabled');
      if (enabled === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'security.tirith_enabled: false',
          detail: 'Tirith pre-exec scanner explicitly disabled — agent-suggested commands run unscanned',
        });
        continue;
      }

      // Default is fail_open: true. If the binary isn't on PATH, scanning silently no-ops.
      const failOpen = getNestedValue(config.data, 'security.tirith_fail_open');
      const failOpenEffective = failOpen !== false; // undefined or true → fail-open
      if (failOpenEffective) {
        let binaryPresent = false;
        try {
          const result = ctx.fs.execSync('which', ['tirith'], { timeout: 3000 }).trim();
          binaryPresent = result.length > 0;
        } catch {
          binaryPresent = false;
        }
        if (!binaryPresent) {
          evidence.push({
            file: config.filePath,
            snippet: `security.tirith_fail_open: ${failOpen ?? '<default true>'} (binary missing)`,
            detail: 'Tirith fail-open is enabled and the tirith binary is not on PATH — pre-exec scanning silently does nothing',
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Tirith pre-exec scanner is enabled and reachable',
      failed: (n) => `Found ${n} Tirith configuration issue(s) — dangerous-command scanning may be inactive`,
      fixDescription: 'Set security.tirith_enabled: true and security.tirith_fail_open: false; install tirith on PATH',
    });
  },
});

import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const pol002 = defineCheck({
  id: 'POL-002',
  name: 'Log Redaction',
  category: 'policy',
  severity: 'warning',
  description: 'Verify logging has secret redaction configured when logging is enabled',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const loggingEnabled = getNestedValue(config.data, 'logging.enabled') ??
                             getNestedValue(config.data, 'log.enabled') ??
                             getNestedValue(config.data, 'logs');

      if (loggingEnabled === true || loggingEnabled === 'true' || (typeof loggingEnabled === 'object' && loggingEnabled !== null)) {
        const redaction = getNestedValue(config.data, 'logging.redact') ??
                          getNestedValue(config.data, 'logRedaction') ??
                          getNestedValue(config.data, 'redactSecrets') ??
                          getNestedValue(config.data, 'log.redact') ??
                          getNestedValue(config.data, 'logging.redactSecrets');

        if (!redaction) {
          evidence.push({
            file: config.filePath,
            detail: 'Logging is enabled but no secret redaction is configured',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Log redaction is properly configured or logging is not enabled',
      failed: (n) => `Found ${n} config(s) with logging enabled but no redaction`,
    });
  },
});

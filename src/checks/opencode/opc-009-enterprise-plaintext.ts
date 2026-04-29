import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const opc009 = defineCheck({
  id: 'OPC-009',
  name: 'OpenCode Enterprise URL Plaintext',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when enterprise.url is set to plaintext HTTP — well-known config and tokens travel unencrypted',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const url = getNestedValue(config.data, 'enterprise.url');
      if (typeof url === 'string' && url.startsWith('http://')) {
        evidence.push({
          file: config.filePath,
          snippet: `enterprise.url = ${url}`,
          detail: 'Enterprise endpoint uses plaintext HTTP — config payload and bearer tokens travel unencrypted',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode enterprise URL uses HTTPS (or is unset)',
      failed: () => 'OpenCode enterprise URL uses plaintext HTTP',
      fixDescription: 'Change enterprise.url to https:// in opencode.json',
    });
  },
});

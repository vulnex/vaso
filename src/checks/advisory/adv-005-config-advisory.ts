import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { getNestedValue } from '../../core/utils.js';

export const adv005 = defineCheck({
  id: 'ADV-005',
  name: 'Config-Based Advisory',
  category: 'advisory',
  severity: 'critical',
  description: 'Match agent configurations against advisory config patterns',

  async run(ctx, h) {
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const configAdvisories = db.advisories.filter(adv => {
      if (!adv.configPattern) return false;
      return adv.agent === agent || adv.agent === '*';
    });

    if (configAdvisories.length === 0) return h.passed('No config-pattern advisories in database');

    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      for (const adv of configAdvisories) {
        const pattern = adv.configPattern!;
        const value = getNestedValue(config.data, pattern.key);
        if (value === undefined || value === null) continue;

        const valueStr = String(value);
        const re = new RegExp(pattern.valuePattern);
        if (re.test(valueStr)) {
          evidence.push({
            file: config.filePath,
            detail: `${adv.id}: ${adv.title} — config key "${pattern.key}" = "${valueStr}" matches dangerous pattern`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No config patterns match known advisories',
      failed: (n) => `${n} config${n === 1 ? '' : 's'} match${n === 1 ? 'es' : ''} known advisory patterns`,
    });
  },
});

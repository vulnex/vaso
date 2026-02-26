import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { getNestedValue } from '../../core/utils.js';

export const adv005: CheckModule = {
  id: 'ADV-005',
  name: 'Config-Based Advisory',
  category: 'advisory',
  severity: 'critical',
  description: 'Match agent configurations against advisory config patterns',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const configAdvisories = db.advisories.filter(adv => {
      if (!adv.configPattern) return false;
      return adv.agent === agent || adv.agent === '*';
    });

    if (configAdvisories.length === 0) {
      return {
        id: 'ADV-005',
        name: 'Config-Based Advisory',
        category: 'advisory',
        severity: 'critical',
        passed: true,
        message: 'No config-pattern advisories in database',
      };
    }

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

    return {
      id: 'ADV-005',
      name: 'Config-Based Advisory',
      category: 'advisory',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No config patterns match known advisories'
        : `${evidence.length} config${evidence.length === 1 ? '' : 's'} match${evidence.length === 1 ? 'es' : ''} known advisory patterns`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

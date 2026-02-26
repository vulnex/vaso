import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';

export const adv003: CheckModule = {
  id: 'ADV-003',
  name: 'End-of-Life Version',
  category: 'advisory',
  severity: 'warning',
  description: 'Detect end-of-life agent versions that no longer receive security patches',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const version = ctx.installation.version;
    if (!version) {
      return {
        id: 'ADV-003',
        name: 'End-of-Life Version',
        category: 'advisory',
        severity: 'warning',
        passed: true,
        message: 'Agent version not detected — skipping EOL check',
      };
    }

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const eolAdvisories = db.advisories.filter(adv => {
      if (!adv.eolNotice) return false;
      if (adv.agent !== agent && adv.agent !== '*') return false;
      return satisfies(version, adv.affectedVersions);
    });

    if (eolAdvisories.length === 0) {
      return {
        id: 'ADV-003',
        name: 'End-of-Life Version',
        category: 'advisory',
        severity: 'warning',
        passed: true,
        message: `${agent} v${version} is not end-of-life`,
      };
    }

    const evidence = eolAdvisories.map(adv => ({
      file: adv.id,
      detail: `${adv.id}: ${adv.description}`,
    }));

    return {
      id: 'ADV-003',
      name: 'End-of-Life Version',
      category: 'advisory',
      severity: 'warning',
      passed: false,
      message: `${agent} v${version} is end-of-life and no longer receives security patches`,
      evidence,
    };
  },
};

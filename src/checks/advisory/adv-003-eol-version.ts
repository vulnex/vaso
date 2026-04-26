import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';

export const adv003 = defineCheck({
  id: 'ADV-003',
  name: 'End-of-Life Version',
  category: 'advisory',
  severity: 'warning',
  description: 'Detect end-of-life agent versions that no longer receive security patches',

  async run(ctx, h) {
    const version = ctx.installation.version;
    if (!version) return h.passed('Agent version not detected — skipping EOL check');

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const eolAdvisories = db.advisories.filter(adv => {
      if (!adv.eolNotice) return false;
      if (adv.agent !== agent && adv.agent !== '*') return false;
      return satisfies(version, adv.affectedVersions);
    });

    if (eolAdvisories.length === 0) return h.passed(`${agent} v${version} is not end-of-life`);

    const evidence = eolAdvisories.map(adv => ({
      file: adv.id,
      detail: `${adv.id}: ${adv.description}`,
    }));

    return h.result({
      passed: false,
      message: `${agent} v${version} is end-of-life and no longer receives security patches`,
      evidence,
    });
  },
});

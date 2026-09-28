import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';
import { describeAffected, describeVersion, installedVersions, type InstalledVersion } from './installed-versions.js';

export const adv003 = defineCheck({
  id: 'ADV-003',
  name: 'End-of-Life Version',
  category: 'advisory',
  severity: 'warning',
  description: 'Detect end-of-life agent versions that no longer receive security patches',

  async run(ctx, h) {
    const versions = installedVersions(ctx.installation);
    if (versions.length === 0) return h.passed('Agent version not detected — skipping EOL check');

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const eolNotices = db.advisories.filter(adv => adv.eolNotice && (adv.agent === agent || adv.agent === '*'));

    const evidence = [];
    const affected: InstalledVersion[] = [];
    for (const v of versions) {
      const matching = eolNotices.filter(adv => satisfies(v.version, adv.affectedVersions));
      if (matching.length === 0) continue;
      affected.push(v);
      for (const adv of matching) {
        evidence.push({
          file: v.path ?? adv.id,
          detail: `${adv.id}: ${adv.description}${v.path ? ` — installed copy ${describeVersion(v)}` : ''}`,
        });
      }
    }

    if (affected.length === 0) return h.passed(`${agent} ${versions.map(describeVersion).join(', ')} is not end-of-life`);

    return h.result({
      passed: false,
      message: `${describeAffected(agent, affected)} is end-of-life and no longer receives security patches`,
      evidence,
    });
  },
});

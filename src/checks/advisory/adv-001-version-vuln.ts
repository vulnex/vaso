import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';

export const adv001: CheckModule = {
  id: 'ADV-001',
  name: 'Known Framework Vulnerability',
  category: 'advisory',
  severity: 'critical',
  description: 'Check installed agent version against known CVEs and security advisories',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const version = ctx.installation.version;
    if (!version) {
      return {
        id: 'ADV-001',
        name: 'Known Framework Vulnerability',
        category: 'advisory',
        severity: 'critical',
        passed: true,
        message: 'Agent version not detected — skipping advisory check',
      };
    }

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const matching = db.advisories.filter(adv => {
      if (!adv.tags?.includes('framework')) return false;
      if (adv.agent !== agent && adv.agent !== '*') return false;
      if (adv.eolNotice) return false; // handled by ADV-003
      return satisfies(version, adv.affectedVersions);
    });

    if (matching.length === 0) {
      return {
        id: 'ADV-001',
        name: 'Known Framework Vulnerability',
        category: 'advisory',
        severity: 'critical',
        passed: true,
        message: `No known vulnerabilities for ${agent} v${version}`,
      };
    }

    const evidence = matching.map(adv => ({
      file: adv.reference ?? adv.id,
      detail: `${adv.id}: ${adv.title} (severity: ${adv.severity}${adv.fixedVersion ? `, fix: v${adv.fixedVersion}` : ''})`,
    }));

    return {
      id: 'ADV-001',
      name: 'Known Framework Vulnerability',
      category: 'advisory',
      severity: 'critical',
      passed: false,
      message: `${matching.length} known vulnerabilit${matching.length === 1 ? 'y' : 'ies'} affect ${agent} v${version}`,
      evidence,
    };
  },
};

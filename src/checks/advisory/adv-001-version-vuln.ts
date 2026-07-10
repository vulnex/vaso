import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';

export const adv001 = defineCheck({
  id: 'ADV-001',
  name: 'Known Framework Vulnerability',
  category: 'advisory',
  severity: 'critical',
  description: 'Check installed agent version against known CVEs and security advisories',

  async run(ctx, h) {
    const version = ctx.installation.version;
    if (!version) return h.passed('Agent version not detected — skipping advisory check');

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const matching = db.advisories.filter(adv => {
      // Version-based agent advisories: framework CVEs and coding-agent CVEs
      // (e.g. GhostApproval). Dependency/MCP-package advisories are ADV-002's
      // job and carry no such tag, so they're excluded here.
      if (!adv.tags?.includes('framework') && !adv.tags?.includes('coding-agent')) return false;
      if (adv.agent !== agent && adv.agent !== '*') return false;
      if (adv.eolNotice) return false; // handled by ADV-003
      return satisfies(version, adv.affectedVersions);
    });

    if (matching.length === 0) return h.passed(`No known vulnerabilities for ${agent} v${version}`);

    const evidence = matching.map(adv => ({
      file: adv.reference ?? adv.id,
      detail: `${adv.id}: ${adv.title} (severity: ${adv.severity}${adv.fixedVersion ? `, fix: v${adv.fixedVersion}` : ''})`,
    }));

    return h.result({
      passed: false,
      message: `${matching.length} known vulnerabilit${matching.length === 1 ? 'y' : 'ies'} affect ${agent} v${version}`,
      evidence,
    });
  },
});

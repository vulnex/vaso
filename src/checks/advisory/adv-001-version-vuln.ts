import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';
import { advisoryAppliesToPlatform, advisoryVersionOptions } from '../../advisory/applicability.js';
import { describeAffected, describeVersion, installedVersions, type InstalledVersion } from './installed-versions.js';

export const adv001 = defineCheck({
  id: 'ADV-001',
  name: 'Known Framework Vulnerability',
  category: 'advisory',
  severity: 'critical',
  description: 'Check installed agent version against known CVEs and security advisories',

  async run(ctx, h) {
    const versions = installedVersions(ctx.installation);
    if (versions.length === 0) return h.passed('Agent version not detected — skipping advisory check');

    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const candidates = db.advisories.filter(adv => {
      // Version-based agent advisories: framework CVEs and coding-agent CVEs
      // (e.g. GhostApproval). Dependency/MCP-package advisories are ADV-002's
      // job and carry no such tag, so they're excluded here.
      if (!adv.tags?.includes('framework') && !adv.tags?.includes('coding-agent')) return false;
      if (adv.agent !== agent && adv.agent !== '*') return false;
      if (!advisoryAppliesToPlatform(adv, ctx.platform)) return false;
      return !adv.eolNotice; // EOL notices are ADV-003's
    });
    const versionOpts = advisoryVersionOptions(agent);

    // Every installed copy is evaluated: an older copy left on disk stays runnable.
    const evidence = [];
    const affected: InstalledVersion[] = [];
    const advisoryIds = new Set<string>();
    const matchedSeverities = new Set<string>();
    for (const v of versions) {
      const matching = candidates.filter(adv => satisfies(v.version, adv.affectedVersions, versionOpts));
      if (matching.length === 0) continue;
      affected.push(v);
      for (const adv of matching) {
        advisoryIds.add(adv.id);
        matchedSeverities.add(adv.severity);
        evidence.push({
          file: v.path ?? adv.reference ?? adv.id,
          detail: `${adv.id}: ${adv.title} (severity: ${adv.severity}${adv.fixedVersion ? `, fix: v${adv.fixedVersion}` : ''})${v.path ? ` — affects installed copy ${describeVersion(v)}` : ''}`,
        });
      }
    }

    if (affected.length === 0) {
      return h.passed(`No known vulnerabilities for ${agent} ${versions.map(describeVersion).join(', ')}`);
    }

    // Report at the most severe matched advisory's level (the check default is critical)
    const severity = matchedSeverities.has('critical') ? 'critical' : matchedSeverities.has('warning') ? 'warning' : 'info';
    const n = advisoryIds.size;
    return h.result({
      passed: false,
      severity,
      message: `${n} known vulnerabilit${n === 1 ? 'y affects' : 'ies affect'} ${describeAffected(agent, affected)}`,
      evidence,
    });
  },
});

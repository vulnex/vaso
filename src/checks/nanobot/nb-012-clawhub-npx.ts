import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const nb012 = defineCheck({
  id: 'NB-012',
  name: 'npx Skill Installation',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if skills are installed via npx (supply chain risk from unverified packages)',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const skillSource = getNestedValue(config.data, 'skillSource')
        ?? getNestedValue(config.data, 'skills.source')
        ?? getNestedValue(config.data, 'skills.installMethod');

      if (typeof skillSource === 'string' && skillSource.toLowerCase().includes('npx')) {
        evidence.push({
          file: config.filePath,
          detail: `skillSource is set to "${skillSource}" — skills installed via npx without version pinning`,
        });
      }

      const raw = config.raw;
      const npxPattern = /\bnpx\s+[@a-zA-Z0-9\-_/]+/g;
      const matches = raw.match(npxPattern);
      if (matches) {
        for (const match of matches) {
          evidence.push({
            file: config.filePath,
            snippet: match,
            detail: `npx invocation found: "${match}" — runs unverified remote code on every execution`,
          });
        }
      }

      const skills = config.data.skills;
      if (skills && typeof skills === 'object') {
        const skillEntries = Array.isArray(skills)
          ? skills
          : Object.entries(skills).map(([name, val]) => ({ name, ...(typeof val === 'object' && val !== null ? val : {}) }));

        for (const skill of skillEntries) {
          const s = skill as Record<string, unknown>;
          const cmd = s.command ?? s.cmd ?? s.run;
          if (typeof cmd === 'string' && cmd.includes('npx')) {
            evidence.push({
              file: config.filePath,
              snippet: String(cmd).slice(0, 120),
              detail: `Skill "${s.name ?? 'unnamed'}" uses npx — supply chain risk from unverified package execution`,
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'No npx-based skill installations found',
      failed: (n) => `Found ${n} npx-based skill reference(s) — supply chain risk`,
      fixable: true,
      fixDescription: 'Install skills locally with pinned versions instead of using npx for remote execution',
    });
  },

  async fix() {
    return { checkId: 'NB-012', applied: false, message: 'Manual action required: install skills locally with pinned versions instead of using npx for remote execution' };
  },
});

import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const nb012: CheckModule = {
  id: 'NB-012',
  name: 'npx Skill Installation',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if skills are installed via npx (supply chain risk from unverified packages)',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      // Check skillSource config
      const skillSource = getNestedValue(config.data, 'skillSource')
        ?? getNestedValue(config.data, 'skills.source')
        ?? getNestedValue(config.data, 'skills.installMethod');

      if (typeof skillSource === 'string' && skillSource.toLowerCase().includes('npx')) {
        evidence.push({
          file: config.filePath,
          detail: `skillSource is set to "${skillSource}" — skills installed via npx without version pinning`,
        });
      }

      // Check for npx references in raw config
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

      // Check skills array/object for npx-based entries
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
    return {
      id: 'NB-012', name: 'npx Skill Installation', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No npx-based skill installations found'
        : `Found ${evidence.length} npx-based skill reference(s) — supply chain risk`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Install skills locally with pinned versions instead of using npx for remote execution',
    };
  },
};

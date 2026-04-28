import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const EXECUTABLE_EXTS = ['.ts', '.js', '.mjs', '.py', '.sh'];

export const ly014 = defineCheck({
  id: 'LY-014',
  name: 'Executable Skill Files Outside Shield Scope',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect executable skill files (.ts/.js/.py/.sh) in the skills directory. Lyrie\'s SkillManager Shield filter applies to declarative SKILL.md content; executable code paths are run by the skill\'s own loader and may not pass through the Shield gate.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join(ctx.installation.installDir, 'skills');
    if (!(await ctx.fs.access(skillsDir))) return h.passed('Skills directory not present');

    const evidence: Evidence[] = [];
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir, { recursive: true });
      const executables = entries.filter(e => {
        if (!e.isFile) return false;
        const lower = e.name.toLowerCase();
        return EXECUTABLE_EXTS.some(ext => lower.endsWith(ext));
      });

      if (executables.length > 0) {
        evidence.push({
          file: skillsDir,
          detail: `${executables.length} executable skill file(s) found — confirm each is registered through SkillManager so Shield scans its output`,
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'No executable skill files found outside Shield scope',
      failed: () => 'Executable skill files present — verify Shield coverage',
      fixDescription: 'Audit each .ts/.js/.py skill: register it through Lyrie\'s SkillManager so its output passes through `SkillManager.shieldFilter`, or move it out of the skills directory',
    });
  },
});

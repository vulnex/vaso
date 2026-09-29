import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

const EXECUTABLE_EXTS = ['.ts', '.js', '.mjs', '.cjs', '.py', '.sh'];

/**
 * Lyrie's SkillLoader only reads SKILL.md manifests (prompt content that
 * passes the Shield's input scan); code shipped beside them runs when the
 * agent invokes it through its exec/code tools, where the Shield applies
 * only its fixed dangerous-command patterns. Inventory, not a verdict — the
 * SKL-* checks analyze the code itself.
 */
export const ly014 = defineCheck({
  id: 'LY-014',
  name: 'Executable Code in Lyrie Skills Directory',
  category: 'lyrie',
  severity: 'info',
  description: 'Inventory executable files (.ts/.js/.py/.sh) in ~/.lyrie/skills. Lyrie loads skills as SKILL.md prompt manifests; bundled scripts run when a skill tells the agent to execute them, where the Shield only applies its fixed dangerous-command patterns. Review their provenance (SKL-* checks analyze the code).',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join(lyrieStateDir(ctx.fs), 'skills');
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
        const names = executables.slice(0, 5).map(e => e.name).join(', ');
        evidence.push({
          file: skillsDir,
          detail: `${executables.length} executable file(s) in skills (${names}${executables.length > 5 ? ', …' : ''}) — verify their source before the agent runs them`,
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'No executable code in the skills directory',
      failed: () => 'Executable code present in the skills directory',
      fixDescription: 'Review each script\'s origin; remove skills you did not install deliberately (migrated skills land here too)',
    });
  },
});

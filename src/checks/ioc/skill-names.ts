import type { ScanContext } from '../../core/types.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { listSkills, skillFrontmatterName } from '../../core/skill-walk.js';

export interface NamedSkill {
  dir: string;
  /** Directory name, plus the SKILL.md frontmatter `name:` when it differs —
   *  agents list and invoke a skill by the frontmatter name. */
  names: string[];
}

/** Every skill of the installation with the names it goes by. */
export async function namedSkills(ctx: ScanContext): Promise<NamedSkill[]> {
  const skills = await listSkills(ctx.fs, getAllSkillsDirs(ctx.installation), {
    rootIsSkill: ctx.installation.agent === 'skill-audit',
  });
  const out: NamedSkill[] = [];
  for (const skill of skills) {
    const declared = await skillFrontmatterName(ctx.fs, skill.dir);
    out.push({ dir: skill.dir, names: declared && declared !== skill.name ? [skill.name, declared] : [skill.name] });
  }
  return out;
}

/** Name segments split on `-`, `_`, `.` and spaces, lowercased. */
export function nameSegments(name: string): string[] {
  return name.toLowerCase().split(/[-_.\s]+/).filter(Boolean);
}

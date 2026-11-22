import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { listSkills } from '../../core/skill-walk.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { noSkillsDirResult } from '../skills/skill-files.js';
import { parseFrontmatter } from '../claude-code/subagents.js';

/** Names a metadata object gives its author or publisher (`author`, `author.name`, `publisher`, `metadata.author`). */
function authorsOf(data: unknown): string[] {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];
  const rec = data as Record<string, unknown>;
  const out: string[] = [];
  const take = (v: unknown) => {
    if (typeof v === 'string') out.push(v);
    else if (v && typeof v === 'object' && !Array.isArray(v) && typeof (v as { name?: unknown }).name === 'string') {
      out.push((v as { name: string }).name);
    }
  };
  take(rec.author);
  take(rec.publisher);
  // Agent Skills spec: client-defined keys live under `metadata`
  const meta = rec.metadata;
  if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
    take((meta as Record<string, unknown>).author);
    take((meta as Record<string, unknown>).publisher);
  }
  return out.map(a => a.trim().toLowerCase()).filter(Boolean);
}

export const ioc004 = defineCheck({
  id: 'IOC-004',
  name: 'Malicious Publishers',
  category: 'ioc',
  severity: 'critical',
  description: 'Check skill metadata (package.json, skill.json, metadata.json, SKILL.md frontmatter) for known malicious publishers',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const publisherSet = new Set(db.maliciousPublishers.map(p => p.toLowerCase()));
    const skillsDirs = getAllSkillsDirs(ctx.installation);
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const skills = await listSkills(ctx.fs, skillsDirs, { rootIsSkill: ctx.installation.agent === 'skill-audit' });
    for (const skill of skills) {
      const report = (file: string, data: unknown) => {
        const author = authorsOf(data).find(a => publisherSet.has(a));
        if (author) evidence.push({ file, detail: `Skill "${skill.name}" by known malicious publisher: ${author}` });
      };
      for (const metaFile of ['package.json', 'skill.json', 'metadata.json']) {
        const metaPath = join(skill.dir, metaFile);
        try {
          report(metaPath, JSON.parse(await ctx.fs.readFile(metaPath)));
        } catch {}
      }
      const skillMd = join(skill.dir, 'SKILL.md');
      try {
        report(skillMd, parseFrontmatter(await ctx.fs.readFile(skillMd)));
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious publishers found',
      failed: (n) => `Found ${n} skill(s) from known malicious publishers`,
    });
  },
});

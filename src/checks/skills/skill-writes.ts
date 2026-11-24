import { basename, dirname, join, relative, sep } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { relEscapes } from '../../core/utils.js';
import { firstSkillWrite, type WriteLang } from '../../analyzers/skill-writes.js';
import { packageScripts, readSkillSource } from './skill-source.js';
import { skillsDirsOf } from './skill-files.js';

const isSkillMd = (file: string) => basename(file).toUpperCase() === 'SKILL.MD';
const within = (dir: string, path: string) => path === dir || !relEscapes(relative(dir, path));

/**
 * The skill a file belongs to: the outermost folder holding a SKILL.md
 * between the file and its skills directory; without one, the skills
 * directory's top-level entry the file sits in (the directory itself for a
 * file directly in it).
 */
export function skillRootOf(file: string, roots: readonly string[], skillMdDirs: ReadonlySet<string>): string {
  const root = roots.filter(r => within(r, file)).sort((a, b) => b.length - a.length)[0];
  if (!root) return dirname(file);
  let best: string | undefined;
  for (let d = dirname(file); ; d = dirname(d)) {
    if (skillMdDirs.has(d)) best = d;
    if (d === root || dirname(d) === d || !within(root, d)) break;
  }
  if (best) return best;
  const parts = relative(root, file).split(sep);
  return parts.length > 1 ? join(root, parts[0]) : root;
}

/**
 * For SKL-003: the first place the skill of a file can write or download a
 * file (`relative/path:line, what`), or undefined when nothing in it can —
 * every file of the skill read (scripts in their language, Markdown code and
 * package.json scripts as shell commands). A file of the skill that can't be
 * read (binary code, unreadable, over the size limit) or a folder that can't
 * be listed counts: what it does isn't known. Computed once per skill.
 */
export function skillWriteFinder(ctx: ScanContext, files: readonly string[]): (file: string) => Promise<string | undefined> {
  const roots = skillsDirsOf(ctx);
  const skillMdDirs = new Set(files.filter(isSkillMd).map(f => dirname(f)));
  const cache = new Map<string, Promise<string | undefined>>();
  const find = async (skill: string): Promise<string | undefined> => {
    const label = (f: string) => relative(skill, f) || basename(f);
    for (const dir of ctx.skillUnlistableDirs ?? []) {
      if (within(skill, dir)) return `${label(dir)}/ can't be listed`;
    }
    for (const file of files) {
      if (!within(skill, file) || skillRootOf(file, roots, skillMdDirs) !== skill) continue;
      let src;
      try {
        src = await readSkillSource(ctx, file, 'patterns', 'code');
      } catch {
        return `${label(file)} can't be read`;
      }
      if (!src || src.kind === 'data') continue;
      let text = src.text;
      let lang: WriteLang;
      if (src.kind === 'manifest') {
        // one script per line, at its key's line
        const lines: string[] = [];
        for (const s of packageScripts(src)) lines[s.line - 1] = `${lines[s.line - 1] ?? ''} ; ${s.command.replace(/\n/g, ' ')}`;
        text = Array.from(lines, l => l ?? '').join('\n');
        lang = 'shell';
      } else if (src.kind === 'markdown') {
        lang = 'shell';
      } else {
        lang = src.lang === 'js' || src.lang === 'python' ? src.lang
          : src.lang === 'shell' || src.lang === 'batch' || src.lang === 'powershell' ? 'shell' : 'other';
      }
      const w = firstSkillWrite(text, lang);
      if (w) return `${label(file)}:${w.line}, ${w.what}`;
    }
    return undefined;
  };
  return (file: string) => {
    const skill = skillRootOf(file, roots, skillMdDirs);
    let hit = cache.get(skill);
    if (!hit) cache.set(skill, hit = find(skill));
    return hit;
  };
}

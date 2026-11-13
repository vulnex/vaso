import { basename, dirname, join, relative, isAbsolute, sep } from 'node:path';
import type { DirentInfo, FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, AgentInventory, SkillItem, SkillTreeEntry, SkillsDirInfo } from '../core/types.js';
import { getAllSkillsDirs, isExcludedPath, listSkillTree } from '../core/utils.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { redactSecretsInLine } from '../core/patterns.js';
import { maskCredentialsInLine } from '../reporting/serialize.js';

/** Longest description carried into reports. */
export const MAX_SKILL_DESCRIPTION = 200;
/** SKILL.md bytes read for the frontmatter. */
const FRONTMATTER_READ = 8192;

export interface SkillInventoryResult {
  /** The files skill/IOC checks read, across every skills directory —
   *  undefined when the installation declares none (ScanContext.skillFiles). */
  files: string[] | undefined;
  inventory: AgentInventory;
}

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

const isSkillMd = (path: string) => basename(path).toUpperCase() === 'SKILL.MD';

/**
 * The skills an installation loads, from one walk per skills directory —
 * the same walk (and file list) the skill checks use, so the counts match
 * what a scan reads. A skill is the outermost folder holding a SKILL.md;
 * anything else directly under a skills directory is an "other entry".
 */
export async function collectSkillInventory(installation: AgentInstallation, fs: FSProvider): Promise<SkillInventoryResult> {
  const roots = [...new Set(getAllSkillsDirs(installation))];
  const scope: SkillItem['scope'] = installation.profile === 'project' ? 'project' : 'user';
  const skillsDirs: SkillsDirInfo[] = [];
  const skills: SkillItem[] = [];
  const otherEntries: SkillTreeEntry[] = [];
  const incomplete: string[] = [];
  const allFiles: string[] = [];

  for (const root of roots) {
    const listing = await listSkillTree(root, fs);
    const missing = listing.error !== undefined && isMissing(listing.error);
    skillsDirs.push({ path: root, exists: !missing });
    allFiles.push(...listing.files);
    if (listing.error && !missing) {
      incomplete.push(`${root}: can't be listed (${listing.error.code ?? listing.error.message})`);
    }
    for (const dir of listing.unlistable) incomplete.push(`${dir}: contents can't be listed`);

    // A SKILL.md that is a symlink into the same tree (gstack links each
    // skill's SKILL.md to its copy under skills/gstack/): the walk doesn't
    // follow it — the checks read the target where it is — but the agent
    // loads the skill. The skill's files are counted at the link's target.
    const linked = new Map<string, string>(); // skill dir → target dir
    for (const entry of listing.entries) {
      if (!entry.isSymbolicLink || !isSkillMd(entry.name)) continue;
      const parent = entry.parentPath ?? root;
      if (isExcludedPath(root, parent, { keepBuildOutput: true })) continue;
      const target = await inTreeTarget(fs, root, join(parent, entry.name));
      if (target) linked.set(parent, dirname(target));
    }

    // Outermost folders holding a SKILL.md: a SKILL.md inside a skill (an
    // example, a bundled sub-skill) belongs to it
    const candidates = [...new Set([...listing.files.filter(isSkillMd).map(f => dirname(f)), ...linked.keys()])]
      .sort((a, b) => a.split(sep).length - b.split(sep).length || a.localeCompare(b));
    const skillDirs: string[] = [];
    for (const dir of candidates) {
      if (!skillDirs.some(s => isWithin(dir, s))) skillDirs.push(dir);
    }

    for (const dir of skillDirs) {
      const contentDir = linked.get(dir) ?? dir;
      const files = listing.files.filter(f => isWithin(f, contentDir));
      const skillMd = linked.has(dir) ? join(dir, 'SKILL.md') : files.find(f => dirname(f) === dir && isSkillMd(f));
      const front = skillMd ? await readFrontmatter(fs, skillMd) : {};
      const target = linked.has(dir) ? contentDir : await symlinkTarget(fs, dir);
      skills.push({
        name: front.name ?? basename(dir),
        path: dir,
        root,
        scope,
        kind: 'skill-md',
        ...(front.description ? { description: front.description } : {}),
        files: files.length,
        hasCode: files.some(f => !isSkillMd(f)),
        ...(target ? { symlinkTarget: target } : {}),
      });
    }

    // Direct children with no skill in or around them: folders, and files
    // the skill checks read (a loose script). Dotfiles and vendor dirs aren't
    // something an agent loads. A plain listing, not the walk: a snapshot's
    // recursive listing holds files only, so an empty folder or one holding
    // no collected file would be missing from it.
    if (missing || listing.error) continue;
    let children: DirentInfo[];
    try {
      children = await fs.readdirEntries(root);
    } catch {
      continue;
    }
    for (const entry of children) {
      if (entry.name.startsWith('.')) continue;
      const path = join(root, entry.name);
      if (isExcludedPath(root, path, { keepBuildOutput: true })) continue;
      if (skillDirs.some(s => isWithin(s, path) || isWithin(path, s))) continue;
      const files = listing.files.filter(f => isWithin(f, path));
      // a symlink is a folder unless it leads to one file the checks read
      const isFile = entry.isFile || (entry.isSymbolicLink === true && files.length === 1 && files[0] === path);
      if (!isFile && (entry.isDirectory || entry.isSymbolicLink)) {
        otherEntries.push({ path, root, type: 'directory', files: files.length, hasCode: files.length > 0 });
      } else if (isFile && files.length > 0) {
        otherEntries.push({ path, root, type: 'file', files: 1, hasCode: true });
      }
    }
  }

  const inventory: AgentInventory = {
    skillsDirs,
    skills,
    otherEntries,
    ...(incomplete.length > 0 ? { incomplete } : {}),
  };
  return { files: roots.length > 0 ? allFiles : undefined, inventory };
}

/** Attach the skill inventory to each installation (detect). */
export async function attachSkillInventories(installations: AgentInstallation[], fs: FSProvider): Promise<void> {
  await Promise.all(installations.map(async (inst) => {
    inst.inventory = (await collectSkillInventory(inst, fs)).inventory;
  }));
}

/** The directory isn't there — locally (ENOENT/ENOTDIR) or in a snapshot, whose
 *  "not collected" errors carry the code in the message only. */
function isMissing(err: NodeJS.ErrnoException): boolean {
  return err.code === 'ENOENT' || err.code === 'ENOTDIR' || (err.code === undefined && /^ENOENT\b/.test(err.message ?? ''));
}

/**
 * Where a symlink inside the tree leads, as a path under `root` (the walk's
 * spelling), when it resolves to a file inside the same tree; undefined for
 * a dangling link or one leading out (the walk followed that one already).
 */
async function inTreeTarget(fs: FSProvider, root: string, link: string): Promise<string | undefined> {
  try {
    const [real, rootReal] = await Promise.all([fs.realpath(link), fs.realpath(root)]);
    if (!isWithin(real, rootReal) || !(await fs.access(real))) return undefined;
    return join(root, relative(rootReal, real));
  } catch {
    return undefined;
  }
}

async function symlinkTarget(fs: FSProvider, path: string): Promise<string | undefined> {
  if (typeof fs.readlink !== 'function') return undefined;
  try {
    await fs.readlink(path);
  } catch {
    return undefined;
  }
  try {
    return await fs.realpath(path);
  } catch {
    return undefined;
  }
}

/** A frontmatter value as one display line: control characters dropped, secrets masked, shortened. */
export function cleanDescription(value: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  const flat = value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!flat) return undefined;
  return maskCredentialsInLine(redactSecretsInLine(flat, MAX_SKILL_DESCRIPTION));
}

/**
 * `name` and `description` from a SKILL.md's YAML frontmatter. Descriptions
 * often hold an unquoted `: `, which is invalid YAML — then the two keys are
 * read line by line. Content the snapshot omitted, or that can't be read,
 * gives nothing (the folder name stands in).
 */
export async function readFrontmatter(fs: FSProvider, path: string): Promise<{ name?: string; description?: string }> {
  let text: string;
  try {
    text = (await fs.readFile(path)).slice(0, FRONTMATTER_READ);
  } catch {
    return {};
  }
  const match = /^\uFEFF?---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!match) return {};
  const block = match[1];
  let name: unknown;
  let description: unknown;
  try {
    const data = parseYamlSafe(block);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      ({ name, description } = data as Record<string, unknown>);
    }
  } catch {
    name = lineValue(block, 'name');
    description = lineValue(block, 'description');
  }
  const out: { name?: string; description?: string } = {};
  if (typeof name === 'string') {
    const clean = cleanDescription(name);
    if (clean) out.name = clean;
  }
  if (typeof description === 'string') {
    const clean = cleanDescription(description);
    if (clean) out.description = clean;
  }
  return out;
}

function lineValue(block: string, key: string): string | undefined {
  const m = new RegExp(`^${key}:[ \\t]*(.*)$`, 'm').exec(block);
  if (!m) return undefined;
  return m[1].trim().replace(/^(['"])(.*)\1$/, '$2') || undefined;
}

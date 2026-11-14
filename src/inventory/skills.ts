import { basename, dirname, join, relative, isAbsolute, sep } from 'node:path';
import type { DirentInfo, FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, AgentInventory, SkillItem, SkillTreeEntry, SkillsDirInfo } from '../core/types.js';
import { getAllSkillsDirs, isExcludedPath, listSkillTree } from '../core/utils.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { redactSecretsInLine } from '../core/patterns.js';
import { maskCredentialsInLine } from '../reporting/serialize.js';
import { shannonEntropy } from '../analyzers/entropy.js';
import { probeCoversTree } from '../core/probe-coverage.js';

/**
 * Folders under a skills directory whose skills an agent doesn't load: Hermes
 * moves unused skills to `.archive/` and skips these when it indexes skills
 * (EXCLUDED_SKILL_DIRS, hermes-agent agent/skill_utils.py). The skill checks
 * still read them — a restore brings them back — but they aren't counted as
 * skills; the folder is listed as an other entry. Codex's `.system/` is loaded.
 */
const INACTIVE_SKILL_DIRS = new Set(['.archive', '.curator_backups', '.hub', '.locks', '.git', '.github']);

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
  // `..x.js` is a file in `dir`, not a step out of it
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** `path` and every directory above it, up to and including `root`. */
function* upTo(path: string, root: string): Generator<string> {
  for (let p = path; ; p = dirname(p)) {
    yield p;
    if (p === root || dirname(p) === p) return;
  }
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
    // A snapshot has nothing for a directory the probe never collected (one a
    // config points outside the manifest's trees): unknown, not absent
    const uncollected = missing && !probeCoversTree(fs, root);
    skillsDirs.push({ path: root, exists: !missing, ...(uncollected ? { unverified: true as const } : {}) });
    if (uncollected) incomplete.push(`${root}: not collected by the remote probe — not verified (scan locally)`);
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

    // Files and code files under each directory, counted once per file
    // (a lookup per skill over every file was quadratic: 7000 skills, 3 min)
    const fileSet = new Set(listing.files);
    const filesUnder = new Map<string, number>();
    const codeUnder = new Map<string, number>();
    for (const f of listing.files) {
      const code = !isSkillMd(f);
      for (const d of upTo(dirname(f), root)) {
        filesUnder.set(d, (filesUnder.get(d) ?? 0) + 1);
        if (code) codeUnder.set(d, (codeUnder.get(d) ?? 0) + 1);
      }
    }

    // Outermost folders holding a SKILL.md: a SKILL.md inside a skill (an
    // example, a bundled sub-skill) belongs to it. The skills directory itself
    // is a skill only when nothing below it is (`vaso skill audit <skill>`):
    // agents load <root>/<name>/SKILL.md, so a stray root SKILL.md would
    // otherwise swallow every skill.
    const inactive = (dir: string) => relative(root, dir).split(sep).some(seg => INACTIVE_SKILL_DIRS.has(seg));
    const found = [...new Set([...listing.files.filter(isSkillMd).map(f => dirname(f)), ...linked.keys()])]
      .filter(dir => !inactive(dir));
    const candidates = (found.some(d => d !== root) ? found.filter(d => d !== root) : found)
      .sort((a, b) => a.split(sep).length - b.split(sep).length || a.localeCompare(b));
    const chosen = new Set<string>();
    for (const dir of candidates) {
      let inside = false;
      for (const up of upTo(dirname(dir), root)) if (up !== dir && chosen.has(up)) { inside = true; break; }
      if (!inside && !(dir !== root && chosen.has(root))) chosen.add(dir);
    }
    const skillDirs = [...chosen];

    for (const dir of skillDirs) {
      const target = linked.get(dir);
      // a linked skill: its own folder (a script beside the link) plus the target's files
      const count = (m: Map<string, number>) => (m.get(dir) ?? 0) + (target ? (m.get(target) ?? 0) : 0);
      const skillMd = target ? join(dir, 'SKILL.md') : listing.files.find(f => dirname(f) === dir && isSkillMd(f));
      const front = skillMd ? await readFrontmatter(fs, skillMd) : {};
      const link = target ?? await symlinkTarget(fs, dir);
      skills.push({
        name: front.name ?? cleanDescription(basename(dir)) ?? basename(dir),
        path: dir,
        root,
        scope,
        kind: 'skill-md',
        ...(front.description ? { description: front.description } : {}),
        files: count(filesUnder),
        hasCode: count(codeUnder) > 0,
        ...(link ? { symlinkTarget: link } : {}),
      });
    }

    // Direct children with no skill in or around them: folders, and files
    // the skill checks read (a loose script). Vendor dirs aren't something an
    // agent loads; a dot entry is listed when the checks read files in it.
    // A plain listing, not the walk: a snapshot's recursive listing holds
    // files only, so an empty folder or one holding no collected file would
    // be missing from it.
    if (missing || listing.error) continue;
    let children: DirentInfo[];
    try {
      children = await fs.readdirEntries(root);
    } catch {
      continue;
    }
    // top-level children that are, or hold, a skill
    const holdsSkill = new Set<string>();
    for (const dir of skillDirs) {
      if (dir === root) continue;
      holdsSkill.add(join(root, relative(root, dir).split(sep)[0]));
    }
    for (const entry of children) {
      const path = join(root, entry.name);
      if (chosen.has(root) || holdsSkill.has(path)) continue;
      if (isExcludedPath(root, path, { keepBuildOutput: true })) continue;
      const files = filesUnder.get(path) ?? (fileSet.has(path) ? 1 : 0);
      if (entry.name.startsWith('.') && !INACTIVE_SKILL_DIRS.has(entry.name) && files === 0) continue;
      // a symlink is a folder unless it leads to one file the checks read
      const isFile = entry.isFile || (entry.isSymbolicLink === true && fileSet.has(path));
      if (!isFile && (entry.isDirectory || entry.isSymbolicLink)) {
        otherEntries.push({ path, root, type: 'directory', files, hasCode: (codeUnder.get(path) ?? 0) > 0 });
      } else if (isFile && files > 0) {
        otherEntries.push({ path, root, type: 'file', files: 1, hasCode: !isSkillMd(path) });
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
  // A relative target (gstack writes `../gs/skills/x/SKILL.md`) resolves
  // against the link's own path, in the walked spelling: the same locally and
  // in a snapshot, which can't resolve it through a symlinked skills root
  if (typeof fs.readlink === 'function') {
    try {
      const raw = await fs.readlink(link);
      if (!isAbsolute(raw)) {
        const target = join(dirname(link), raw);
        if (isWithin(target, root)) return (await fs.access(target)) ? target : undefined;
      }
    } catch {
      // fall through to the resolved path
    }
  }
  try {
    const [real, rootReal] = await Promise.all([fs.realpath(link), fs.realpath(root)]);
    if (!isWithin(real, rootReal)) return undefined;
    // the walk's spelling: a snapshot holds the file under the root as walked
    // (a symlinked skills root), not under its real path
    const inRoot = join(root, relative(rootReal, real));
    return (await fs.access(inRoot)) ? inRoot : undefined;
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
  // mask first: redactSecretsInLine rewrites a PEM header, after which the
  // key body is no longer recognisable
  return redactSecretsInLine(maskBareTokens(maskCredentialsInLine(flat)), MAX_SKILL_DESCRIPTION);
}

/**
 * A bare high-entropy token in prose — an AWS secret access key, a random
 * API token with no recognisable prefix — names no key the maskers know.
 * Descriptions are prose: such a token is masked whatever its shape.
 */
const BARE_TOKEN = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9+/=_-])/g;

function maskBareTokens(text: string): string {
  return text.replace(BARE_TOKEN, (t) => {
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(re => re.test(t)).length;
    return classes === 3 && shannonEntropy(t) >= 4 ? `${t.slice(0, 4)}…${t.slice(-4)} (${t.length} chars)` : t;
  });
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

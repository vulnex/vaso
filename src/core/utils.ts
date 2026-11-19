import { join, extname, dirname, normalize, relative, sep, basename, isAbsolute } from 'node:path';
import { mkdir, open, rename, unlink, writeFile } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import type { DirentInfo, FSProvider } from './fs-provider.js';
import type { AgentInstallation } from './types.js';
import { walkSkillTree } from './skill-walk.js';
import { relEscapes } from './path-rel.js';
import { CREDENTIAL_FILE_NAME, startsLikeProgram } from '../analyzers/credential-file-names.js';
import { MAX_VENDOR_LOAD_DEPTH, MAX_VENDOR_LOADS, isLoadSource, isSkillAsset, loadCandidates, loadReferences, runReferences, vendorReferencePaths } from './skill-tree-files.js';
import { readCappedFile } from './file-limits.js';
import { isAppleDouble } from '../analyzers/binary-text.js';

export { relEscapes };
import { LocalFSProvider } from './local-fs-provider.js';

/**
 * A config key path: dot-separated text (`gateway.host`), or its segments
 * when a key itself contains a dot — `['risk_profiles', 'prod.v2', 'level']`
 * — which a dotted string cannot express.
 */
export type KeyPath = string | readonly string[];

/** The segments of a key path (a string splits on every dot). */
export function keySegments(path: KeyPath): string[] {
  return typeof path === 'string' ? path.split('.') : [...path];
}

/** A key path for messages: segments containing a dot (or empty) are quoted. */
export function formatKeyPath(path: KeyPath): string {
  if (typeof path === 'string') return path;
  return path.map(s => (/^[^.\s"]+$/.test(s) ? s : JSON.stringify(s))).join('.');
}

/**
 * Navigate a nested object by key path.
 * e.g. getNestedValue({ a: { b: 1 } }, 'a.b') → 1
 * Own keys only: `constructor` or `__proto__` is a config key or nothing,
 * never Object.prototype's.
 */
export function getNestedValue(obj: Record<string, unknown>, path: KeyPath): unknown {
  return keySegments(path).reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object' && Object.hasOwn(curr, key)) return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

/** Key path segments that reach an object's prototype rather than a key of it. */
const PROTOTYPE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

/** Scripts and source by extension: a skill's code (inventory `hasCode`). */
export const CODE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts', '.cts', '.py', '.pyw',
  '.sh', '.bash', '.zsh', '.ksh', '.fish', '.command', '.ps1', '.psm1', '.bat', '.cmd',
  '.rb', '.pl', '.pm', '.php', '.lua',
]);
/**
 * Compiled code a skill can ship and run (`./helper`, a native addon). Read as
 * bytes by IOC-003/IOC-007 (hash, executable headers); the text checks skip
 * them (see checks/skills/skill-files.ts).
 */
export const BINARY_EXTENSIONS = new Set(['.bin', '.node', '.exe', '.so', '.dylib', '.dll']);

// Vendor / VCS / cache directories every walk skips. The gstack skill
// ecosystem ships per-skill node_modules trees (hundreds of MB, including
// minified ML bundles) directly under ~/.claude/skills/<skill>/ — parsing
// those hangs @babel/parser for minutes and they aren't skill code anyway.
const VENDOR_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.cache',
  '.venv',
  'venv',
  '__pycache__',
]);
// Build output. Skipped when walking an install dir (an agent's own checkout),
// but read inside skill trees: a skill's `dist/index.js` or `build/run.py` is
// usually the code SKILL.md tells the agent to run.
const BUILD_OUTPUT_DIRS = new Set(['dist', 'build']);

/** A vendor/VCS/cache directory name every walk skips (build output not included). */
export function isVendorDirName(name: string): boolean {
  return VENDOR_DIRS.has(name);
}

/**
 * True when parentPath lies under a vendor/VCS dir below root — or a build
 * output dir, unless `keepBuildOutput` (skill trees). `skills`: folders
 * (paths relative to root) that are skills though named like a vendor dir
 * (vendorNamedSkills) — not excluded themselves; vendor dirs inside them are.
 */
export function isExcludedPath(
  root: string,
  parentPath: string | undefined,
  opts: { keepBuildOutput?: boolean; skills?: ReadonlySet<string> } = {},
): boolean {
  if (!parentPath) return false;
  const rel = relative(root, parentPath);
  if (!rel || relEscapes(rel)) return false;
  const segments = rel.split(sep);
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (!segment) continue;
    if (VENDOR_DIRS.has(segment)) {
      if (opts.skills?.has(segments.slice(0, i + 1).join(sep))) continue;
      return true;
    }
    if (!opts.keepBuildOutput && BUILD_OUTPUT_DIRS.has(segment)) return true;
  }
  return false;
}

/**
 * Folders anywhere under the skills directory `root` that are named like a
 * vendor dir (`venv`, `node_modules`, `.cache`) yet hold a SKILL.md (any
 * case) directly: skills, not vendored code — Hermes loads skills nested in
 * category folders, `.cache/` among them — so they are read like any other
 * (isExcludedPath's `skills`). A real virtualenv or node_modules holds no
 * SKILL.md at its top. Paths relative to root. The probe judges a folder the
 * same way (vendorNamedSkill in probe/collector.go).
 */
export function vendorNamedSkills(root: string, entries: readonly DirentInfo[]): ReadonlySet<string> {
  const out = new Set<string>();
  for (const e of entries) {
    if (!e.parentPath || e.name.toUpperCase() !== 'SKILL.MD') continue;
    if (!VENDOR_DIRS.has(basename(e.parentPath))) continue;
    const rel = relative(root, e.parentPath);
    if (rel && !relEscapes(rel) && !isAbsolute(rel)) out.add(rel);
  }
  return out;
}

/**
 * Resolve every skills directory an installation declares. Adapters that
 * expose multiple skills locations (e.g. OpenClaw's shared + per-agent dirs)
 * populate `skillsDirs`; adapters that only have one populate `skillsDir`.
 * This helper normalises both shapes into a single list so file enumeration
 * and directory scans can walk every relevant location once.
 */
export function getAllSkillsDirs(installation: AgentInstallation): string[] {
  if (installation.skillsDirs && installation.skillsDirs.length > 0) {
    return installation.skillsDirs;
  }
  return installation.skillsDir ? [installation.skillsDir] : [];
}

/**
 * Every file under a skills directory that skill/IOC checks read: every file
 * but assets (images, fonts, archives — SKILL_ASSET_EXTENSIONS), hidden
 * extensionless files (`.gitignore`, `.DS_Store`) and key or token files
 * that aren't programs. A script runs whatever its extension (`bash
 * scripts/install`, `python3 helper.txt`) and a reference doc is
 * instructions as much as SKILL.md is; each check decides what it reads in
 * which (checks/skills/skill-files.ts). Vendor dirs are skipped, build output
 * is not — see VENDOR_DIRS / BUILD_OUTPUT_DIRS — except the files a SKILL.md
 * runs from a vendor folder (`node node_modules/helper/index.js`).
 */
export async function getSkillFiles(dir: string, fs?: FSProvider, opts: { uncapped?: boolean } = {}): Promise<string[]> {
  return (await listSkillTree(dir, fs, opts)).files;
}

/** One walk of a skills directory: what getSkillFiles returns, and what the inventory needs. */
export interface SkillTreeListing {
  /** Every entry the walk returned (symlinks outside the tree followed). */
  entries: DirentInfo[];
  /** The files skill/IOC checks read — see getSkillFiles. */
  files: string[];
  /** Those of `files` that are code: scripts and source by extension,
   *  compiled helpers, extensionless executables, files starting with `#!`,
   *  files a SKILL.md runs through an interpreter and the vendor-folder files
   *  a skill runs or loads (inventory `hasCode`). */
  codeFiles: string[];
  /** Folders inside vendor dirs a SKILL.md runs (`node node_modules/helper`):
   *  only the files it names are read, so SKL-002 reports them as not scanned. */
  vendorDirRefs: string[];
  /** Skill directories that exist but can't be listed (see unlistableSkillDirs). */
  unlistable: string[];
  /** Folders deeper in the tree (inside a skill) that exist but can't be
   *  listed: the walk skips them, so their files go unread (see
   *  unlistableSubdirs). The skill directories in `unlistable` aren't repeated. */
  unlistableNested: string[];
  /** Why `dir` itself couldn't be listed (ENOENT when it doesn't exist). */
  error?: NodeJS.ErrnoException;
  /** Links in the tree the walk did not follow for where they lead (an OS
   *  directory, another user's home, the home itself — linkScope). */
  refusedLinks: string[];
  /** Directory links in the tree the walk did not follow because the tree
   *  they lead to holds more than MAX_SKILL_TREE_ENTRIES entries (linkCap). */
  overLimitLinks: string[];
  /** Directory links in the tree the walk did not follow because the tree's
   *  links together would hold more than MAX_LINKED_SKILL_ENTRIES (linkCap). */
  overTotalLinks: string[];
  /** On a snapshot: directory links the probe left out after it had
   *  stopped recording links it does not follow (linkCap). */
  unrecordedLinks: string[];
}

/** `uncapped`: follow links whatever the size of their tree (`vaso skill audit`). */
export async function listSkillTree(dir: string, fs?: FSProvider, opts: { uncapped?: boolean } = {}): Promise<SkillTreeListing> {
  const provider = fs ?? new LocalFSProvider();
  const files: string[] = [];
  const codeFiles: string[] = [];
  const vendorDirRefs: string[] = [];
  let entries: DirentInfo[] = [];
  let error: NodeJS.ErrnoException | undefined;
  const refusedLinks: string[] = [];
  const overLimitLinks: string[] = [];
  const overTotalLinks: string[] = [];
  const unrecordedLinks: string[] = [];
  try {
    // Follows symlinked skills that point outside the tree (walkSkillTree)
    entries = await walkSkillTree(provider, dir, refusedLinks, { overLimit: overLimitLinks, overTotal: overTotalLinks, unrecorded: unrecordedLinks, uncapped: opts.uncapped });
    const skills = vendorNamedSkills(dir, entries);
    const skillMds: string[] = [];
    const add = async (fullPath: string, name: string) => {
      const ext = extname(name).toLowerCase();
      if (CODE_EXTENSIONS.has(ext) || BINARY_EXTENSIONS.has(ext)) {
        files.push(fullPath);
        codeFiles.push(fullPath);
      } else if (name.toUpperCase() === 'SKILL.MD') {
        files.push(fullPath);
        skillMds.push(fullPath);
      // an id_ed25519 or token (with an execute bit or not) is a key, not a program
      } else if ((ext === '' && name.startsWith('.')) || isSkillAsset(name) || await keyFile(provider, fullPath, name)) {
        return;
      } else {
        files.push(fullPath);
        // a script by its execute bit (extensionless: without one a `#!` line
        // doesn't run it) or by its `#!` line under any other name
        if (ext === '' ? await isExecutable(provider, fullPath) : !NO_SHEBANG_EXTENSIONS.has(ext) && await startsWithShebang(provider, fullPath)) {
          codeFiles.push(fullPath);
        }
      }
    };
    const sidecars: string[] = [];
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (isExcludedPath(dir, entry.parentPath, { keepBuildOutput: true, skills })) continue;
      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
      // a macOS `._*` sidecar is Finder metadata, not a file of the skill
      if (await isAppleDouble(provider, fullPath, entry.name)) {
        sidecars.push(fullPath);
        continue;
      }
      await add(fullPath, entry.name);
    }
    // …unless a file of the tree names it (`sh ._setup.sh`): then it is one
    for (const path of await namedFiles(provider, files, sidecars)) await add(path, basename(path));
    // Files a SKILL.md runs from a vendor folder the walk skips
    const listed = new Set(files);
    const code = new Set(codeFiles);
    for (const skillMd of skillMds) {
      let text: string;
      try {
        text = await readCappedFile(provider, skillMd);
      } catch {
        continue;
      }
      // a file it runs through an interpreter is code, whatever its name (`python3 helper.txt`)
      for (const [path] of runReferences(skillMd, text)) {
        if (listed.has(path) && !code.has(path)) {
          code.add(path);
          codeFiles.push(path);
        }
      }
      for (const path of vendorReferencePaths(dir, skillMd, text)) {
        if (listed.has(path) || !isExcludedPath(dir, dirname(path), { keepBuildOutput: true, skills })) continue;
        const st = await provider.stat(path).catch(() => undefined);
        if (st?.isDirectory()) {
          if (!vendorDirRefs.includes(path)) vendorDirRefs.push(path);
          continue;
        }
        if (!st?.isFile() || isSkillAsset(path) || await keyFile(provider, path, basename(path))) continue;
        listed.add(path);
        files.push(path);
        codeFiles.push(path);
      }
    }
    // …and the vendor-folder files the tree's scripts load from there
    // (`require('../node_modules/helper')`) or its package.json scripts run
    // (`node .cache/boot.js`), a few loads deep
    for (const path of await vendorLoads(provider, dir, files, skills)) {
      listed.add(path);
      files.push(path);
      codeFiles.push(path);
    }
  } catch (err) {
    // Directory may not exist
    error = (err ?? undefined) as NodeJS.ErrnoException | undefined;
  }
  // A skill directory the scan can enter but not list (mode 111) hides every
  // file in it from the walk, while the agent still loads SKILL.md by name
  const unlistable = await unlistableSkillDirs(dir, provider);
  for (const skillDir of unlistable) {
    const skillMd = join(skillDir, 'SKILL.md');
    if (!files.includes(skillMd) && await provider.access(skillMd)) files.push(skillMd);
  }
  // Sorted: a local walk and a snapshot list folders in different orders
  const unlistableNested = (await unlistableSubdirs(provider, dir, entries)).filter(d => !unlistable.includes(d)).sort();
  return { entries, files, codeFiles, vendorDirRefs: vendorDirRefs.sort(), unlistable: unlistable.sort(), unlistableNested, refusedLinks, overLimitLinks, overTotalLinks, unrecordedLinks, ...(error ? { error } : {}) };
}

/**
 * Vendor-folder files (`node_modules/`, `.cache/`, … — the walk skips them)
 * that the tree's files load: a script's relative require/import, a
 * package.json's references (loadReferences), resolved as Node resolves a
 * module path (loadCandidates) and followed from the files they add, at
 * most MAX_VENDOR_LOAD_DEPTH loads deep and MAX_VENDOR_LOADS files. Sources
 * are taken in path order, level by level, so the bound cuts where the
 * probe's does (probe/skill_refs.go collectVendorLoads).
 */
async function vendorLoads(fs: FSProvider, root: string, files: readonly string[], skills: ReadonlySet<string>): Promise<string[]> {
  const inVendor = (p: string) => !relEscapes(relative(root, p)) && isExcludedPath(root, dirname(p), { keepBuildOutput: true, skills });
  const known = new Set(files);
  const out: string[] = [];
  let level = files.filter(isLoadSource).sort();
  for (let depth = 0; depth < MAX_VENDOR_LOAD_DEPTH && level.length > 0 && out.length < MAX_VENDOR_LOADS; depth++) {
    const next: string[] = [];
    for (const source of level) {
      let text: string;
      try {
        text = await readCappedFile(fs, source);
      } catch {
        continue;
      }
      for (const ref of loadReferences(source, text)) {
        if (out.length >= MAX_VENDOR_LOADS) return out;
        const p = normalize(join(dirname(source), ...ref.split('/')));
        if (!inVendor(p)) continue;
        const target = await resolveLoad(fs, p, inVendor);
        if (target === undefined || known.has(target)) continue;
        known.add(target);
        if (isSkillAsset(target) || await keyFile(fs, target, basename(target))) continue;
        out.push(target);
        if (isLoadSource(target)) next.push(target);
      }
    }
    level = next.sort();
  }
  return out;
}

/**
 * Those of `candidates` (sidecars) whose name one of `files` mentions, in
 * candidate order: each file is read once, and only while some candidate is
 * unnamed.
 */
async function namedFiles(fs: FSProvider, files: readonly string[], candidates: readonly string[]): Promise<string[]> {
  if (candidates.length === 0) return [];
  const named = new Set<string>();
  for (const file of [...files].sort()) {
    if (named.size === candidates.length) break;
    let text: string;
    try {
      text = await readCappedFile(fs, file);
    } catch {
      continue;
    }
    for (const c of candidates) if (!named.has(c) && text.includes(basename(c))) named.add(c);
  }
  return candidates.filter(c => named.has(c));
}

/** The first of loadCandidates(p) that is a file in a vendor folder of the tree. */
async function resolveLoad(fs: FSProvider, p: string, inVendor: (p: string) => boolean): Promise<string | undefined> {
  let main: string | undefined;
  if (await fs.stat(p).then(st => st.isDirectory(), () => false)) {
    try {
      const m = (JSON.parse(await readCappedFile(fs, join(p, 'package.json'))) as { main?: unknown } | null)?.main;
      if (typeof m === 'string' && m.trim() !== '') main = m;
    } catch {
      // no package.json, or no main in it
    }
  }
  for (const c of loadCandidates(p, main)) {
    if (!inVendor(c)) continue;
    if (await fs.stat(c).then(st => st.isFile(), () => false)) return c;
  }
  return undefined;
}

/** A key or token file by its name that isn't a program (isCredentialNotProgram) — the name is tested first. */
async function keyFile(fs: FSProvider, path: string, name: string): Promise<boolean> {
  return CREDENTIAL_FILE_NAME.test(name) && !(await startsLikeProgram(fs, path));
}

/**
 * Skill directories directly under `skillsDir` that exist but can't be
 * listed (EACCES — e.g. mode 111): their files can only be reached by name.
 * SKL-002 reports them; getSkillFiles still reads their SKILL.md.
 */
export async function unlistableSkillDirs(skillsDir: string, fs?: FSProvider): Promise<string[]> {
  const provider = fs ?? new LocalFSProvider();
  let entries: DirentInfo[];
  try {
    entries = await provider.readdirEntries(skillsDir);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory) continue;
    const dir = join(skillsDir, entry.name);
    try {
      await provider.readdirEntries(dir);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      if (code === 'EACCES' || code === 'EPERM') out.push(dir);
    }
  }
  return out;
}

/**
 * Folders anywhere in a walked skill tree that exist but can't be listed
 * (EACCES — a chmod-000 `locked/` inside a skill): the recursive walk skips
 * them without a word, so the files in them would pass as reviewed. The
 * local and snapshot providers mark such folders as they walk
 * (DirentInfo.denied); another provider's folders the walk listed nothing
 * under are asked again (an empty one lists fine). Vendor dirs are skipped
 * as the walk's file list skips them. A snapshot's recursive listing carries
 * the folders its probe could not list for this.
 */
async function unlistableSubdirs(fs: FSProvider, root: string, entries: DirentInfo[]): Promise<string[]> {
  const listed = new Set(entries.map(e => e.parentPath ?? root));
  const skills = vendorNamedSkills(root, entries);
  const marks = fs.kind === 'local' || fs.kind === 'snapshot';
  const out = new Set<string>();
  for (const entry of entries) {
    if (!entry.isDirectory || entry.isSymbolicLink) continue;
    if (marks && !entry.denied) continue;
    const path = join(entry.parentPath ?? root, entry.name);
    if (listed.has(path) || isExcludedPath(root, path, { keepBuildOutput: true, skills })) continue;
    if (entry.denied) {
      out.add(path);
      continue;
    }
    try {
      await fs.readdirEntries(path);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      if (code === 'EACCES' || code === 'EPERM') out.add(path);
    }
  }
  return [...out];
}

/** Documents and data a `#!` line isn't looked for in (inventory `hasCode`). */
const NO_SHEBANG_EXTENSIONS = new Set(['.md', '.mdx', '.markdown', '.json', '.jsonl', '.yaml', '.yml', '.csv', '.tsv', '.lock', '.svg', '.html', '.htm', '.xml']);

/** The file starts with `#!`: a script whatever its name. */
async function startsWithShebang(fs: FSProvider, path: string): Promise<boolean> {
  const head = await fs.readHead?.(path, 2).catch(() => undefined);
  return head !== undefined && head[0] === 0x23 && head[1] === 0x21;
}

/** Any execute bit set — what makes an extensionless file a script or program. */
async function isExecutable(fs: FSProvider, path: string): Promise<boolean> {
  try {
    return ((await fs.stat(path)).mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

/**
 * Set a value at a key path in a nested object.
 * Creates intermediate objects as needed.
 * e.g. setNestedValue({}, 'a.b.c', 1) → { a: { b: { c: 1 } } }
 * Throws for a `__proto__`, `prototype` or `constructor` segment: setting
 * through one would change Object.prototype for the whole process.
 */
export function setNestedValue(obj: Record<string, unknown>, path: KeyPath, value: unknown): void {
  const keys = keySegments(path);
  if (keys.some(k => PROTOTYPE_KEYS.has(k))) {
    throw new Error(`Refusing to set "${formatKeyPath(path)}": __proto__, prototype and constructor are not config keys`);
  }
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!Object.hasOwn(current, keys[i]) || typeof current[keys[i]] !== 'object' || current[keys[i]] === null) {
      current[keys[i]] = {};
    }
    current = current[keys[i]] as Record<string, unknown>;
  }
  current[keys[keys.length - 1]] = value;
}

/**
 * Deep merge two objects. Override wins for conflicts.
 * Arrays from override replace base arrays (not concatenated).
 */
export function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };
  for (const key of Object.keys(override)) {
    const baseVal = base[key];
    const overVal = override[key];
    if (
      overVal !== null &&
      typeof overVal === 'object' &&
      !Array.isArray(overVal) &&
      baseVal !== null &&
      typeof baseVal === 'object' &&
      !Array.isArray(baseVal)
    ) {
      result[key] = deepMerge(
        baseVal as Record<string, unknown>,
        overVal as Record<string, unknown>,
      );
    } else {
      result[key] = overVal;
    }
  }
  return result;
}

/**
 * Check if a path exists (file or directory).
 */
export async function pathExists(path: string, fs?: FSProvider): Promise<boolean> {
  const provider = fs ?? new LocalFSProvider();
  return provider.access(path);
}

/**
 * Write text to a file path, creating any missing parent directories.
 * Behaves like `mkdir -p $(dirname path) && cat > path`.
 */
/**
 * Write a file readable by its owner only — for output that holds collected
 * file contents (probe snapshots) or scan history (baselines). The content
 * goes to a new file created 0600 (O_EXCL, never through a symlink) next to
 * the target, which is then renamed over it: a symlink planted at the target
 * is replaced rather than followed, and the data is never in a file someone
 * else can read, not even between create and chmod.
 */
export async function writeFileOwnerOnly(path: string, content: string): Promise<void> {
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(tmp, flags, 0o600);
  try {
    await handle.writeFile(content, 'utf-8');
  } catch (err) {
    await handle.close();
    await unlink(tmp).catch(() => {});
    throw err;
  }
  await handle.close();
  try {
    await rename(tmp, path);
  } catch (err) {
    await unlink(tmp).catch(() => {});
    throw err;
  }
}

export async function writeFileEnsureDir(path: string, content: string): Promise<void> {
  const parent = dirname(path);
  if (parent && parent !== '.' && parent !== '/') {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, content, 'utf-8');
}

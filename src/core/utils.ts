import { join, extname, dirname, relative, sep } from 'node:path';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import type { FSProvider } from './fs-provider.js';
import type { AgentInstallation } from './types.js';
import { walkSkillTree } from './skill-walk.js';
import { LocalFSProvider } from './local-fs-provider.js';

/**
 * Navigate a nested object by dot-separated path.
 * e.g. getNestedValue({ a: { b: 1 } }, 'a.b') → 1
 */
export function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

const CODE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts', '.cts', '.py',
  '.sh', '.bash', '.zsh', '.ksh', '.fish', '.ps1', '.psm1',
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

/**
 * True when parentPath lies under a vendor/VCS dir below root — or a build
 * output dir, unless `keepBuildOutput` (skill trees).
 */
export function isExcludedPath(
  root: string,
  parentPath: string | undefined,
  opts: { keepBuildOutput?: boolean } = {},
): boolean {
  if (!parentPath) return false;
  const rel = relative(root, parentPath);
  if (!rel || rel.startsWith('..')) return false;
  for (const segment of rel.split(sep)) {
    if (!segment) continue;
    if (VENDOR_DIRS.has(segment)) return true;
    if (!opts.keepBuildOutput && BUILD_OUTPUT_DIRS.has(segment)) return true;
  }
  return false;
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
 * Every file under a skills directory that skill/IOC checks read: code and
 * scripts by extension, SKILL.md (the agent runs its code blocks), compiled
 * binaries, and extensionless executables (`scripts/setup` with a shebang, a
 * native `helper`). Vendor dirs are skipped, build output is not — see
 * VENDOR_DIRS / BUILD_OUTPUT_DIRS.
 */
export async function getSkillFiles(dir: string, fs?: FSProvider): Promise<string[]> {
  const provider = fs ?? new LocalFSProvider();
  const files: string[] = [];
  try {
    // Follows symlinked skills that point outside the tree (walkSkillTree)
    const entries = await walkSkillTree(provider, dir);
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (isExcludedPath(dir, entry.parentPath, { keepBuildOutput: true })) continue;
      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
      const ext = extname(entry.name).toLowerCase();
      if (CODE_EXTENSIONS.has(ext) || BINARY_EXTENSIONS.has(ext) || entry.name.toUpperCase() === 'SKILL.MD') {
        files.push(fullPath);
      } else if (ext === '' && !entry.name.startsWith('.') && await isExecutable(provider, fullPath)) {
        files.push(fullPath);
      }
    }
  } catch {
    // Directory may not exist
  }
  return files;
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
 * Set a value at a dot-separated path in a nested object.
 * Creates intermediate objects as needed.
 * e.g. setNestedValue({}, 'a.b.c', 1) → { a: { b: { c: 1 } } }
 */
export function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split('.');
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!(keys[i] in current) || typeof current[keys[i]] !== 'object' || current[keys[i]] === null) {
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
 * file contents (probe snapshots) or scan history (baselines). `mode` alone
 * only applies when the file is created, so an existing file is chmod-ed too.
 */
export async function writeFileOwnerOnly(path: string, content: string): Promise<void> {
  await writeFile(path, content, { encoding: 'utf-8', mode: 0o600 });
  await chmod(path, 0o600);
}

export async function writeFileEnsureDir(path: string, content: string): Promise<void> {
  const parent = dirname(path);
  if (parent && parent !== '.' && parent !== '/') {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, content, 'utf-8');
}

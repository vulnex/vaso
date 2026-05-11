import { join, extname, dirname } from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import type { FSProvider } from './fs-provider.js';
import type { AgentInstallation } from './types.js';
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

const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py', '.sh', '.bash']);

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
 * Recursively find all code files (JS/TS/Python/Shell) under a directory.
 */
export async function getSkillFiles(dir: string, fs?: FSProvider): Promise<string[]> {
  const provider = fs ?? new LocalFSProvider();
  const files: string[] = [];
  try {
    const entries = await provider.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (entry.isFile && CODE_EXTENSIONS.has(extname(entry.name))) {
        const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
        files.push(fullPath);
      }
    }
  } catch {
    // Directory may not exist
  }
  return files;
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
export async function writeFileEnsureDir(path: string, content: string): Promise<void> {
  const parent = dirname(path);
  if (parent && parent !== '.' && parent !== '/') {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, content, 'utf-8');
}

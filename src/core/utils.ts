import { access, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';

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
 * Recursively find all code files (JS/TS/Python/Shell) under a directory.
 */
export async function getSkillFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true, recursive: true });
    for (const entry of entries) {
      if (entry.isFile() && CODE_EXTENSIONS.has(extname(entry.name))) {
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
 * Check if a path exists (file or directory).
 */
export async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

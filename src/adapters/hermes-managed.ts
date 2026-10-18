import { isAbsolute, join } from 'node:path';
import type { Evidence, ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { getNestedValue } from '../core/utils.js';

/**
 * Hermes' administrator-managed scope (hermes_cli/managed_scope.py): a
 * directory of IT-pushed `config.yaml` and `.env` that every Hermes process
 * on the host applies over the user's own `$HERMES_HOME` files.
 *
 *  - Directory: `$HERMES_MANAGED_DIR` when non-empty (used as given, no `~`),
 *    else `/etc/hermes`; only when it is a directory.
 *  - `config.yaml` is deep-merged on top of the user's config per leaf
 *    (`_deep_merge`): a managed mapping recurses, a managed scalar replaces
 *    the whole user subtree there, and a managed `null` over a user mapping
 *    is ignored.
 *  - `.env` is loaded last, with override (`_apply_managed_env`), so its
 *    variables beat the user's `.env` and the shell.
 * Enforcement is filesystem permissions only, so the directory and its files
 * must not be writable by other users (HM-011).
 */
export const HERMES_MANAGED_DEFAULT_DIR = '/etc/hermes';
export const HERMES_MANAGED_FILES = ['config.yaml', '.env'] as const;

/** The managed-scope directory Hermes would use, or undefined when there is none. */
export async function hermesManagedDir(fs: FSProvider): Promise<string | undefined> {
  const override = fs.getEnv('HERMES_MANAGED_DIR')?.trim();
  // A relative override resolves against the daemon's cwd, which a scan can't see
  const dir = override ? (isAbsolute(override) ? override : undefined) : HERMES_MANAGED_DEFAULT_DIR;
  if (!dir) return undefined;
  try {
    return (await fs.stat(dir)).isDirectory() ? dir : undefined;
  } catch {
    return undefined;
  }
}

export function managedFilePaths(dir: string): string[] {
  return HERMES_MANAGED_FILES.map(f => join(dir, f));
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Whether deep-merging `managed` over a user config replaces the user's value at `path`. */
function replacesLeaf(managed: unknown, path: string[]): boolean {
  let node = managed;
  for (let i = 0; i < path.length; i++) {
    if (!isRecord(node) || !Object.hasOwn(node, path[i])) return false;
    const v = node[path[i]];
    if (i === path.length - 1) return true;
    // A managed scalar replaces the user's whole mapping; a null over a mapping is ignored
    if (!isRecord(v)) return v !== null;
    node = v;
  }
  return false;
}

/**
 * The managed file whose value Hermes uses instead of the one `config`
 * holds at `key` (a dotted config.yaml path, or a variable name for `.env`);
 * undefined when the user's value is the effective one.
 */
export function managedOverride(configs: ParsedConfig[], config: ParsedConfig, key: string | string[]): ParsedConfig | undefined {
  if (config.managed) return undefined;
  const env = config.format === 'env';
  for (const m of configs) {
    if (!m.managed || (m.format === 'env') !== env) continue;
    if (env ? Object.hasOwn(m.data, key as string) : replacesLeaf(m.data, Array.isArray(key) ? key : key.split('.'))) return m;
  }
  return undefined;
}

/** Mark evidence about a user value the managed layer replaces as mitigated, naming that file. */
export function markManagedOverride(evidence: Evidence, managed: ParsedConfig | undefined): Evidence {
  if (!managed) return evidence;
  return {
    ...evidence,
    mitigated: true,
    detail: `${evidence.detail ?? ''}${evidence.detail ? ' — ' : ''}overridden by the administrator-managed ${managed.filePath}`,
  };
}

/**
 * The value Hermes uses for a config.yaml key: the managed layer's when it
 * sets the key, else the user's. `file` names where it comes from.
 */
export function hermesYamlSetting<T extends Pick<ParsedConfig, 'format' | 'data' | 'managed'> & { filePath?: string }>(
  configs: T[],
  key: string,
): { value: unknown; file: T['filePath']; config: T } | undefined {
  const yamls = configs.filter(c => c.format !== 'env');
  const user = yamls.filter(c => !c.managed);
  for (const m of yamls.filter(c => c.managed)) {
    if (replacesLeaf(m.data, key.split('.'))) return { value: getNestedValue(m.data, key), file: m.filePath, config: m };
  }
  for (const c of user) {
    const value = getNestedValue(c.data, key);
    if (value !== undefined) return { value, file: c.filePath, config: c };
  }
  return undefined;
}

/** Configs in the order Hermes lets them win: managed layer first, then the user's files. */
export function byHermesPrecedence<T extends { managed?: boolean }>(configs: T[]): T[] {
  return [...configs.filter(c => c.managed), ...configs.filter(c => !c.managed)];
}

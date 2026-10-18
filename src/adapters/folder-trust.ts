import { basename, dirname, resolve, sep } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { Evidence, ScanContext } from '../core/types.js';
import { parseJsonLenient } from '../core/jsonc.js';

/**
 * Folder trust as Gemini CLI and Qwen Code (a Gemini CLI fork) implement it:
 * with `security.folderTrust.enabled`, a workspace's `.gemini/` / `.qwen/`
 * settings and `.env` are ignored until the user trusts the folder in
 * `trustedFolders.json` (gemini-cli settings.ts: `workspaceSettings` is `{}`
 * unless `isWorkspaceTrusted`; core utils/trust.ts `checkPathTrust`). An
 * unmatched folder counts as untrusted.
 */
export interface FolderTrustSpec {
  /** Project root (the directory holding `.gemini/` / `.qwen/`). */
  workspace: string;
  /** User and system settings files, lowest precedence first. The workspace's
   *  own settings can't enable or disable trust for itself. */
  settingsFiles: string[];
  /** `security.folderTrust.enabled` when no settings file sets it. */
  enabledByDefault: boolean;
  trustFile: string;
  /** How the CLI picks among matching trust rules. */
  precedence: TrustPrecedence;
  /** A decision forced by the environment, if any. */
  envDecision?: boolean;
}

async function readJson(fs: FSProvider, file: string): Promise<unknown> {
  try {
    return parseJsonLenient(await fs.readFile(file));
  } catch {
    return undefined;
  }
}

function folderTrustSetting(data: unknown): boolean | undefined {
  const enabled = (((data as Record<string, unknown> | undefined)?.security as Record<string, unknown> | undefined)
    ?.folderTrust as Record<string, unknown> | undefined)?.enabled;
  return typeof enabled === 'boolean' ? enabled : undefined;
}

function isSubpath(parent: string, child: string): boolean {
  const p = parent.endsWith(sep) ? parent : parent + sep;
  return child === parent || child.startsWith(p);
}

/** Number of segments below the root (`/a/b` → 2). */
function pathDepth(p: string): number {
  return p.split(sep).filter(Boolean).length;
}

/**
 * How the CLI picks among the matching rules:
 * - `longest` (Gemini CLI, packages/core/src/utils/trust.ts `isPathTrusted`
 *   @ google-gemini/gemini-cli 0bd1d439): the rule whose raw key string is
 *   longest wins, the first one on a tie; paths compare by realpath, and
 *   case-insensitively on macOS and Windows (utils/paths.ts `normalizePath`
 *   / `isSubpath` @ 2fe7c2d3).
 * - `deepest` (Qwen Code, packages/cli/src/config/trust-precedence.ts, added
 *   in QwenLM/qwen-code 9e874534 "honor explicit distrust over inherited
 *   trust (#8628)"): the rule whose effective path (TRUST_PARENT → its
 *   parent) is deepest wins, DO_NOT_TRUST on a tie; a path compares by its
 *   resolved and its real form (path-comparison.ts), case-sensitively.
 * Neither expands `~` in a key: both `path.resolve` it against the CLI's
 * working directory — the workspace — so `~/repo` names `<workspace>/~/repo`.
 */
export type TrustPrecedence = 'longest' | 'deepest';

/**
 * The trust file's decision for `workspace` (see TrustPrecedence for which
 * matching rule wins): `TRUST_PARENT` covers the rule path's parent,
 * `DO_NOT_TRUST` distrusts. Undefined when no rule matches or the file is
 * absent; a malformed file stops the CLI, so nothing is trusted either.
 */
export async function trustFileDecision(
  fs: FSProvider,
  trustFile: string,
  workspace: string,
  precedence: TrustPrecedence = 'longest',
): Promise<boolean | undefined> {
  const data = await readJson(fs, trustFile);
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  const foldCase = precedence === 'longest' && (fs.platform === 'darwin' || fs.platform === 'win32');
  const fold = (p: string) => (foldCase ? p.toLowerCase() : p);
  const realOf = async (p: string) => { try { return (await fs.realpath(p)) || undefined; } catch { return undefined; } };
  /** Gemini compares the real path (else the resolved one); Qwen either form. */
  const variants = async (p: string): Promise<string[]> => {
    const resolved = resolve(workspace, p);
    const real = await realOf(resolved);
    if (precedence === 'longest') return [fold(real ?? resolved)];
    return real && real !== resolved ? [resolved, real] : [resolved];
  };
  const locations = await variants(workspace);

  let bestLength = -1;
  let bestDepth = -1;
  let decision: boolean | undefined;
  for (const [rulePath, level] of Object.entries(data as Record<string, unknown>)) {
    if (level !== 'TRUST_FOLDER' && level !== 'TRUST_PARENT' && level !== 'DO_NOT_TRUST') continue;
    const trusted = level !== 'DO_NOT_TRUST';
    const ruleVariants = await variants(level === 'TRUST_PARENT' ? dirname(rulePath) : rulePath);
    let depth = -1;
    for (const r of ruleVariants) {
      if (locations.some(l => isSubpath(r, l))) depth = Math.max(depth, pathDepth(r));
    }
    if (depth < 0) continue;
    if (precedence === 'longest') {
      if (rulePath.length <= bestLength) continue;
      bestLength = rulePath.length;
      decision = trusted;
    } else if (depth > bestDepth || (depth === bestDepth && !trusted && decision !== false)) {
      bestDepth = depth;
      decision = trusted;
    }
  }
  return decision;
}

/** Whether the agent applies the workspace's own settings. */
export async function workspaceTrusted(fs: FSProvider, spec: FolderTrustSpec): Promise<boolean> {
  if (spec.envDecision !== undefined) return spec.envDecision;
  let enabled = spec.enabledByDefault;
  for (const file of spec.settingsFiles) {
    const setting = folderTrustSetting(await readJson(fs, file));
    if (setting !== undefined) enabled = setting;
  }
  if (!enabled) return true;
  return (await trustFileDecision(fs, spec.trustFile, spec.workspace, spec.precedence)) === true;
}

/**
 * Downgrade evidence from an untrusted workspace's settings: the agent
 * ignores them until the folder is trusted, so the finding is inactive —
 * kept (trusting the folder activates it), never dropped.
 */
export async function markUntrustedWorkspace(
  ctx: ScanContext,
  evidence: Evidence[],
  trusted: (fs: FSProvider, workspace: string) => Promise<boolean>,
): Promise<void> {
  if (ctx.installation.profile !== 'project' || evidence.length === 0) return;
  // installDir = <workspace>/.gemini (or .qwen)
  const workspace = dirname(ctx.installation.installDir);
  if (await trusted(ctx.fs, workspace)) return;
  for (const e of evidence) {
    e.mitigated = true;
    e.detail = `${e.detail ?? ''} — inactive: the CLI ignores this workspace's settings until folder "${basename(workspace)}" is trusted`.replace(/^ — /, '');
  }
}

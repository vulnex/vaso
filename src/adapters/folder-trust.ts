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

function expandHome(p: string, home: string): string {
  return p === '~' || p.startsWith('~/') ? home + p.slice(1) : p;
}

function isSubpath(parent: string, child: string): boolean {
  const p = parent.endsWith(sep) ? parent : parent + sep;
  return child === parent || child.startsWith(p);
}

/**
 * The trust file's decision for `workspace`: the longest matching rule wins,
 * `TRUST_PARENT` covers the rule path's parent, `DO_NOT_TRUST` distrusts.
 * Paths compare resolved. Undefined when no rule matches or the file is
 * absent; a malformed file stops the CLI, so nothing is trusted either.
 */
export async function trustFileDecision(fs: FSProvider, trustFile: string, workspace: string): Promise<boolean | undefined> {
  const data = await readJson(fs, trustFile);
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  const real = async (p: string) => fs.realpath(p).catch(() => p);
  const location = await real(resolve(workspace));
  let best = -1;
  let decision: boolean | undefined;
  for (const [rulePath, level] of Object.entries(data as Record<string, unknown>)) {
    if (level !== 'TRUST_FOLDER' && level !== 'TRUST_PARENT' && level !== 'DO_NOT_TRUST') continue;
    const path = resolve(expandHome(rulePath, fs.homedir()));
    const effective = await real(level === 'TRUST_PARENT' ? dirname(path) : path);
    if (!isSubpath(effective, location) || rulePath.length <= best) continue;
    best = rulePath.length;
    decision = level !== 'DO_NOT_TRUST';
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
  return (await trustFileDecision(fs, spec.trustFile, spec.workspace)) === true;
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

import { basename, dirname, join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import type { PermissionFacts } from '../../core/fs-provider.js';
import { queryPermissions } from '../../core/permissions.js';
import { parseIfPresent } from '../../adapters/load-if-present.js';
import { MUSE_CODE_PROJECT_HOOKS, MUSE_CODE_PROJECT_MCP, MUSE_CODE_SETTINGS, MUSE_CODE_TRUST, museConfigDir } from '../../adapters/muse-code.js';

/**
 * Shared helpers for the Meta Muse Code checks. Semantics verified against
 * Muse Code 1.4.25 (R9361.1) with its offline echo provider and the
 * `runtime.session.permission_profile_committed` record each session logs.
 */

export function isProjectInstall(ctx: ScanContext): boolean {
  return ctx.installation.profile === 'project';
}

export function settingsConfig(configs: ParsedConfig[]): ParsedConfig | undefined {
  return configs.find(c => basename(c.filePath) === MUSE_CODE_SETTINGS && basename(dirname(c.filePath)) !== '.muse');
}

export function isProjectHooks(config: ParsedConfig): boolean {
  return config.filePath.endsWith(MUSE_CODE_PROJECT_HOOKS);
}

// ---------------------------------------------------------------------------
// Permission profiles
// ---------------------------------------------------------------------------

/** The four dimensions a session's permission profile resolves to. */
export interface ResolvedProfile {
  /** on_request | prompt_unmatched | allow_all (allow_all: nothing is ever asked) */
  approval: string;
  /** human | auto_review (an LLM judge decides prompts) | none */
  reviewer: string;
  /** managed (sandboxed to the workspace) | unrestricted */
  filesystem: string;
  /** restricted | proxy_only | enabled (shell commands' network) */
  network: string;
}

/** Built-in profiles, as each session records them. */
export const BUILTIN_PROFILES: Record<string, ResolvedProfile> = {
  ':read-only': { approval: 'on_request', reviewer: 'human', filesystem: 'managed', network: 'restricted' },
  ':auto-review': { approval: 'on_request', reviewer: 'auto_review', filesystem: 'managed', network: 'proxy_only' },
  ':unrestricted': { approval: 'allow_all', reviewer: 'none', filesystem: 'unrestricted', network: 'enabled' },
};

/** What a session runs with when settings.json names no default profile. */
export const DEFAULT_PROFILE = ':auto-review';

// A custom profile may extend only these (`:unrestricted` is refused as a parent)
const PARENTABLE = new Set([':read-only', ':auto-review']);
const APPROVALS = new Set(['on_request', 'prompt_unmatched', 'allow_all']);
const REVIEWERS = new Set(['human', 'auto_review', 'none']);
const NETWORK_MODES = new Set(['restricted', 'proxy_only', 'enabled']);

type Profiles = Record<string, Record<string, unknown>>;

function profilesOf(settings: ParsedConfig | undefined): { profiles: Profiles; defaultId?: string } {
  const perms = settings?.data.permissions;
  if (!perms || typeof perms !== 'object' || Array.isArray(perms)) return { profiles: {} };
  const p = perms as Record<string, unknown>;
  const raw = p.profiles && typeof p.profiles === 'object' && !Array.isArray(p.profiles) ? p.profiles as Record<string, unknown> : {};
  const profiles: Profiles = {};
  for (const [id, v] of Object.entries(raw)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) profiles[id] = v as Record<string, unknown>;
  }
  return { profiles, defaultId: typeof p.default_profile === 'string' ? p.default_profile : undefined };
}

/**
 * A profile's effective dimensions, or undefined when Muse would refuse it
 * (unknown parent, cycle, invalid value, contradictory authority) — a
 * refused default profile stops Muse from starting, so it weakens nothing.
 */
export function resolveProfile(id: string, profiles: Profiles, seen = new Set<string>()): ResolvedProfile | undefined {
  if (BUILTIN_PROFILES[id]) return { ...BUILTIN_PROFILES[id] };
  const p = profiles[id];
  if (!p || seen.has(id)) return undefined;
  seen.add(id);
  let base: Partial<ResolvedProfile> = {};
  if (typeof p.extends === 'string') {
    if (p.extends.startsWith(':') && !PARENTABLE.has(p.extends)) return undefined;
    const parent = resolveProfile(p.extends, profiles, seen);
    if (!parent) return undefined;
    base = parent;
  }
  const out: Partial<ResolvedProfile> = { ...base };
  if (p.approval !== undefined) {
    if (typeof p.approval !== 'string' || !APPROVALS.has(p.approval)) return undefined;
    out.approval = p.approval;
  }
  if (p.reviewer !== undefined) {
    if (typeof p.reviewer !== 'string' || !REVIEWERS.has(p.reviewer)) return undefined;
    out.reviewer = p.reviewer;
  }
  if (p.filesystem !== undefined) {
    if (p.filesystem === 'unrestricted') out.filesystem = 'unrestricted';
    // Path rules keep the sandbox (managed); any other string is refused
    else if (p.filesystem && typeof p.filesystem === 'object' && !Array.isArray(p.filesystem)) out.filesystem = 'managed';
    else return undefined;
  }
  const net = p.network;
  if (net !== undefined) {
    if (!net || typeof net !== 'object' || Array.isArray(net)) return undefined;
    const mode = (net as Record<string, unknown>).mode;
    if (mode !== undefined) {
      if (typeof mode !== 'string' || !NETWORK_MODES.has(mode)) return undefined;
      out.network = mode;
    }
  }
  // A parentless profile must define all four dimensions
  if (!out.approval || !out.reviewer || !out.filesystem || !out.network) return undefined;
  // Contradictory authority is refused
  if ((out.approval === 'allow_all') !== (out.reviewer === 'none')) return undefined;
  if (out.filesystem === 'unrestricted' && out.network === 'restricted') return undefined;
  return out as ResolvedProfile;
}

export interface ProfileView {
  config: ParsedConfig;
  /** The profile id sessions start with. */
  id: string;
  /** Whether settings.json names it (else it is Muse's default). */
  configured: boolean;
  profile: ResolvedProfile;
}

/** The default profile of the user settings file, if it resolves. */
export function defaultProfile(configs: ParsedConfig[]): ProfileView | undefined {
  const config = settingsConfig(configs);
  if (!config) return undefined;
  const { profiles, defaultId } = profilesOf(config);
  const id = defaultId ?? DEFAULT_PROFILE;
  const profile = resolveProfile(id, profiles);
  return profile ? { config, id, configured: defaultId !== undefined, profile } : undefined;
}

/** Custom profiles other than the default (selectable with --permission-profile). */
export function otherProfiles(configs: ParsedConfig[]): { config: ParsedConfig; id: string; profile: ResolvedProfile }[] {
  const config = settingsConfig(configs);
  if (!config) return [];
  const { profiles, defaultId } = profilesOf(config);
  return Object.keys(profiles)
    .filter(id => id !== defaultId)
    .flatMap(id => {
      const profile = resolveProfile(id, profiles);
      return profile ? [{ config, id, profile }] : [];
    });
}

// ---------------------------------------------------------------------------
// MCP servers
// ---------------------------------------------------------------------------

export interface McpServerRef {
  config: ParsedConfig;
  name: string;
  server: Record<string, unknown>;
  path: string;
}

/** Servers in the user settings.json and a project .mcp.json (`mcpServers` map). */
export function mcpServers(configs: ParsedConfig[]): McpServerRef[] {
  const refs: McpServerRef[] = [];
  for (const config of configs) {
    const name = basename(config.filePath);
    if (name !== MUSE_CODE_SETTINGS && name !== MUSE_CODE_PROJECT_MCP) continue;
    const raw = config.data.mcpServers;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    for (const [server, entry] of Object.entries(raw as Record<string, unknown>)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const rec = entry as Record<string, unknown>;
      if (rec.enabled === false || rec.disabled === true) continue;
      refs.push({ config, name: server, server: rec, path: `mcpServers.${server}` });
    }
  }
  return refs;
}

// ---------------------------------------------------------------------------
// Workspace trust
// ---------------------------------------------------------------------------

/** Directories recorded as trusted in trust.json (exact paths — trust is not inherited). */
export async function trustedProjects(ctx: ScanContext): Promise<Set<string>> {
  const file = join(museConfigDir(ctx.fs.homedir(), ctx.fs), MUSE_CODE_TRUST);
  let data: unknown;
  try {
    data = await parseIfPresent(file, ctx.fs, raw => JSON.parse(raw) as unknown);
  } catch {
    data = undefined;
  }
  const projects = (data as { projects?: unknown } | undefined)?.projects;
  const out = new Set<string>();
  if (!projects || typeof projects !== 'object' || Array.isArray(projects)) return out;
  for (const [path, entry] of Object.entries(projects as Record<string, unknown>)) {
    if ((entry as { decision?: unknown } | undefined)?.decision === 'trusted') out.add(path.replace(/[\\/]+$/, '') || '/');
  }
  return out;
}

/**
 * Project files (.mcp.json, .muse/hooks.json) take effect only once their
 * exact workspace is trusted: until then the finding is downgraded, not
 * dropped — trusting the repo activates it.
 */
export async function markUntrustedProject(ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!isProjectInstall(ctx) || evidence.length === 0) return;
  const workspace = dirname(ctx.installation.installDir);
  if ((await trustedProjects(ctx)).has(workspace)) return;
  for (const e of evidence) {
    e.mitigated = true;
    e.detail = `${e.detail ?? ''} — inactive until workspace "${basename(workspace)}" is trusted`.replace(/^ — /, '');
  }
}

// ---------------------------------------------------------------------------
// File modes
// ---------------------------------------------------------------------------

export async function modeFacts(ctx: ScanContext, path: string): Promise<PermissionFacts | undefined> {
  if (!(await ctx.fs.access(path))) return undefined;
  try {
    const q = await queryPermissions(ctx.fs, path);
    return q === 'unsupported' ? undefined : q;
  } catch {
    return undefined;
  }
}

/**
 * For findings about *world* access only a world barrier counts: a 0750 home
 * blocks other users even though its group can still traverse it.
 */
export async function markWorldUnreachable(ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  for (const e of evidence) {
    for (let dir = dirname(e.file); ; dir = dirname(dir)) {
      const f = await modeFacts(ctx, dir);
      if (f && !f.worldExec) {
        e.mitigated = true;
        e.detail = `${e.detail} — mitigated: ${dir} (${f.octal}) blocks other users`;
        break;
      }
      if (dirname(dir) === dir) break;
    }
  }
}

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

export function envFlag(ctx: ScanContext, name: string): boolean {
  return TRUTHY.has((ctx.fs.getEnv(name) ?? '').trim().toLowerCase());
}

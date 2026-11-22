import type { ParsedConfig } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { openclawAgentEntries } from './openclaw-agents.js';

/**
 * Whether OpenClaw's tool policy leaves a core tool on an agent's tool
 * surface — so a check about how that tool is configured (CFG-005: the exec
 * policy; CFG-006: file-tool confinement) only speaks when the tool exists.
 *
 * Mirrors OpenClaw 2026.11.2 (`resolveEffectiveToolPolicy`,
 * `createToolPolicyMatcher`, tool-catalog): a tool must pass every stage —
 * the profile (`tools.profile`, an agent's own `tools.profile` replacing it;
 * minimal / messaging carry no runtime or fs tools, coding does, full is
 * "*", plus `alsoAllow`), the root `tools.allow`/`alsoAllow`/`deny`, and the
 * agent's own allow/deny. Deny wins; `group:<section>` and `*` globs expand;
 * `bash` is `exec`; a `write` allow also allows `apply_patch`. Provider-scoped
 * policies (`byProvider`) only apply to some models and are not judged — the
 * tool counts as available. An allowlist naming no core tool (plugin tools
 * only) is dropped by OpenClaw, so it doesn't restrict here either.
 */

const RUNTIME = ['exec', 'process', 'code_execution', 'secrets'];
const FS = ['ls', 'read', 'write', 'edit', 'apply_patch'];
const GROUPS: Record<string, string[]> = { 'group:runtime': RUNTIME, 'group:fs': FS };
/** Core tools of the minimal / messaging profiles that matter here: none of RUNTIME/FS but `secrets` (messaging). */
const PROFILE_ALLOW: Record<string, string[] | undefined> = {
  minimal: ['presence'],
  messaging: ['secrets', 'message', 'sessions', 'sessions_list', 'sessions_send', 'presence'],
  coding: [...RUNTIME, ...FS],
  full: ['*'],
};
const ALIASES: Record<string, string> = { bash: 'exec', 'apply-patch': 'apply_patch' };
/** Core tool ids (2026.11.2 catalog) — an allowlist naming none of them is plugin-only. */
const CORE_TOOLS = new Set([
  ...RUNTIME, ...FS, 'agents_list', 'agents_wait', 'ask_user', 'automations', 'browser', 'canvas', 'computer',
  'conversations_list', 'conversations_send', 'conversations_turn', 'create_goal', 'dashboard',
  'decision_evaluate', 'dismiss_task', 'gateway', 'get_goal', 'github_identity_status', 'github_publish',
  'heartbeat_respond', 'image_generate', 'memory_get', 'memory_search', 'message', 'mobile_ui',
  'music_generate', 'nodes', 'pdf', 'personal_instructions', 'plugins', 'portal', 'presence',
  'progress_card', 'screen', 'session_status', 'sessions', 'sessions_history', 'sessions_list',
  'sessions_search', 'sessions_send', 'sessions_spawn', 'sessions_yield', 'show_widget', 'skill_workshop',
  'skills_read', 'skills_search', 'subagents', 'suggest_task', 'terminal', 'theme', 'transcripts', 'tts',
  'update_goal', 'video_generate', 'view_image', 'web_fetch', 'web_search', 'x_search',
]);

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function list(v: unknown): string[] | undefined {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').map(x => x.trim().toLowerCase()).filter(Boolean) : undefined;
}

function expand(entries: string[]): string[] {
  return entries.flatMap(e => GROUPS[e] ?? [ALIASES[e] ?? e]);
}

function matches(name: string, patterns: string[]): boolean {
  return patterns.some(p => p === name
    || (p.includes('*') && new RegExp(`^${p.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(name)));
}

interface Policy { allow?: string[]; deny?: string[] }

/** OpenClaw's pickSandboxToolPolicy: alsoAllow widens an allowlist, or "*" when there is none. */
function pick(tools: Record<string, unknown> | undefined): Policy | undefined {
  if (!tools) return undefined;
  const base = list(tools.allow);
  const extra = list(tools.alsoAllow);
  const allow = extra?.length ? [...(base?.length ? base : ['*']), ...extra] : base;
  const deny = list(tools.deny);
  return allow || deny ? { allow, deny } : undefined;
}

function allowed(name: string, policy: Policy | undefined): boolean {
  if (!policy) return true;
  const deny = expand(policy.deny ?? []);
  if (matches(name, deny)) return false;
  const allow = expand(policy.allow ?? []);
  // plugin-only allowlists are stripped so core tools stay available
  if (allow.length === 0 || !allow.some(a => a.includes('*') || CORE_TOOLS.has(a))) return true;
  if (matches(name, allow)) return true;
  return name === 'apply_patch' && matches('write', allow);
}

function profilePolicy(profile: unknown, alsoAllow: string[] | undefined): Policy | undefined {
  if (typeof profile !== 'string') return undefined;
  const base = PROFILE_ALLOW[profile.trim().toLowerCase()];
  if (!base) return undefined;
  return { allow: [...base, ...(alsoAllow ?? [])] };
}

/** Whether any of `names` is on the tool surface of one agent (`agentTools` = its own `tools`). */
function availableFor(root: Record<string, unknown>, agentTools: Record<string, unknown> | undefined, names: string[]): boolean {
  const globalTools = asRecord(root.tools);
  const profile = agentTools?.profile ?? globalTools?.profile;
  const alsoAllow = list(agentTools?.alsoAllow) ?? list(globalTools?.alsoAllow);
  const stages = [profilePolicy(profile, alsoAllow), pick(globalTools), pick(agentTools)];
  return names.some(n => stages.every(s => allowed(n, s)));
}

export interface OpenclawToolScope {
  /** undefined = the default agent; otherwise the agent entry id */
  agentId?: string;
  config: ParsedConfig;
  /** the agent entry (undefined for the default agent) */
  entry?: Record<string, unknown>;
  available: boolean;
}

/**
 * Every agent of each OpenClaw config (.env files hold no tool policy) and
 * whether `names` reach it: the default agent (with `agents.defaults.tools`
 * when the config has no agent roster, as OpenClaw resolves it) and every
 * `agents.entries.<id>` / `agents.list[]` entry.
 */
export function openclawToolScopes(configs: ParsedConfig[], names: string[]): OpenclawToolScope[] {
  const out: OpenclawToolScope[] = [];
  const policyConfigs = configs.filter(c => c.format !== 'env');
  const entries = openclawAgentEntries(policyConfigs);
  for (const config of policyConfigs) {
    const root = config.data ?? {};
    const roster = getNestedValue(root, 'agents.entries') !== undefined || getNestedValue(root, 'agents.list') !== undefined;
    const defaults = roster ? undefined : asRecord(getNestedValue(root, 'agents.defaults.tools'));
    out.push({ config, available: availableFor(root, defaults, names) });
    for (const e of entries.filter(x => x.config === config)) {
      out.push({ agentId: e.id, config, entry: e.data, available: availableFor(root, asRecord(e.data.tools), names) });
    }
  }
  return out;
}

/** True unless the tool policy removes every one of `names` from every agent (none of the configs is a policy → available). */
export function openclawToolsAvailable(configs: ParsedConfig[], names: string[]): boolean {
  const scopes = openclawToolScopes(configs, names);
  return scopes.length === 0 || scopes.some(s => s.available);
}

export const OPENCLAW_EXEC_TOOLS = ['exec'];
export const OPENCLAW_FS_TOOLS = ['read', 'write', 'edit', 'apply_patch'];

/** gateway.mode "remote": this install is a client of a gateway elsewhere — its tools run there, under that gateway's config. */
export function openclawRemoteClient(configs: ParsedConfig[]): ParsedConfig | undefined {
  return configs.find(c => c.format !== 'env' && getNestedValue(c.data, 'gateway.mode') === 'remote');
}

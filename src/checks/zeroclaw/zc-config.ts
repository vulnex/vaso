import type { FixResult, ParsedConfig, ScanContext } from '../../core/types.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import type { KeyPath } from '../../core/utils.js';
import { envOverrideFor } from '../../adapters/env-overrides.js';
import { isLoopbackAddress } from '../../core/listen-address.js';

/**
 * Shared readers for ZeroClaw's V3 config schema (`schema_version = 3`,
 * zeroclaw ≥ 0.8). Upstream auto-migrates V1/V2 configs to V3 on load, so
 * on-disk configs are V3 after the first run; the only legacy shape still
 * honoured here is the V2 `[autonomy]` table (migrated upstream into
 * `[risk_profiles.default]`).
 *
 * Every reader tolerates absent/null sections, scalar keys among alias maps
 * and unexpected types — checks must never throw on a real config.
 */

export type Rec = Record<string, unknown>;

export function asRecord(v: unknown): Rec | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Rec) : undefined;
}

export function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function isTrue(v: unknown): boolean {
  return v === true || v === 'true';
}

export function isFalse(v: unknown): boolean {
  return v === false || v === 'false';
}

export function hasWildcard(v: unknown): boolean {
  return asStringArray(v).some(s => s.trim() === '*');
}

/** The main `config.toml` (never the migration backup or auth-profiles.json). */
export function mainConfig(configs: ParsedConfig[]): ParsedConfig | undefined {
  return configs.find(c => c.format === 'toml' && /(^|[\\/])config\.toml$/.test(c.filePath));
}

/**
 * Whether the gateway host binds loopback only — any spelling the socket
 * layer resolves to 127.0.0.0/8 or ::1 (src/core/listen-address.ts), not
 * just the literals upstream's is_public_bind guard lists.
 */
export function isLoopbackHost(host: string): boolean {
  return isLoopbackAddress(host);
}

export interface GatewayPosture {
  host: string;
  hostExposed: boolean;
  allowPublicBind: boolean;
  tunnelProvider: string;
  tunnelActive: boolean;
  tlsEnabled: boolean;
  requirePairing: boolean;
  webhookSecret: boolean;
}

/** `[gateway]` + `[tunnel]` with upstream defaults applied. */
export function gatewayPosture(data: Rec): GatewayPosture {
  const gw = asRecord(data.gateway) ?? {};
  const tunnel = asRecord(data.tunnel) ?? {};
  const host = typeof gw.host === 'string' && gw.host.trim() ? gw.host.trim() : '127.0.0.1';
  // V3 key is tunnel_provider; pre-V3 configs used [tunnel] provider.
  const rawTunnel = tunnel.tunnel_provider ?? tunnel.provider;
  const tunnelProvider = typeof rawTunnel === 'string' && rawTunnel.trim() ? rawTunnel.trim().toLowerCase() : 'none';
  const tls = asRecord(gw.tls);
  return {
    host,
    hostExposed: !isLoopbackHost(host),
    allowPublicBind: isTrue(gw.allow_public_bind),
    tunnelProvider,
    tunnelActive: tunnelProvider !== 'none',
    tlsEnabled: isTrue(tls?.enabled),
    requirePairing: !isFalse(gw.require_pairing),
    webhookSecret: typeof gw.webhook_secret === 'string' && gw.webhook_secret.trim() !== '',
  };
}

export interface AgentEntry {
  alias: string;
  data: Rec;
}

/** `[agents.<alias>]` entries that are enabled (upstream default: enabled). */
export function enabledAgents(data: Rec): AgentEntry[] {
  const agents = asRecord(data.agents);
  if (!agents) return [];
  const out: AgentEntry[] = [];
  for (const [alias, raw] of Object.entries(agents)) {
    const a = asRecord(raw);
    if (!a || isFalse(a.enabled)) continue;
    out.push({ alias, data: a });
  }
  return out;
}

export interface EffectiveProfile {
  name: string;
  /** Key segments of the profile table (fix target) — a profile name may contain a dot. */
  path: string[];
  profile: Rec;
  /** Enabled agents bound to this profile (empty when no agents are declared). */
  agents: string[];
  /** V2 `[autonomy]` table rather than a V3 risk profile. */
  legacy: boolean;
}

/**
 * Risk profiles that actually govern an enabled agent. When the config
 * declares no agents at all every profile is evaluated (nothing narrows
 * them). A pre-V3 `[autonomy]` table is evaluated as a legacy profile.
 */
export function effectiveProfiles(data: Rec): EffectiveProfile[] {
  const profiles = asRecord(data.risk_profiles);
  const agents = enabledAgents(data);
  const out: EffectiveProfile[] = [];

  if (profiles) {
    const bound = new Map<string, string[]>();
    for (const a of agents) {
      const ref = typeof a.data.risk_profile === 'string' && a.data.risk_profile.trim()
        ? a.data.risk_profile.trim()
        : 'default';
      bound.set(ref, [...(bound.get(ref) ?? []), a.alias]);
    }
    const declaredAgents = asRecord(data.agents) !== undefined && Object.keys(asRecord(data.agents)!).length > 0;
    for (const [name, raw] of Object.entries(profiles)) {
      const profile = asRecord(raw);
      if (!profile) continue;
      const users = bound.get(name) ?? [];
      if (declaredAgents && users.length === 0) continue;
      out.push({ name, path: ['risk_profiles', name], profile, agents: users, legacy: false });
    }
  }

  if (out.length === 0 && !profiles) {
    const autonomy = asRecord(data.autonomy);
    if (autonomy) {
      out.push({ name: '[autonomy]', path: ['autonomy'], profile: autonomy, agents: [], legacy: true });
    }
  }
  return out;
}

export function profileLabel(p: EffectiveProfile): string {
  if (p.legacy) return 'legacy [autonomy]';
  const who = p.agents.length > 0 ? ` (agent${p.agents.length > 1 ? 's' : ''}: ${p.agents.join(', ')})` : '';
  return `risk_profiles.${/^[A-Za-z0-9_-]+$/.test(p.name) ? p.name : JSON.stringify(p.name)}${who}`;
}

/** 1-based line of the first `key =` inside the TOML table `[table]`, when present. */
export function tomlLine(raw: string, table: string, key: string): { line: number; snippet: string } | undefined {
  const lines = raw.split('\n');
  let inTable = table === '';
  const header = `[${table}]`;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith('[')) {
      inTable = t === header;
      continue;
    }
    if (inTable && new RegExp(`^"?${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?\\s*=`).test(t)) {
      return { line: i + 1, snippet: t.slice(0, 160) };
    }
  }
  return undefined;
}

/**
 * Write several real V3 keys into the main config.toml. Every path passed
 * here must exist in the upstream schema with the right type — ZeroClaw
 * validates the file on load.
 */
export async function writeMainConfig(
  ctx: ScanContext,
  checkId: string,
  updates: Array<[path: KeyPath, value: unknown]>,
  message: string,
): Promise<FixResult> {
  const config = mainConfig(ctx.configs);
  if (!config) return { checkId, applied: false, message: 'No ZeroClaw config.toml found' };
  if (updates.length === 0) return { checkId, applied: false, message: 'Nothing to change' };
  // A ZEROCLAW_<path> env override beats config.toml, so writing the file
  // alone doesn't change what the daemon runs with — say so instead of
  // implying the fix took effect. The file did change (backup/rollback must
  // still cover it), so the result stays applied.
  const overridden: string[] = [];
  for (const [path, value] of updates) {
    await updateConfigValue(config, path, value);
    const env = envOverrideFor(config.data, path);
    if (env) overridden.push(env);
  }
  if (overridden.length > 0) {
    const vars = overridden.map(e => `$${e}`).join(', ');
    return {
      checkId,
      applied: true,
      message: `${message} in config.toml, but ${vars} still override${overridden.length === 1 ? 's' : ''} it — unset ${overridden.length === 1 ? 'it' : 'them'} in the daemon's environment`,
    };
  }
  return { checkId, applied: true, message };
}

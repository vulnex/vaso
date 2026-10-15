import type { ParsedConfig } from '../../core/types.js';
import { deepMerge } from '../../core/utils.js';

export interface Posture {
  tls?: boolean;
  authMode?: string;
  gatewayHost?: string;
  gatewayPort?: number;
  sandboxEnabled?: boolean;
  approvalRequired?: boolean;
}

export function mergeConfigData(configs: ParsedConfig[]): Record<string, unknown> {
  let merged: Record<string, unknown> = {};
  for (const c of configs) {
    merged = deepMerge(merged, c.data) as Record<string, unknown>;
  }
  return merged;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function asBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    const lower = v.toLowerCase();
    if (lower === 'true' || lower === '1') return true;
    if (lower === 'false' || lower === '0') return false;
  }
  return undefined;
}

/** OpenClaw 2026.x `gateway.bind` mode → the address it listens on, as far as config tells. */
function bindHost(bind: unknown, customBindHost: unknown): string | undefined {
  switch (typeof bind === 'string' ? bind.toLowerCase() : undefined) {
    case 'loopback': return '127.0.0.1';
    case 'lan': return '0.0.0.0';
    // Prefers the tailnet address, else LAN (0.0.0.0) — can expose all interfaces
    case 'auto': return 'auto';
    case 'tailnet': return 'tailnet';
    case 'custom': return typeof customBindHost === 'string' ? customBindHost : undefined;
    default: return undefined;
  }
}

/** sandbox.mode (2026.x: off | non-main | all) → enabled. */
function sandboxModeEnabled(mode: unknown): boolean | undefined {
  if (typeof mode !== 'string') return undefined;
  return mode.toLowerCase() !== 'off';
}

/** tools.exec (2026.x mode/ask, legacy security/ask) → whether a human approves misses. */
function execApproval(exec: Record<string, unknown> | undefined): boolean | undefined {
  if (!exec) return undefined;
  const mode = typeof exec.mode === 'string' ? exec.mode : exec.security;
  if (mode === 'full') return false;
  if (mode === 'ask') return true;
  if (exec.ask === 'off') return false;
  if (exec.ask === 'on-miss' || exec.ask === 'always') return true;
  return undefined;
}

/**
 * Security posture of a merged OpenClaw config. Reads the 2026.x keys
 * (verified against the 2026.9.4 `openclaw config schema`): gateway.bind /
 * customBindHost, gateway.tls.enabled, gateway.auth.mode,
 * agents.defaults.sandbox.mode and tools.exec — with the per-agent
 * `agents.entries.<agentId>` overrides when an agent id is given. The
 * pre-2026 keys (gateway.host, boolean gateway.tls, sandbox.enabled,
 * policy.require_approval) are the fallback.
 */
export function extractPosture(merged: Record<string, unknown>, agentId?: string): Posture {
  const gw = asRecord(merged.gateway);
  const auth = gw ? asRecord(gw.auth) : undefined;
  const sandbox = asRecord(merged.sandbox);
  const policy = asRecord(merged.policy);
  const agents = asRecord(merged.agents);
  const entries = asRecord(agents?.entries);
  const list = Array.isArray(agents?.list) ? agents.list : [];
  const entry = agentId
    ? asRecord(entries?.[agentId]) ?? asRecord(list.find(i => asRecord(i)?.id === agentId))
    : undefined;
  const tlsSection = gw ? asRecord(gw.tls) : undefined;

  const sandboxEnabled = sandboxModeEnabled(asRecord(entry?.sandbox)?.mode)
    ?? sandboxModeEnabled(asRecord(asRecord(agents?.defaults)?.sandbox)?.mode)
    ?? (sandbox ? asBool(sandbox.enabled) : undefined);
  const approvalRequired = execApproval(asRecord(asRecord(entry?.tools)?.exec))
    ?? execApproval(asRecord(asRecord(merged.tools)?.exec))
    ?? (policy ? asBool(policy.require_approval ?? policy.requireApproval) : undefined);

  return {
    tls: tlsSection ? asBool(tlsSection.enabled) : gw ? asBool(gw.tls) : undefined,
    // Typed reads: a hand-edited config can hold any JSON value here
    authMode: typeof auth?.mode === 'string' ? auth.mode : undefined,
    gatewayHost: (typeof gw?.host === 'string' ? gw.host : undefined) ?? bindHost(gw?.bind, gw?.customBindHost),
    gatewayPort: typeof gw?.port === 'number' ? gw.port : undefined,
    sandboxEnabled,
    approvalRequired,
  };
}

const PUBLIC_HOSTS = new Set(['0.0.0.0', '::', '*', 'auto']);

function isPublic(host: string | undefined): boolean {
  return host !== undefined && PUBLIC_HOSTS.has(host);
}

function isLoopback(host: string | undefined): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

const AUTH_RANK: Record<string, number> = {
  none: 0,
  basic: 1,
  apikey: 2,
  api_key: 2,
  jwt: 3,
  oauth: 4,
  oauth2: 4,
  mtls: 5,
  // OpenClaw 2026.x gateway.auth.mode: every mode but "none" requires a credential
  token: 2,
  password: 2,
  'trusted-proxy': 2,
};

function authRank(mode: string | undefined): number | undefined {
  if (!mode) return undefined;
  return AUTH_RANK[mode.toLowerCase()];
}

export function findDowngrades(base: Posture, override: Posture): string[] {
  const issues: string[] = [];

  if (base.tls === true && override.tls === false) {
    issues.push('TLS disabled (base had TLS enabled)');
  }

  if (isLoopback(base.gatewayHost) && isPublic(override.gatewayHost)) {
    issues.push(`Gateway re-bound from ${base.gatewayHost} to ${override.gatewayHost} (publicly exposed)`);
  }

  if (base.sandboxEnabled === true && override.sandboxEnabled === false) {
    issues.push('Sandbox disabled (base had sandbox enabled)');
  }

  if (base.approvalRequired === true && override.approvalRequired === false) {
    issues.push('Tool approval no longer required (base required approval)');
  }

  const baseAuth = authRank(base.authMode);
  const overrideAuth = authRank(override.authMode);
  if (baseAuth !== undefined && overrideAuth !== undefined && overrideAuth < baseAuth) {
    issues.push(`Auth mode downgraded from ${base.authMode} to ${override.authMode}`);
  }

  return issues;
}

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

export function extractPosture(merged: Record<string, unknown>): Posture {
  const gw = asRecord(merged.gateway);
  const auth = gw ? asRecord(gw.auth) : undefined;
  const sandbox = asRecord(merged.sandbox);
  const policy = asRecord(merged.policy);

  return {
    tls: gw ? asBool(gw.tls) : undefined,
    authMode: auth?.mode as string | undefined,
    gatewayHost: gw?.host as string | undefined,
    gatewayPort: gw?.port as number | undefined,
    sandboxEnabled: sandbox ? asBool(sandbox.enabled) : undefined,
    approvalRequired: policy ? asBool(policy.require_approval ?? policy.requireApproval) : undefined,
  };
}

const PUBLIC_HOSTS = new Set(['0.0.0.0', '::', '*']);

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

import type { Evidence, ScanContext } from '../../core/types.js';
import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

/**
 * Credential and state stores in an OpenClaw state dir (2026.9.4 sources):
 *   state/openclaw.sqlite                      shared state DB (sessions, pairing)
 *   agents/<id>/agent/openclaw-agent.sqlite    per-agent DB, incl. the auth-profile store
 *   agents/<id>/agent/auth-profiles.json, auth-state.json, auth.json
 *                                              pre-SQLite auth stores (doctor migrates them)
 *   credentials/**                             OAuth dir: oauth.json, channel logins
 *                                              (credentials/whatsapp/<account>/creds.json)
 *   identity/device.json                       legacy device identity key
 *   memory.json, conversations.db              pre-2026 memory stores
 * plus any `secrets.providers.<name>` file provider's path. Remote scans
 * collect all but the configured secret-provider paths, metadata only.
 */
const STATE_FILES = ['memory.json', 'conversations.db', 'identity/device.json'];
const SQLITE_SIDECARS = ['', '-wal', '-shm'];
const AGENT_FILES = [
  ...SQLITE_SIDECARS.map(s => `openclaw-agent.sqlite${s}`),
  'auth-profiles.json', 'auth-state.json', 'auth.json',
];
/** credentials/ nesting OpenClaw uses: <channel>/<account>/<file>. */
const CREDENTIALS_DEPTH = 3;

async function filesUnder(ctx: ScanContext, dir: string, depth: number): Promise<string[]> {
  if (depth < 0) return [];
  let entries;
  try {
    entries = await ctx.fs.readdirEntries(dir);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory) out.push(...(await filesUnder(ctx, p, depth - 1)));
    else if (e.isFile) out.push(p);
  }
  return out;
}

async function subdirs(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    return (await ctx.fs.readdirEntries(dir)).filter(e => e.isDirectory).map(e => join(dir, e.name));
  } catch {
    return [];
  }
}

/** `secrets.providers.<name>.path` of `source: "file"` providers (`~` = home). */
function secretProviderFiles(ctx: ScanContext): string[] {
  const out: string[] = [];
  for (const config of ctx.configs) {
    const providers = getNestedValue(config.data, 'secrets.providers');
    if (!providers || typeof providers !== 'object') continue;
    for (const p of Object.values(providers as Record<string, unknown>)) {
      const provider = p as Record<string, unknown> | null;
      if (provider?.source !== 'file' || typeof provider.path !== 'string' || !provider.path.trim()) continue;
      const path = provider.path.trim();
      out.push(path === '~' || path.startsWith('~/') ? join(ctx.fs.homedir(), path.slice(1)) : path);
    }
  }
  return out;
}

export async function openclawStoreFiles(ctx: ScanContext): Promise<string[]> {
  const dir = ctx.installation.installDir;
  const candidates = [
    ...STATE_FILES.map(f => join(dir, f)),
    ...SQLITE_SIDECARS.map(s => join(dir, 'state', `openclaw.sqlite${s}`)),
    ...(await filesUnder(ctx, join(dir, 'credentials'), CREDENTIALS_DEPTH)),
    ...secretProviderFiles(ctx),
  ];
  for (const agentDir of await subdirs(ctx, join(dir, 'agents'))) {
    candidates.push(...AGENT_FILES.map(f => join(agentDir, 'agent', f)));
  }
  const present: string[] = [];
  for (const p of [...new Set(candidates)]) if (await ctx.fs.access(p)) present.push(p);
  return present;
}

async function exposedStores(ctx: ScanContext): Promise<Evidence[]> {
  const evidence: Evidence[] = [];
  for (const filePath of await openclawStoreFiles(ctx)) {
    try {
      const stats = await ctx.fs.stat(filePath);
      if (!stats.isFile()) continue;
      const perms = await queryPermissions(ctx.fs, filePath);
      if (perms !== 'unsupported' && accessibleByOthers(perms)) {
        evidence.push({
          file: filePath,
          detail: `Permissions: ${perms.octal} — should be 600 (owner-only)`,
        });
      }
    } catch {
      // stat failure — skip
    }
  }
  return evidence;
}

export const oc006 = defineCheck({
  id: 'OC-006',
  name: 'Credential and State Store Permissions',
  category: 'openclaw',
  severity: 'warning',
  description: 'Verify OpenClaw\'s credential and state stores are not group/world-readable: the state and per-agent SQLite databases (sessions, auth profiles), credentials/ (OAuth tokens, channel logins such as WhatsApp creds.json), legacy auth-profiles.json / device identity / memory files, and file-based secret providers.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-006 only runs at top-level');
    }

    const evidence = await exposedStores(ctx);
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Credential and state stores are owner-only (or absent)',
      failed: (n) => `${n} credential/state store${n === 1 ? '' : 's'} readable by group/other`,
      fixable: true,
      fixDescription: 'Remove group/other access from the listed stores (chmod go-rwx)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('OC-006', (await exposedStores(ctx)).map(e => e.file!));
  },
});

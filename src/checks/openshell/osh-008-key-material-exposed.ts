import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, readableByOthers } from '../../core/permissions.js';
import { expandHome } from '../../adapters/openshell.js';
import { databasePaths, facts, gateway, listDir, paths, record, tlsDirs } from './shared.js';

interface Target { path: string; critical: boolean; detail: string }

/** Every file under `dir` (two levels: <workspace>/<sandbox-id>/<file>). */
async function tokenFiles(ctx: ScanContext, dir: string, depth = 3): Promise<string[]> {
  const out: string[] = [];
  for (const e of await listDir(ctx, dir)) {
    if (e.isDirectory) {
      if (depth > 1) out.push(...await tokenFiles(ctx, e.path, depth - 1));
    } else {
      out.push(e.path);
    }
  }
  return out;
}

async function targets(ctx: ScanContext): Promise<Target[]> {
  const p = paths(ctx);
  const t: Target[] = [];
  for (const dir of tlsDirs(ctx)) {
    t.push({ path: join(dir, 'ca.key'), critical: true, detail: 'Gateway CA private key — mints client certificates that authenticate as a gateway user' });
    t.push({ path: join(dir, 'jwt', 'signing.pem'), critical: true, detail: 'Gateway JWT signing key — forges supervisor and sandbox credentials' });
    t.push({ path: join(dir, 'server', 'tls.key'), critical: false, detail: 'Gateway server TLS key — impersonates the gateway' });
    t.push({ path: join(dir, 'client', 'tls.key'), critical: true, detail: 'Gateway client key — authenticates as the gateway user (mTLS)' });
  }
  // Key paths named explicitly in the gateway TOML
  const gw = gateway(ctx);
  const tls = record(gw.tls);
  const jwt = record(gw.gateway_jwt);
  const cs = record(gw.credential_storage);
  for (const [v, critical, detail] of [
    [tls?.key_path, false, 'Gateway server TLS key'],
    [jwt?.signing_key_path, true, 'Gateway JWT signing key'],
    [gw.guest_tls_key, true, 'Sandbox client TLS key'],
    [cs?.key_encryption_key_path, true, 'Key-encryption key for stored provider credentials'],
  ] as const) {
    if (typeof v === 'string' && v.trim()) t.push({ path: expandHome(v.trim(), p.home), critical, detail });
  }
  t.push({ path: join(p.stateDir, 'gateway', 'credentials', 'key-encryption-key.bin'), critical: true, detail: 'Key-encryption key — with the database, decrypts every stored provider credential' });
  for (const db of databasePaths(ctx)) {
    for (const suffix of ['', '-wal', '-shm']) {
      t.push({ path: db + suffix, critical: false, detail: 'Gateway database — sandboxes, policies and (encrypted) provider credentials' });
    }
  }
  for (const file of await tokenFiles(ctx, join(p.stateDir, 'docker-sandbox-tokens'))) {
    t.push({ path: file, critical: true, detail: 'Sandbox bootstrap credential (sandbox JWT / supervisor auth / boundary key)' });
  }
  for (const g of await listDir(ctx, join(p.configDir, 'gateways'))) {
    if (!g.isDirectory) continue;
    t.push({ path: join(g.path, 'mtls', 'tls.key'), critical: true, detail: `CLI client key for gateway "${g.name}" — full gateway user access` });
    t.push({ path: join(g.path, 'oidc_token.json'), critical: true, detail: `OIDC token bundle for gateway "${g.name}"` });
    t.push({ path: join(g.path, 'edge_token'), critical: true, detail: `Edge proxy token for gateway "${g.name}"` });
  }
  const seen = new Set<string>();
  return t.filter(x => !seen.has(x.path) && seen.add(x.path));
}

export const osh008 = defineCheck({
  id: 'OSH-008',
  name: 'OpenShell Key Material Readable by Others',
  category: 'openshell',
  severity: 'critical',
  description: 'Check that OpenShell secrets are owner-only: the gateway CA key, JWT signing key, TLS keys, the credential key-encryption key and database, per-sandbox bootstrap tokens, and the CLI\'s client keys and OIDC tokens',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    for (const t of await targets(ctx)) {
      const f = await facts(ctx, t.path);
      if (!f || !readableByOthers(f)) continue;
      (t.critical ? critical : warning).push({ file: t.path, snippet: `mode 0${f.octal ?? '?'}`, detail: `${t.detail} — readable by ${f.worldRead ? 'all users' : 'group'}` });
    }
    await markUnreachable(ctx.fs, critical);
    await markUnreachable(ctx.fs, warning);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'OpenShell key material is owner-only',
      failed: (n) => `Found ${n} OpenShell secret file(s) readable by other users`,
      severity: critical.some(e => !e.mitigated) ? undefined : 'warning',
      fixDescription: 'chmod 600 the listed files (and 700 their directories); rotate any key another user could have read (openshell-gateway generate-certs, re-register the CLI)',
    });
  },
});

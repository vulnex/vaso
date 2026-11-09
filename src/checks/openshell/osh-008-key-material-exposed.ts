import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, readableByOthers } from '../../core/permissions.js';
import { expandHome } from '../../adapters/openshell.js';
import {
  databasePaths, facts, fixedDatabasePaths, fixedTlsDirs, gateway, gatewayEnv, listDir, paths, record,
  redirectedDatabase, redirectedTlsDir, tlsDirs,
} from './shared.js';

interface Target {
  path: string;
  critical: boolean;
  detail: string;
  /** Named in the gateway config — the probe collects only fixed locations */
  named?: boolean;
  /** How an uncollected file is reported (one line per redirected directory or database) */
  unverifiedAs?: string;
}

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
  // gateway.env redirects (OPENSHELL_LOCAL_TLS_DIR, OPENSHELL_DB_URL) point
  // outside the fixed locations the probe collects
  const tlsRedirect = redirectedTlsDir(ctx);
  const dbRedirect = redirectedDatabase(ctx);
  const tlsNamed = tlsRedirect && !fixedTlsDirs(ctx).includes(tlsRedirect) ? tlsRedirect : undefined;
  const dbNamed = dbRedirect && !fixedDatabasePaths(ctx).includes(dbRedirect) ? dbRedirect : undefined;
  for (const dir of tlsDirs(ctx)) {
    const named = dir === tlsNamed ? { named: true, unverifiedAs: `${dir}/ (OPENSHELL_LOCAL_TLS_DIR)` } : {};
    t.push({ path: join(dir, 'ca.key'), critical: true, detail: 'Gateway CA private key — mints client certificates that authenticate as a gateway user', ...named });
    t.push({ path: join(dir, 'jwt', 'signing.pem'), critical: true, detail: 'Gateway JWT signing key — forges supervisor and sandbox credentials', ...named });
    t.push({ path: join(dir, 'server', 'tls.key'), critical: false, detail: 'Gateway server TLS key — impersonates the gateway', ...named });
    t.push({ path: join(dir, 'client', 'tls.key'), critical: true, detail: 'Gateway client key — authenticates as the gateway user (mTLS)', ...named });
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
    // Gateway config docs: OPENSHELL_TLS_KEY = server private key path (env beats the TOML)
    [gatewayEnv(ctx)?.data.OPENSHELL_TLS_KEY, false, 'Gateway server TLS key'],
  ] as const) {
    if (typeof v === 'string' && v.trim()) t.push({ path: expandHome(v.trim(), p.home), critical, detail, named: true });
  }
  t.push({ path: join(p.stateDir, 'gateway', 'credentials', 'key-encryption-key.bin'), critical: true, detail: 'Key-encryption key — with the database, decrypts every stored provider credential' });
  for (const db of databasePaths(ctx)) {
    const named = db === dbNamed ? { named: true, unverifiedAs: `${db} (OPENSHELL_DB_URL)` } : {};
    for (const suffix of ['', '-wal', '-shm']) {
      t.push({ path: db + suffix, critical: false, detail: 'Gateway database — sandboxes, policies and (encrypted) provider credentials', ...named });
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
    const unverified = new Set<string>();
    for (const t of await targets(ctx)) {
      const f = await facts(ctx, t.path);
      // A key path the config names elsewhere isn't in a remote snapshot:
      // invisible there, not absent
      if (!f && t.named && ctx.fs.kind === 'snapshot' && !(await ctx.fs.access(t.path))) unverified.add(t.unverifiedAs ?? t.path);
      if (!f || !readableByOthers(f)) continue;
      (t.critical ? critical : warning).push({ file: t.path, snippet: `mode 0${f.octal ?? '?'}`, detail: `${t.detail} — readable by ${f.worldRead ? 'all users' : 'group'}` });
    }
    await markUnreachable(ctx.fs, critical);
    await markUnreachable(ctx.fs, warning);
    const note = unverified.size > 0
      ? ` (not collected by the remote probe, permissions unverified — scan locally: ${[...unverified].join(', ')})`
      : '';
    return h.fromEvidence([...critical, ...warning], {
      // Not "owner-only" when part of it was never seen
      passed: note ? `No collected OpenShell key material is readable by others${note}` : 'OpenShell key material is owner-only',
      failed: (n) => `Found ${n} OpenShell secret file(s) readable by other users${note}`,
      severity: critical.some(e => !e.mitigated) ? undefined : 'warning',
      fixDescription: 'chmod 600 the listed files (and 700 their directories); rotate any key another user could have read (openshell-gateway generate-certs, re-register the CLI)',
    });
  },
});

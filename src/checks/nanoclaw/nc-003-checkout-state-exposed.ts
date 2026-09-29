import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import type { Severity } from '../../core/types.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';
import { checkoutDir, Findings, groupOnlyNote } from './shared.js';

const TEMP_PREFIXES = ['/tmp', '/var/tmp', '/private/tmp', '/private/var/tmp', '/dev/shm'];

function inTemp(path: string): boolean {
  return TEMP_PREFIXES.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * The NanoClaw host runs `node dist/index.js` from its checkout, keeps all
 * state under `<checkout>/data/` (central v2.db with users/roles/wirings/
 * pending approvals, per-session inbound/outbound DBs) and serves the `ncl`
 * admin API on `data/ncl.sock` (host callers are trusted by filesystem access
 * alone; upstream chmods it 0600). Anyone who can write the checkout controls
 * code the host executes; anyone who can reach the socket administers the
 * install. NANOCLAW_TEMPLATES_DIR relocates the agent-template library.
 */
export const nc003 = defineCheck({
  id: 'NC-003',
  name: 'Checkout or State Directory Exposed',
  category: 'nanoclaw',
  severity: 'critical',
  description: 'Detect a NanoClaw checkout (host code + .env) or its data/ state directory, central v2.db or ncl.sock admin socket that other local users can write or reach, a checkout inside a world-writable temp directory, or NANOCLAW_TEMPLATES_DIR pointing into one.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const checkout = checkoutDir(ctx);
    if (!checkout) return h.passed('No NanoClaw checkout located');

    const findings = new Findings();
    if (inTemp(checkout)) {
      findings.add({ file: checkout, detail: `Checkout lives in world-writable temp location ${checkout} — any local user can race or replace host code` }, 'critical');
    }

    const probe = async (
      path: string,
      test: 'write' | 'access',
      what: string,
      worldSeverity: Severity,
    ): Promise<void> => {
      try {
        const p = await queryPermissions(ctx.fs, path);
        if (p === 'unsupported') return;
        const world = test === 'write' ? p.worldWrite : (p.worldRead || p.worldWrite);
        const group = test === 'write' ? p.groupWrite : (p.groupRead || p.groupWrite);
        if (!world && !group) return;
        const verb = test === 'write' ? 'writable' : 'accessible';
        findings.add(
          { file: path, detail: `Permissions ${p.octal ?? p.description} — ${what} ${verb} by ${world ? 'any local user' : 'the group'}${groupOnlyNote(world)}` },
          world ? worldSeverity : 'info',
        );
      } catch {
        // absent
      }
    };

    await probe(checkout, 'write', 'checkout (host code the service executes)', 'critical');
    await probe(join(checkout, 'dist'), 'write', 'built host code (dist/)', 'critical');
    await probe(join(checkout, 'data'), 'write', 'state directory (data/)', 'critical');
    await probe(join(checkout, 'data', 'ncl.sock'), 'write', 'ncl admin socket', 'critical');
    await probe(join(checkout, 'data', 'v2.db'), 'access', 'central database v2.db (users, roles, approvals)', 'warning');

    const templates = ctx.fs.getEnv('NANOCLAW_TEMPLATES_DIR')?.trim();
    if (templates && inTemp(templates)) {
      findings.add({ file: '<process env>', detail: `NANOCLAW_TEMPLATES_DIR=${templates} — agent templates loaded from a world-writable temp location` }, 'warning');
    }

    await markUnreachable(ctx.fs, findings.evidence);
    return h.fromEvidence(findings.evidence, {
      passed: 'NanoClaw checkout and state directory are owner-controlled',
      failed: (n) => `${n} NanoClaw checkout/state path${n === 1 ? ' is' : 's are'} exposed to other users`,
      severity: findings.severity('critical'),
      fixable: false,
      fixDescription: 'chmod go-w on the checkout and dist/, chmod 700 data/ (and 600 data/ncl.sock, data/v2.db); keep the checkout out of /tmp',
    });
  },
});

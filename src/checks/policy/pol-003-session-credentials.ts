import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import type { ScanContext } from '../../core/types.js';
import { exposesCredentials, unloadedFileExposes } from '../../core/secret-values.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

/**
 * The declared credential paths that can expose something: a loaded settings
 * file only when it holds a secret (as CFG-003 judges it) — Claude Code,
 * Cursor and Copilot write theirs with the default umask; every other
 * declared path (token stores, auth files) always.
 */
async function exposingPaths(ctx: ScanContext): Promise<string[]> {
  const byPath = new Map(ctx.configs.map(c => [c.filePath, c]));
  const out: string[] = [];
  for (const p of ctx.credentialPaths ?? []) {
    const config = byPath.get(p);
    if (config ? exposesCredentials(config) : await unloadedFileExposes(ctx.fs, p)) out.push(p);
  }
  return out;
}

export const pol003 = defineCheck({
  id: 'POL-003',
  name: 'Session Credential Permissions',
  category: 'policy',
  severity: 'warning',
  description: 'Check that adapter-declared session/token/auth files have restrictive permissions (0600)',
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    if ((ctx.credentialPaths ?? []).length === 0) {
      return h.passed('Adapter does not declare credential paths; skipping');
    }

    const evidence: Evidence[] = [];
    for (const fullPath of await exposingPaths(ctx)) {
      try {
        const stats = await ctx.fs.stat(fullPath);
        if (!stats.isFile()) continue;
        const perms = await queryPermissions(ctx.fs, fullPath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${perms.octal} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    await markUnreachable(ctx.fs, evidence);
    // vaso fix never changes a file through a link: a finding made only of
    // links (a credential path linked to a file elsewhere) is not offered
    let links = 0;
    for (const e of evidence) {
      const file = e.file;
      if (file && await Promise.resolve().then(() => ctx.fs.readlink(file)).then(() => true, () => false)) links++;
    }
    const linkNote = links === 0 ? ''
      : ` — ${links === evidence.length ? (links === 1 ? 'it is' : 'each is') : `${links} of them are`} a link, which vaso fix doesn't change: chmod the target yourself, or replace the link with a file of the agent's own`;
    return h.fromEvidence(evidence, {
      passed: 'All session/credential files have restrictive permissions',
      failed: (n) => `${n} session/credential file(s) have overly permissive permissions`,
      fixable: links < evidence.length,
      fixDescription: `Remove group/other access (chmod go-rwx)${linkNote}`,
    });
  },

  // Credential files that aren't loaded configs (credentials.json, auth.json,
  // token stores) are only reported here; CFG-003's fix never reached them.
  // A declared directory (Copilot's session-state/) is not reported by run(),
  // so the fix leaves it alone too — the agent's own check judges it.
  async fix(ctx) {
    const files: string[] = [];
    for (const path of await exposingPaths(ctx)) {
      if (await Promise.resolve().then(() => ctx.fs.stat(path)).then(s => s.isFile(), () => false)) files.push(path);
    }
    return restrictFilesToOwner('POL-003', files);
  },
});

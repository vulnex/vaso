import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

const CREDENTIAL_FILE = 'credentials.json';

export const cfg020 = defineCheck({
  id: 'CFG-020',
  name: 'NemoClaw API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check if NemoClaw credentials.json stores API keys in plaintext with unsafe file permissions',
  supportedAgents: ['openclaw', 'nemoclaw'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    const credPath = join(ctx.fs.homedir(), '.nemoclaw', CREDENTIAL_FILE);

    if (!(await ctx.fs.access(credPath))) {
      return h.passed('No NemoClaw credentials file found');
    }

    const evidence: Evidence[] = [];
    let hasPlaintextKey = false;
    let hasLoosePerms = false;
    let permEvidence: Evidence | undefined;

    // Check file permissions (unix only)
    if (ctx.fs.platform === 'darwin' || ctx.fs.platform === 'linux') {
      try {
        const perms = await queryPermissions(ctx.fs, credPath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          hasLoosePerms = true;
          permEvidence = {
            file: credPath,
            detail: `Permissions: ${perms.octal} — group/other can read credentials (should be 600)`,
          };
          // Only the permission finding can be mitigated by parent dirs
          await markUnreachable(ctx.fs, [permEvidence]);
          evidence.push(permEvidence);
        }
      } catch {}
    }

    // Check for plaintext API keys
    try {
      const raw = await ctx.fs.readFile(credPath);
      const creds = JSON.parse(raw) as Record<string, unknown>;

      for (const [key, value] of Object.entries(creds)) {
        if (typeof value === 'string' && value.length > 0) {
          // Detect common API key patterns
          const isApiKey = /api[_-]?key|token|secret|password/i.test(key);
          const looksLikeKey = /^(nvapi-|sk-|key-|ghp_|ghs_|glpat-)/.test(value) ||
            (value.length >= 32 && /^[A-Za-z0-9+/=_-]+$/.test(value));

          if (isApiKey || looksLikeKey) {
            hasPlaintextKey = true;
            const redacted = value.slice(0, 8) + '...' + value.slice(-4);
            evidence.push({
              file: credPath,
              detail: `Plaintext key "${key}": ${redacted} (${value.length} chars) — legacy file; current NemoClaw keeps credentials in the OpenShell gateway and deletes it once onboarding migrates every key`,
            });
          }
        }
      }
    } catch {
      evidence.push({ file: credPath, detail: 'Credentials file exists but could not be parsed' });
    }

    const passed = !hasPlaintextKey && !hasLoosePerms;

    return h.result({
      passed,
      message: passed
        ? 'NemoClaw credentials are properly secured'
        : `NemoClaw credentials at risk: ${[
            hasPlaintextKey && 'plaintext API keys',
            hasLoosePerms && 'overly permissive file permissions',
          ].filter(Boolean).join(', ')}`,
      evidence,
      // Critical only when other users can read the keys. A plaintext key in
      // an owner-only file (NemoClaw's legacy store, written 0600 in a 0700
      // dir) is at-rest exposure: migrate it. Loose perms alone, unreachable
      // through parent dirs → informational.
      severity: hasLoosePerms && !permEvidence?.mitigated
        ? undefined
        : hasPlaintextKey ? 'warning' : 'info',
      fixable: hasLoosePerms,
      fixDescription: hasLoosePerms ? 'Remove group/other access from credentials.json (chmod go-rwx)' : undefined,
    });
  },

  async fix(ctx) {
    const credPath = join(ctx.fs.homedir(), '.nemoclaw', CREDENTIAL_FILE);
    if (!(await ctx.fs.access(credPath))) {
      return { checkId: 'CFG-020', applied: false, message: 'Credentials file not found' };
    }

    return restrictFilesToOwner('CFG-020', [credPath]);
  },
});

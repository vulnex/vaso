import { dirname, isAbsolute, join, resolve } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';

/**
 * Absolute path of the helper script, or undefined for a PATH command or a
 * relative path that can't be anchored. Relative paths run from the project
 * root, so they resolve against the repo that holds `.claude/settings*.json`
 * (never the scanner's cwd); user-scope settings have no fixed root.
 */
function helperScriptPath(first: string, settingsFile: string, ctx: ScanContext): string | undefined {
  if (first === '~' || first.startsWith('~/')) return join(ctx.fs.homedir(), first.slice(1));
  if (isAbsolute(first)) return first;
  if (!first.includes('/')) return undefined;
  if (ctx.installation.profile !== 'project') return undefined;
  return resolve(dirname(dirname(settingsFile)), first);
}

export const cc007 = defineCheck({
  id: 'CC-007',
  name: 'apiKeyHelper Script Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that an apiKeyHelper script is not world-writable',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const writable: Evidence[] = [];
    const unverified: string[] = [];
    const missing: string[] = [];

    for (const config of ctx.configs) {
      const helper = config.data.apiKeyHelper;
      if (typeof helper !== 'string' || helper.length === 0) continue;

      // apiKeyHelper is a shell command. Only a path-like first word names a
      // script whose mode matters; `op read op://…` or `security
      // find-generic-password …` run a PATH tool and there is nothing to stat.
      const path = helperScriptPath(helper.trim().split(/\s+/)[0], config.filePath, ctx);
      if (!path) continue;

      try {
        if (!(await ctx.fs.access(path))) {
          // Nothing to replace: a missing script only means Claude Code gets
          // no key from it (the settings reference's own example names
          // /bin/generate_temp_api_key.sh). A snapshot holds only what the
          // probe collected, so absence there says nothing either way.
          if (ctx.fs.kind === 'snapshot') unverified.push(path);
          else missing.push(path);
          continue;
        }
        const perms = await queryPermissions(ctx.fs, path);
        if (perms !== 'unsupported' && perms.worldWrite) {
          // Evidence on the script itself — the settings file's own mode is
          // CFG-003/POL-003's finding, which a shared file would hide
          writable.push({
            file: path,
            snippet: `apiKeyHelper = ${helper} (mode ${perms.octal})`,
            detail: `apiKeyHelper (set in ${config.filePath}) is world-writable — any local user can replace it and exfiltrate the key`,
          });
        }
      } catch {
        // stat failed — skip
      }
    }

    // A world-writable script nobody else can reach (behind a 0700 dir) is
    // downgraded, like every other permission finding
    await markUnreachable(ctx.fs, writable);
    evidence.push(...writable);

    return h.fromEvidence(evidence, {
      passed: unverified.length > 0 && evidence.length === 0
        ? `apiKeyHelper script ${unverified.join(', ')} not verified — the probe doesn't collect it (checked on local scans)`
        : missing.length > 0
        ? `apiKeyHelper script ${missing.join(', ')} does not exist — nothing to replace`
        : 'apiKeyHelper script (if configured) has safe permissions',
      failed: (n) => `Found ${n} apiKeyHelper issue(s)`,
      fixDescription: 'Run `chmod 700` on the apiKeyHelper script and ensure its parent directory is not world-writable',
    });
  },
});

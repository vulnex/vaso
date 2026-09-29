import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, asStringArray, getPath, nanobotConfigs, pick } from './shared.js';

// allowPatterns are re.fullmatch()ed against each shell segment and take
// priority over denyPatterns — including the built-in deny list (rm -rf,
// mkfs, dd if=, shutdown, fork bomb, …) — so a catch-all disables it.
const CATCH_ALL = new Set(['.*', '.+', '^.*$', '^.+$', '(.*)', '[\\s\\S]*', '[\\s\\S]+', '.*?', '(?s).*']);

const SANDBOXES = new Set(['bwrap', 'seatbelt']);

// Bind roots that hand the sandboxed command the whole host or home dir.
function broadBind(path: string): boolean {
  const p = path.trim().replace(/\/+$/, '');
  return p === '' || p === '/' || p === '~' || p === '$HOME' || p === '${HOME}'
    || /^\/(?:home|Users|root|etc)$/.test(p) || /^\/(?:home|Users)\/[^/]+$/.test(p);
}

export const nb004 = defineCheck({
  id: 'NB-004',
  name: 'Shell Exec Tool Unconfined',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check the shell exec tool (tools.exec, enabled by default): a catch-all allowPatterns entry disables the built-in deny list entirely (critical); without tools.exec.sandbox ("bwrap" on Linux, "seatbelt" on macOS) commands run with the user\'s full privileges and can read config.json secrets; broad sandbox bind mounts defeat the sandbox.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of nanobotConfigs(ctx.configs)) {
      const exec = asRecord(getPath(config.data, 'tools.exec'));
      if (exec?.enable === false) continue;

      for (const pattern of asStringArray(pick(exec, 'allowPatterns'))) {
        if (!CATCH_ALL.has(pattern.trim())) continue;
        critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `tools.exec.allowPatterns: ${JSON.stringify(pattern)}`,
          detail: 'Catch-all allow pattern matches every command, so neither denyPatterns nor the built-in deny list (rm -rf, mkfs, dd, shutdown, …) is ever applied',
        });
      }

      const sandbox = pick(exec, 'sandbox');
      if (typeof sandbox !== 'string' || !SANDBOXES.has(sandbox.trim())) {
        evidence.push({
          file: config.filePath,
          snippet: `tools.exec.sandbox: ${JSON.stringify(sandbox ?? '')}`,
          detail: 'Shell commands run unsandboxed with the user\'s full privileges — the deny list is a best-effort regex filter, not a boundary',
        });
      } else {
        const binds = [
          ...asStringArray(pick(exec, 'sandboxRwBinds')).map(b => ({ b, rw: true })),
          ...asStringArray(pick(exec, 'sandboxRoBinds')).map(b => ({ b, rw: false })),
        ];
        for (const { b, rw } of binds) {
          if (!broadBind(b)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `tools.exec.sandbox${rw ? 'Rw' : 'Ro'}Binds: ${JSON.stringify(b)}`,
            detail: `Sandbox ${rw ? 'read-write' : 'read-only'} bind of "${b}" exposes the home directory or host to sandboxed commands`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Shell exec tool is disabled or sandboxed',
      failed: (n) => `${n} shell exec confinement issue(s)`,
      severity: critical ? 'critical' : undefined,
      fixDescription: 'Remove catch-all entries from tools.exec.allowPatterns; set tools.exec.sandbox to "bwrap" (Linux, requires bubblewrap) or "seatbelt" (macOS), keep sandbox binds narrow — or set tools.exec.enable to false if shell access is not needed',
    });
  },
});

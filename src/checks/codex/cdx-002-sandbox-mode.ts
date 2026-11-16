import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';
import { broadRoot, judgeDefaultPermissions } from './permission-profiles.js';

const DANGEROUS_SANDBOX_MODES = new Set([
  'danger-full-access',
  'danger_full_access',
  'dangerously-bypass-sandbox',
  'none',
  'disabled',
]);

export const cdx002 = defineCheck({
  id: 'CDX-002',
  name: 'Codex Sandbox Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Codex sandbox_mode or the default_permissions profile grants unrestricted host access (danger-full-access, writable roots over home, /etc or credential dirs) or unrestricted network access',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    const home = ctx.fs.homedir();
    let critical = false;
    for (const config of ctx.configs) {
      // Profile files only apply under `codex -p <name>` — CDX-008's finding
      if (codexProfileName(config.filePath)) continue;

      // Permission profiles (default_permissions) replace sandbox_mode
      for (const f of judgeDefaultPermissions(config.data, home)) {
        if (f.level === 'critical') critical = true;
        // an entry Codex rejects grants nothing: info
        evidence.push({ file: config.filePath, snippet: f.snippet, detail: f.detail, ...(f.level === 'info' ? { mitigated: true } : {}) });
      }

      const mode = config.data.sandbox_mode ?? config.data.sandboxMode;
      if (typeof mode === 'string' && DANGEROUS_SANDBOX_MODES.has(mode.toLowerCase())) {
        critical = true;
        evidence.push({
          file: config.filePath,
          detail: `sandbox_mode = "${mode}" — Codex commands run with full host access`,
        });
        continue;
      }

      // [sandbox_workspace_write] tunes workspace-write (the default mode for
      // trusted projects): `writable_roots` adds write access beyond the
      // workspace, `network_access` lets sandboxed commands reach the network
      if (typeof mode === 'string' && mode.toLowerCase() !== 'workspace-write') continue;
      const ws = config.data.sandbox_workspace_write as Record<string, unknown> | undefined;
      if (!ws || typeof ws !== 'object') continue;
      for (const root of Array.isArray(ws.writable_roots) ? ws.writable_roots : []) {
        if (typeof root !== 'string') continue;
        const broad = broadRoot(root, home);
        if (broad) {
          critical = true;
          evidence.push({
            file: config.filePath,
            snippet: `[sandbox_workspace_write] writable_roots = "${root}"`,
            detail: `writable root ${broad} — the workspace-write sandbox can modify it (shell rc files, credentials)`,
          });
        }
      }
      if (ws.network_access === true) {
        evidence.push({
          file: config.filePath,
          snippet: '[sandbox_workspace_write] network_access = true',
          detail: 'Sandboxed commands have outbound network access — a prompt-injected command can exfiltrate workspace data',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex sandbox is restricting command execution',
      failed: () => critical
        ? 'Codex sandbox is disabled or can write outside the workspace'
        : evidence.every(e => e.mitigated)
          ? 'Codex permission profile has entries Codex rejects'
          : 'Codex sandboxed commands have outbound network access',
      // network_access alone weakens the sandbox but does not remove it
      severity: critical ? undefined : 'warning',
      fixDescription: 'Set sandbox_mode to "read-only" or "workspace-write" (or default_permissions to ":read-only" / ":workspace"), keep writable roots to project paths, and leave network access off or limited to a domain allowlist',
    });
  },
});

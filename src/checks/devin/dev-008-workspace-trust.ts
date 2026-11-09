import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { devinDataDir } from './paths.js';
import { parseIfPresent } from '../../adapters/load-if-present.js';

/**
 * Workspace trust gates whether a cloned repo's .devin/ hooks, MCP servers,
 * plugins and permission rules load without a prompt. Devin 3000.x exposes
 * two config switches that disable it (both present in the 3000.11.3 binary:
 * `skip_workspace_trust` in the config key set, `respect_workspace_trust`
 * named by its own trust prompt), and records approvals in
 * <data>/cli/trusted_workspaces.json → { "trusted_paths": [...] }.
 *
 * Both switches are user-config only: project configs (.devin/config.json,
 * config.local.json) honour just permissions, hooks, mcpServers and
 * read_config_from as settings (docs.devin.ai configuration precedence; plugin
 * requirements are read separately — DEV-009), so a repo setting them has no
 * effect and isn't reported.
 */
export const dev008 = defineCheck({
  id: 'DEV-008',
  name: 'Devin Workspace Trust Bypassed or Over-Broad',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Devin workspace trust disabled (skip_workspace_trust: true / respect_workspace_trust: false) or a trusted workspace covering /, the home directory, /tmp or /etc — untrusted repos then load hooks, MCP servers and plugins without a prompt',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const userConfigs = ctx.installation.profile === 'project' ? [] : ctx.configs;

    for (const config of userConfigs) {
      if (config.data.skip_workspace_trust === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'skip_workspace_trust: true',
          detail: 'Workspace trust prompts are bypassed — any opened repo\'s .devin/ hooks, MCP servers and plugins load without approval',
        });
      }
      if (config.data.respect_workspace_trust === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'respect_workspace_trust: false',
          detail: 'Workspace trust is not enforced — any opened repo\'s .devin/ hooks, MCP servers and plugins load without approval',
        });
      }
    }

    // Trust approvals are per-user state; the project installation would repeat them
    if (ctx.installation.profile !== 'project') {
      const trustFile = join(devinDataDir(ctx), 'cli', 'trusted_workspaces.json');
      // Present but unreadable or not a JSON object: reported as CONFIG-LOAD
      const data = await parseIfPresent(trustFile, ctx.fs, raw => {
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Top-level value is not a JSON object');
        return parsed as { trusted_paths?: unknown };
      });
      if (data) {
        const home = ctx.fs.homedir();
        const broadPaths = buildBroadPaths(home);
        for (const entry of Array.isArray(data.trusted_paths) ? data.trusted_paths : []) {
          if (typeof entry !== 'string') continue;
          const broad = isBroadPath(entry, broadPaths, home);
          if (broad) {
            evidence.push({
              file: trustFile,
              snippet: `trusted_paths: "${entry}"`,
              detail: `Trusted workspace ${broad.reason} — every repo beneath it is implicitly trusted`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Devin workspace trust is enforced and scoped',
      failed: (n) => `Found ${n} Devin workspace-trust weakness(es)`,
      fixDescription: 'Remove skip_workspace_trust / respect_workspace_trust overrides from Devin config, and drop broad entries from ~/.local/share/devin/cli/trusted_workspaces.json (trust individual repos instead)',
    });
  },
});

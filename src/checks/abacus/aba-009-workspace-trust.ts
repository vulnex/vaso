import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { envFlag, isProjectInstall, trustedWorkspaces } from './shared.js';

/**
 * Workspace trust is what keeps a cloned repo's .abacusai/config.json from
 * raising the permission mode, adding allow rules or directories, swapping the
 * API base URL, and loading its MCP servers and skills. ABACUS_TRUST_WORKSPACE
 * trusts every workspace; trusted-workspaces.json records approvals, and a
 * trusted directory covers every workspace beneath it.
 */
export const aba009 = defineCheck({
  id: 'ABA-009',
  name: 'Abacus.AI Workspace Trust Bypassed or Over-Broad',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI workspace trust disabled by ABACUS_TRUST_WORKSPACE or a trusted workspace covering /, the home directory, /tmp or /etc — any repo opened there can raise the permission mode and load its own MCP servers and skills',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) {
      return h.passed('Workspace trust is user-level — evaluated on the user installation');
    }
    const evidence: Evidence[] = [];

    if (envFlag(ctx, 'ABACUS_TRUST_WORKSPACE')) {
      evidence.push({
        file: '<process env>',
        snippet: `ABACUS_TRUST_WORKSPACE=${ctx.fs.getEnv('ABACUS_TRUST_WORKSPACE')}`,
        detail: 'Every workspace is trusted — a cloned repo\'s .abacusai/config.json, MCP servers and skills apply without a prompt',
      });
    }

    const { file, paths } = await trustedWorkspaces(ctx, { report: true });
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home, ctx.platform);
    for (const p of paths) {
      const broad = isBroadPath(p, broadPaths, home);
      if (!broad) continue;
      evidence.push({
        file,
        snippet: `workspaces: "${p}"`,
        detail: `Trusted workspace ${broad.reason} — trust is inherited, so every repository beneath it loads its .abacusai settings, MCP servers and skills without a prompt`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Abacus.AI workspace trust is enforced and scoped',
      failed: (n) => `Found ${n} Abacus.AI workspace-trust weakness(es)`,
      fixDescription: 'Unset ABACUS_TRUST_WORKSPACE and remove broad entries from ~/.abacusai/trusted-workspaces.json; trust individual repositories instead',
    });
  },
});

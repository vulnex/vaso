import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS, type Evidence } from '../../core/types.js';
import { NATIVE_POLICY_FRAMEWORKS } from './native-policy-frameworks.js';
import { getNestedValue } from '../../core/utils.js';
import { OPENCLAW_FS_TOOLS, openclawRemoteClient, openclawToolScopes } from './openclaw-tool-policy.js';

export const cfg006 = defineCheck({
  id: 'CFG-006',
  name: 'No Workspace Restriction',
  category: 'config',
  severity: 'warning',
  description: 'Check if filesystem access is restricted to a workspace directory',
  // Atomic Agent confines reads via agent.readScope (AT-002), not a workspace key.
  // The other frameworks listed scope the filesystem in their own schemas (framework checks).
  // Hermes and NemoClaw (OpenShell sandbox) have no such keys either.
  excludedAgents: [...CODING_AGENTS, ...NATIVE_POLICY_FRAMEWORKS, 'hermes', 'nemoclaw'],

  async run(ctx, h) {
    // OpenClaw 2026.x: the fs tools are confined by tools.fs.workspaceOnly
    // (agents.defaults.workspace only says where the workspace is).
    // An agent entry's tools.fs.workspaceOnly overrides the root one for that
    // agent, as does a sub-agent file's.
    if (ctx.installation.agent === 'openclaw') {
      if (openclawRemoteClient(ctx.configs)) {
        return h.passed('gateway.mode is "remote" — file tools run on the remote gateway, under its config, not this one\'s');
      }
      // Only agents that have file tools are judged (tools.profile minimal /
      // messaging, or allow/deny lists, can remove them all)
      const scopes = openclawToolScopes(ctx.configs, OPENCLAW_FS_TOOLS);
      if (scopes.length > 0 && !scopes.some(s => s.available)) {
        return h.passed('No agent has file tools (tools.profile / tools.allow / tools.deny) — nothing to confine');
      }
      const restricted = ctx.configs.some(c => getNestedValue(c.data, 'tools.fs.workspaceOnly') === true);
      const evidence: Evidence[] = [];
      for (const c of ctx.configs) {
        const own = scopes.find(s => s.config === c && s.agentId === undefined);
        if (getNestedValue(c.data, 'tools.fs.workspaceOnly') === false && (own?.available ?? true)) {
          evidence.push({ file: c.filePath, detail: 'tools.fs.workspaceOnly: false' });
        }
      }
      for (const scope of scopes) {
        if (scope.entry && scope.available && getNestedValue(scope.entry, 'tools.fs.workspaceOnly') === false) {
          evidence.push({ file: scope.config.filePath, detail: `${scope.entryPath ?? `agents.entries.${scope.agentId}`}.tools.fs.workspaceOnly: false` });
        }
      }
      // Not confined at the root: name each agent with file tools that sets
      // nothing of its own (the default agent, an entry granting them)
      const unconfined: Evidence[] = [];
      if (!restricted) {
        if (scopes.length === 0) {
          unconfined.push({ file: ctx.configs[0]?.filePath ?? ctx.installation.installDir, detail: 'tools.fs.workspaceOnly not set' });
        }
        for (const scope of scopes) {
          if (!scope.available) continue;
          const own = getNestedValue(scope.entry ?? {}, 'tools.fs.workspaceOnly');
          if (own !== undefined) continue; // true confines it; false is reported above
          if (scope.entry) {
            const path = scope.entryPath ?? `agents.entries.${scope.agentId}`;
            unconfined.push({ file: scope.config.filePath, detail: `${path} has file tools and no tools.fs.workspaceOnly — not set at the root either` });
          } else if (getNestedValue(scope.config.data, 'tools.fs.workspaceOnly') === undefined) {
            unconfined.push({ file: scope.config.filePath, detail: 'tools.fs.workspaceOnly not set' });
          }
        }
      }
      const passed = evidence.length === 0 && (restricted || unconfined.length === 0);
      return h.result({
        passed,
        message: passed
          ? 'File tools are confined to the workspace (tools.fs.workspaceOnly)'
          : evidence.length > 0
            ? `File tools can read and write outside the workspace — ${evidence.map(e => e.detail).join('; ')}`
            : `File tools can read and write outside the workspace — ${unconfined.some(e => e.detail?.startsWith('agents.'))
              ? unconfined.map(e => e.detail).join('; ')
              : 'tools.fs.workspaceOnly is not set'}`,
        evidence: [...evidence, ...unconfined],
      });
    }

    let found = false;

    for (const config of ctx.configs) {
      const workspace = getNestedValue(config.data, 'workspace') ??
                        getNestedValue(config.data, 'security.workspace') ??
                        getNestedValue(config.data, 'fs.root') ??
                        getNestedValue(config.data, 'filesystem.restricted') ??
                        config.data.WORKSPACE_DIR;

      if (workspace) {
        found = true;
        break;
      }
    }

    return h.result({
      passed: found,
      message: found
        ? 'Filesystem access is restricted to a workspace directory'
        : 'No workspace restriction — agent has unrestricted filesystem access',
    });
  },
});

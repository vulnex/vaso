import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import {
  asRecord, asStringArray, enabledAgents, effectiveProfiles, isFalse, isTrue, mainConfig, profileLabel, writeMainConfig,
} from './zc-config.js';

export const zc006 = defineCheck({
  id: 'ZC-006',
  name: 'Unrestricted Filesystem Scope',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect filesystem scope escapes: risk profile workspace_only=false, allowed_roots covering / or $HOME, or [agents.<alias>.workspace] unrestricted_filesystem=true',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broad = buildBroadPaths(home);
    let writable = false;

    for (const p of effectiveProfiles(config.data)) {
      if (isFalse(p.profile.workspace_only)) {
        writable = true;
        evidence.push({
          file: config.filePath,
          detail: `${profileLabel(p)}: workspace_only = false — file tools may reach paths outside the agent workspace`,
        });
      }
      for (const root of asStringArray(p.profile.allowed_roots)) {
        const hit = isBroadPath(root, broad, home);
        if (hit) {
          evidence.push({
            file: config.filePath,
            detail: `${profileLabel(p)}: allowed_roots contains "${root}" — ${hit.reason}`,
          });
        }
      }
    }

    for (const a of enabledAgents(config.data)) {
      if (isTrue(asRecord(a.data.workspace)?.unrestricted_filesystem)) {
        writable = true;
        evidence.push({
          file: config.filePath,
          detail: `agents.${a.alias}.workspace.unrestricted_filesystem = true — agent can read/write anywhere the host user can`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Agent filesystem access is scoped to its workspace',
      failed: (n) => `${n} filesystem scope escape(s) configured`,
      fixable: writable,
      fixDescription:
        'Set workspace_only = true on the risk profile, unrestricted_filesystem = false on the agent workspace, and narrow allowed_roots to specific project directories',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const updates: Array<[string, unknown]> = [];
    if (config) {
      for (const p of effectiveProfiles(config.data)) {
        if (isFalse(p.profile.workspace_only)) updates.push([`${p.path}.workspace_only`, true]);
      }
      for (const a of enabledAgents(config.data)) {
        if (isTrue(asRecord(a.data.workspace)?.unrestricted_filesystem)) {
          updates.push([`agents.${a.alias}.workspace.unrestricted_filesystem`, false]);
        }
      }
    }
    return writeMainConfig(
      ctx,
      'ZC-006',
      updates,
      'Restricted filesystem scope (workspace_only=true / unrestricted_filesystem=false); review allowed_roots manually',
    );
  },
});

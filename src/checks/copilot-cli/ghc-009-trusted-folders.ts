import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';

export const ghc009 = defineCheck({
  id: 'GHC-009',
  name: 'Copilot CLI Trusted Folder Too Broad',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect ~/.copilot/config.json trustedFolders entries that grant workspace trust over /, $HOME, /tmp, or /etc',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home);

    for (const config of ctx.configs) {
      const folders = config.data.trustedFolders;
      if (!Array.isArray(folders)) continue;
      for (const path of folders) {
        if (typeof path !== 'string') continue;
        const broad = isBroadPath(path, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: path,
            detail: `Trusted folder "${path}" ${broad.reason} — Copilot CLI skips the workspace-trust prompt for anything inside it`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI trusted folders scope is reasonable',
      failed: (n) => `Found ${n} overly broad trusted folder(s)`,
      fixDescription: 'Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp',
    });
  },
});

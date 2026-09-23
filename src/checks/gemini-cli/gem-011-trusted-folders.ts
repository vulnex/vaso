import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';

export const gem011 = defineCheck({
  id: 'GEM-011',
  name: 'Gemini CLI Trusted Folder Too Broad',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect ~/.gemini/trustedFolders.json entries that grant folder trust over /, $HOME, /tmp, or /etc',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home);

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('trustedFolders.json')) continue;
      for (const [path, level] of Object.entries(config.data)) {
        if (typeof level !== 'string' || !/^trust/i.test(level)) continue;
        const broad = isBroadPath(path, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: `"${path}": "${level}"`,
            detail: `Trusted folder "${path}" ${broad.reason} — folder trust disables Gemini CLI's confirmation prompts for anything inside it`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini CLI trusted folders scope is reasonable',
      failed: (n) => `Found ${n} overly broad trusted folder(s)`,
      fixDescription: 'Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp',
    });
  },
});

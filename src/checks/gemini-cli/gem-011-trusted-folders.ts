import { dirname, join } from 'node:path';
import type { Evidence, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { stripJsonc } from '../../core/jsonc.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { geminiHome } from '../../adapters/gemini.js';

/**
 * The trust file for this install: $GEMINI_CLI_TRUSTED_FOLDERS_PATH (an
 * absolute file path, Gemini CLI trusted-folders docs) when the install is
 * the scanning user's, else trustedFolders.json in the install dir.
 */
function trustFilePath(installDir: string, fs: FSProvider): string {
  const env = fs.getEnv?.('GEMINI_CLI_TRUSTED_FOLDERS_PATH')?.trim();
  if (env && installDir === geminiHome(fs.homedir(), fs)) return env;
  return join(installDir, 'trustedFolders.json');
}

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

    // trustedFolders.json is not a settings file the adapter loads: read it
    // from the user install (Gemini CLI keeps folder trust user-level only).
    const files: ParsedConfig[] = ctx.configs.filter(c => c.filePath.endsWith('trustedFolders.json'));
    const userFile = trustFilePath(ctx.installation.installDir, ctx.fs);
    if (ctx.installation.profile !== 'project' && !files.some(f => f.filePath === userFile) && await ctx.fs.access(userFile)) {
      try {
        const raw = await ctx.fs.readFile(userFile);
        const data = JSON.parse(stripJsonc(raw));
        if (data && typeof data === 'object' && !Array.isArray(data)) files.push({ raw, format: 'json', filePath: userFile, data });
      } catch {
        // unreadable or not JSON — nothing to judge
      }
    }

    for (const config of files) {
      for (const [path, level] of Object.entries(config.data)) {
        if (typeof level !== 'string' || !/^trust/i.test(level)) continue;
        // TRUST_PARENT trusts the rule path's parent directory
        // (trustedFolders.ts: effectivePath = path.dirname(rulePath)), so
        // "~/code": "TRUST_PARENT" trusts all of $HOME.
        const effective = level.toUpperCase() === 'TRUST_PARENT' ? dirname(path) : path;
        const broad = isBroadPath(effective, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: `"${path}": "${level}"`,
            detail: `Trusted folder "${effective}"${effective !== path ? ' (parent of the rule path)' : ''} ${broad.reason} — folder trust disables Gemini CLI's confirmation prompts for anything inside it`,
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

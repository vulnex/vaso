import { dirname, join } from 'node:path';
import type { Evidence, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { stripJsonc } from '../../core/jsonc.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { geminiHome, geminiTrustedFoldersPath } from '../../adapters/gemini.js';
import { parseIfPresent } from '../../adapters/load-if-present.js';

/**
 * The trust file for this install: the scanning user's (which
 * $GEMINI_CLI_TRUSTED_FOLDERS_PATH may relocate), else trustedFolders.json in
 * the install dir.
 */
function trustFilePath(installDir: string, fs: FSProvider): string {
  return installDir === geminiHome(fs.homedir(), fs) ? geminiTrustedFoldersPath(fs) : join(installDir, 'trustedFolders.json');
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
    const broadPaths = buildBroadPaths(home, ctx.platform);

    // trustedFolders.json is not a settings file the adapter loads: read it
    // from the user install (Gemini CLI keeps folder trust user-level only).
    const files: ParsedConfig[] = ctx.configs.filter(c => c.filePath.endsWith('trustedFolders.json'));
    const userFile = trustFilePath(ctx.installation.installDir, ctx.fs);
    if (ctx.installation.profile !== 'project' && !files.some(f => f.filePath === userFile)) {
      // Present but unreadable or not a JSON object: reported as CONFIG-LOAD
      const parsed = await parseIfPresent(userFile, ctx.fs, raw => {
        const data = JSON.parse(stripJsonc(raw)) as unknown;
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Top-level value is not a JSON object');
        return { raw, data: data as Record<string, unknown> };
      });
      if (parsed) files.push({ raw: parsed.raw, format: 'json', filePath: userFile, data: parsed.data });
    }

    for (const config of files) {
      for (const [path, level] of Object.entries(config.data)) {
        if (typeof level !== 'string' || !/^trust/i.test(level)) continue;
        // TRUST_PARENT trusts the rule path's parent directory
        // (trustedFolders.ts: effectivePath = path.dirname(rulePath)), so
        // "~/code": "TRUST_PARENT" trusts all of $HOME.
        const effective = level.toUpperCase() === 'TRUST_PARENT' ? dirname(path) : path;
        // Gemini CLI compares trust paths case-insensitively on macOS
        // (normalizePath / isSubpath lowercase both sides on darwin)
        const broad = isBroadPath(effective, broadPaths, home, { ancestors: true, ignoreCase: ctx.fs.platform === 'darwin' });
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

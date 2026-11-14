import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions, readableByOthers, writableByOthers } from '../../core/permissions.js';
import { configHoldsSecret } from '../../core/secret-values.js';
import { ghc003 } from './ghc-003-plaintext-token.js';

const PROTECTED_FILES = [
  'config.json',
  'settings.json',
  'lsp-config.json',
  'providers.json',
  'command-history-state.json',
  'session-store.db',
];
/** Always private whatever they hold: the user's own history and session data. */
const PRIVATE_FILES = new Set(['command-history-state.json', 'session-store.db']);
/**
 * Directories of private files (config-dir reference): session transcripts,
 * command history (a directory since it replaced command-history-state.json),
 * and the MCP OAuth token / secret fallback stores used when no keychain is
 * available.
 */
const PRIVATE_DIRS: Array<{ dir: string; what: string }> = [
  { dir: 'session-state', what: 'Session transcript' },
  { dir: 'command-history-state', what: 'Command history file' },
  { dir: 'mcp-oauth-config', what: 'MCP OAuth token/registration file' },
  { dir: 'mcp-secrets', what: 'MCP secret fallback file' },
];
const PROTECTED_DIRS = ['.', ...PRIVATE_DIRS.map(d => d.dir)];
/** Enough to judge a session directory without walking a long history. */
const MAX_SESSION_FILES = 200;

export const ghc001 = defineCheck({
  id: 'GHC-001',
  name: 'Copilot CLI Directory Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify ~/.copilot/, its session/history/MCP-secret stores, session-store.db and credential files (incl. providers.json) are not group/world readable',
  supportedAgents: ['copilot-cli'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    // A project install is the repo checkout, not ~/.copilot
    if (ctx.installation.profile === 'project') return h.passed('Project configuration — ~/.copilot permissions are checked on the user install');
    const evidence: Evidence[] = [];

    // Directories: a readable one exposes file names only — what matters is
    // whether others can replace files in it, and the modes of the files
    for (const subdir of PROTECTED_DIRS) {
      const path = subdir === '.' ? ctx.installation.installDir : join(ctx.installation.installDir, subdir);
      if (!(await ctx.fs.access(path))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, path);
        if (perms !== 'unsupported' && writableByOthers(perms)) {
          evidence.push({
            file: path,
            snippet: `mode 0${perms.octal}`,
            detail: `${subdir === '.' ? '~/.copilot/' : `${subdir}/`} is writable by group/other — its auth and session files can be replaced`,
          });
        }
      } catch {}
    }

    // Private stores: each file's own mode
    for (const { dir, what } of PRIVATE_DIRS) {
      const storeDir = join(ctx.installation.installDir, dir);
      try {
        const entries = (await ctx.fs.readdirEntries(storeDir)).filter(e => e.isFile).slice(0, MAX_SESSION_FILES);
        for (const e of entries) {
          const filePath = join(storeDir, e.name);
          const perms = await queryPermissions(ctx.fs, filePath).catch(() => 'unsupported' as const);
          if (perms !== 'unsupported' && readableByOthers(perms)) {
            evidence.push({ file: filePath, snippet: `mode 0${perms.octal}`, detail: `${what} readable by group/other` });
          }
        }
      } catch {
        // store absent
      }
    }

    for (const filename of PROTECTED_FILES) {
      const filePath = join(ctx.installation.installDir, filename);
      if (!(await ctx.fs.access(filePath))) continue;
      // Config files leak only what they hold: a token or other secret.
      // History and session data are the user's own record and always private.
      if (!PRIVATE_FILES.has(filename)) {
        const config = ctx.configs.find(c => c.filePath === filePath);
        if (config && !configHoldsSecret(config.data) && (await ghc003.run({ ...ctx, configs: [config] })).passed) continue;
      }
      try {
        const perms = await queryPermissions(ctx.fs, filePath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.octal}`,
            detail: `${filename} is readable or writable by group/other`,
          });
        }
      } catch {}
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI directory and config files are owner-only',
      failed: (n) => `Found ${n} Copilot CLI path(s) with overly permissive mode`,
      fixDescription: 'Run `chmod -R go-rwx ~/.copilot` to restrict access to the owner',
    });
  },
});

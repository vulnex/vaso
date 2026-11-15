import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions, readableByOthers, writableByOthers } from '../../core/permissions.js';
import { configHoldsSecret } from '../../core/secret-values.js';
import { ghc003 } from './ghc-003-plaintext-token.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

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
/** Open store files listed per store; the rest are counted in one line (all are judged, and the fix changes all). */
const MAX_LISTED_PER_STORE = 200;
/** Files judged per store at most — a bound on a pathological history, far above a real one. */
const MAX_JUDGED_PER_STORE = 20_000;

interface Findings {
  evidence: Evidence[];
  /** Store files a remote scan couldn't judge (the probe didn't collect their metadata). */
  unverified: string[];
  /** Stores with more files than MAX_JUDGED_PER_STORE: only that many were judged. */
  truncated: string[];
}

/**
 * A store's files: its entries and the entries of its subdirectories, one
 * level deep (session-state/<session id>/events.jsonl). Symlinks count — a
 * store file's data is wherever it points, and its mode is the target's.
 */
async function storeFiles(ctx: ScanContext, storeDir: string): Promise<{ files: string[]; truncated: boolean }> {
  const files: string[] = [];
  const add = (path: string) => { if (files.length < MAX_JUDGED_PER_STORE + 1) files.push(path); };
  for (const e of await ctx.fs.readdirEntries(storeDir)) {
    const path = join(storeDir, e.name);
    if (e.isFile || e.isSymbolicLink) {
      add(path);
    } else if (e.isDirectory) {
      try {
        for (const sub of await ctx.fs.readdirEntries(path)) {
          if (sub.isFile || sub.isSymbolicLink) add(join(path, sub.name));
        }
      } catch {
        // an unreadable session folder: nobody else can list it either
      }
    }
    if (files.length > MAX_JUDGED_PER_STORE) break;
  }
  return { files: files.slice(0, MAX_JUDGED_PER_STORE), truncated: files.length > MAX_JUDGED_PER_STORE };
}

/** The paths readable or writable beyond the owner; `maxListed` caps the files listed per private store. */
async function findings(ctx: ScanContext, maxListed: number): Promise<Findings> {
  const evidence: Evidence[] = [];
  const unverified: string[] = [];
  const truncated: string[] = [];

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

  // Private stores: each file's own mode (a symlink's target's)
  for (const { dir, what } of PRIVATE_DIRS) {
    const storeDir = join(ctx.installation.installDir, dir);
    let listing: Awaited<ReturnType<typeof storeFiles>>;
    try {
      listing = await storeFiles(ctx, storeDir);
    } catch {
      continue; // store absent
    }
    if (listing.truncated) truncated.push(storeDir);
    const open: Evidence[] = [];
    let missing = 0;
    for (const filePath of listing.files) {
      let perms: Awaited<ReturnType<typeof queryPermissions>>;
      try {
        perms = await queryPermissions(ctx.fs, filePath);
      } catch {
        // gone, or a dangling link: nothing to read — unless the probe just didn't collect it
        if (ctx.fs.kind === 'snapshot') missing++;
        continue;
      }
      if (perms !== 'unsupported' && readableByOthers(perms)) {
        open.push({ file: filePath, snippet: `mode 0${perms.octal}`, detail: `${what} readable by group/other` });
      }
    }
    if (missing > 0) unverified.push(`${missing} file(s) in ${dir}/`);
    evidence.push(...open.slice(0, maxListed));
    if (open.length > maxListed) {
      evidence.push({
        file: storeDir,
        snippet: `+${open.length - maxListed} more file(s)`,
        detail: `${open.length - maxListed} more ${what.toLowerCase()}(s) in ${dir}/ readable by group/other (not listed)`,
      });
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

  return { evidence, unverified, truncated };
}

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
    const { evidence, unverified, truncated } = await findings(ctx, MAX_LISTED_PER_STORE);
    await markUnreachable(ctx.fs, evidence);
    const notes = [
      ...(unverified.length > 0 ? [`modes of ${unverified.join(', ')} not verified — the probe didn't collect them (checked on local scans)`] : []),
      ...(truncated.length > 0 ? [`only the first ${MAX_JUDGED_PER_STORE} files of ${truncated.join(', ')} checked`] : []),
    ];
    return h.fromEvidence(evidence, {
      passed: `Copilot CLI directory and config files are owner-only${notes.length > 0 ? `; ${notes.join('; ')}` : ''}`,
      failed: (n) => `Found ${n} Copilot CLI path(s) with overly permissive mode`,
      fixable: true,
      fixDescription: 'Remove group/other access (chmod go-rwx) from the listed ~/.copilot paths — `chmod -R go-rwx ~/.copilot` covers everything',
    });
  },

  async fix(ctx) {
    if (ctx.installation.profile === 'project') return { checkId: 'GHC-001', applied: false, alreadyDone: true, message: 'Project configuration — nothing to change' };
    return restrictFilesToOwner('GHC-001', (await findings(ctx, Infinity)).evidence.flatMap(e => (e.file ? [e.file] : [])));
  },
});

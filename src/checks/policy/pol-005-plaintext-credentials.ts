import { join } from 'node:path';
import type { DirentInfo, FSProvider } from '../../core/fs-provider.js';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isExcludedPath } from '../../core/utils.js';
import { API_KEY_PATTERNS, isPlaceholderSecret } from '../../core/patterns.js';

const CREDENTIAL_FILES = new Set([
  '.npmrc',
  '.netrc',
  '.pgpass',
  '.my.cnf',
  '.s3cfg',
  'credentials',
  'secrets.txt',
  '.boto',
  '.pypirc',
  '.authinfo',
]);

/**
 * How far below the install directory credential files are looked for. The
 * remote probe collects these names at the same depths
 * (`credentialFileGlobs` in manifest-builder.ts), so local and remote scans
 * agree; an unbounded walk also crawled whole session and cache trees.
 */
export const CREDENTIAL_SEARCH_DEPTH = 2;
export const CREDENTIAL_FILE_NAMES: readonly string[] = [...CREDENTIAL_FILES];

async function credentialCandidates(fs: FSProvider, root: string): Promise<DirentInfo[]> {
  const out: DirentInfo[] = [];
  let level = [root];
  for (let depth = 0; depth <= CREDENTIAL_SEARCH_DEPTH && level.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      let entries: DirentInfo[];
      try {
        entries = await fs.readdirEntries(dir);
      } catch (err) {
        if (dir === root) throw err;
        continue;
      }
      for (const e of entries) {
        const parentPath = e.parentPath ?? dir;
        if (e.isFile && CREDENTIAL_FILES.has(e.name)) out.push({ ...e, parentPath });
        else if (e.isDirectory && !isExcludedPath(root, join(parentPath, e.name))) next.push(join(parentPath, e.name));
      }
    }
    level = next;
  }
  return out;
}

export const pol005 = defineCheck({
  id: 'POL-005',
  name: 'Plaintext Credential Files',
  category: 'policy',
  severity: 'critical',
  description: 'Scan common credential files for plaintext API keys and secrets',

  async run(ctx, h) {
    const installDir = ctx.installation.installDir;

    let entries: { name: string; isFile: boolean; isDirectory: boolean; parentPath?: string }[];
    try {
      entries = await credentialCandidates(ctx.fs, installDir);
    } catch {
      return h.passed('Install directory not accessible');
    }

    const evidence: Evidence[] = [];
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (!CREDENTIAL_FILES.has(entry.name)) continue;
      // Vendored packages ship sample .env/credential files, not the user's
      if (isExcludedPath(installDir, entry.parentPath)) continue;

      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(installDir, entry.name);
      try {
        const content = await ctx.fs.readFile(fullPath);
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const { pattern, name } of API_KEY_PATTERNS) {
            const m = pattern.exec(line);
            if (m && !isPlaceholderSecret(m[0])) {
              evidence.push({
                file: fullPath,
                line: i + 1,
                snippet: line.trim().slice(0, 80).replace(/[a-zA-Z0-9]{8,}/g, '****'),
                detail: `${name} found in plaintext credential file`,
              });
              break; // One finding per line
            }
          }
        }
      } catch (err) {
        // A remote snapshot records credential files without their content
        // (privacy): say the file is there, unverified, rather than nothing
        if (ctx.fs.kind === 'snapshot' && err instanceof Error && err.message.includes('content not collected')) {
          evidence.push({
            file: fullPath,
            detail: 'Credential file present; its content is not collected by remote scans — scan the host locally to check it for plaintext keys',
            mitigated: true,
          });
        }
      }
    }

    // Only files a remote scan couldn't read: nothing was found, and saying
    // "found N plaintext credentials" would claim what was never checked
    if (evidence.length > 0 && evidence.every(e => e.mitigated)) {
      return h.passed(`${evidence.length} credential file(s) present; their content is not collected by remote scans — scan the host locally to check them for plaintext keys`);
    }
    return h.fromEvidence(evidence, {
      passed: 'No plaintext credentials found in common credential files',
      failed: (n) => `Found ${n} plaintext credential(s) in credential files`,
    });
  },
});

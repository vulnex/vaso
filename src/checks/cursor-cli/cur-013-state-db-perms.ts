import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';

// The Cursor IDE stores its session credentials in plaintext SQLite:
// state.vscdb ItemTable keys cursorAuth/accessToken (JWT) and
// cursorAuth/refreshToken. Chat history lives in the same DB. A single
// sqlite3 query away for anything that can read the file.
function userDataDirs(home: string, platform: string, appData?: string): string[] {
  if (platform === 'darwin') return [join(home, 'Library', 'Application Support', 'Cursor')];
  if (platform === 'linux') return [join(home, '.config', 'Cursor')];
  if (platform === 'win32' && appData) return [join(appData, 'Cursor')];
  return [];
}

export const cur013 = defineCheck({
  id: 'CUR-013',
  name: 'Cursor Session Database Readable by Others',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Check that the Cursor IDE state.vscdb (plaintext session JWTs + chat history) is not readable by other local users',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const home = ctx.fs.homedir();
    const dirs = userDataDirs(home, ctx.platform, ctx.fs.getEnv?.('APPDATA'));
    const evidence: Evidence[] = [];

    for (const dir of dirs) {
      const dbPath = join(dir, 'User', 'globalStorage', 'state.vscdb');
      let facts;
      try {
        facts = await queryPermissions(ctx.fs, dbPath);
      } catch {
        continue; // absent — IDE not installed / never launched
      }
      if (facts === 'unsupported') continue;
      if (readableByOthers(facts)) {
        evidence.push({
          file: dbPath,
          snippet: facts.octal,
          detail: 'Readable by other local users — contains cursorAuth/accessToken + refreshToken in plaintext (ItemTable) and full chat history',
        });
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Cursor session database is not readable by other users',
      failed: (n) => `Found ${n} Cursor state.vscdb file(s) readable by other users`,
      fixDescription: 'chmod 600 the flagged state.vscdb (and its -wal/-shm siblings); rotate the Cursor session if exposure is suspected',
    });
  },
});

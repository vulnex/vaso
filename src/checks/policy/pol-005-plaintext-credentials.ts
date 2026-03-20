import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

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

export const pol005: CheckModule = {
  id: 'POL-005',
  name: 'Plaintext Credential Files',
  category: 'policy',
  severity: 'critical',
  description: 'Scan common credential files for plaintext API keys and secrets',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const installDir = ctx.installation.installDir;

    let entries: { name: string; isFile: boolean; isDirectory: boolean; parentPath?: string }[];
    try {
      entries = await ctx.fs.readdirEntries(installDir, { recursive: true });
    } catch {
      return {
        id: 'POL-005',
        name: 'Plaintext Credential Files',
        category: 'policy',
        severity: 'critical',
        passed: true,
        message: 'Install directory not accessible',
      };
    }

    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (!CREDENTIAL_FILES.has(entry.name)) continue;

      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(installDir, entry.name);
      try {
        const content = await ctx.fs.readFile(fullPath);
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const { pattern, name } of API_KEY_PATTERNS) {
            if (pattern.test(line)) {
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
      } catch {
        // File may not be readable
      }
    }

    return {
      id: 'POL-005',
      name: 'Plaintext Credential Files',
      category: 'policy',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No plaintext credentials found in common credential files'
        : `Found ${evidence.length} plaintext credential(s) in credential files`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { Dirent } from 'node:fs';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const CREDENTIAL_FILE_PATTERNS = [
  /session/i,
  /token/i,
  /credential/i,
  /auth/i,
  /\.secret_key$/i,
];

export const pol003: CheckModule = {
  id: 'POL-003',
  name: 'Session Credential Permissions',
  category: 'policy',
  severity: 'warning',
  description: 'Check that session/token/auth files have restrictive permissions (0600)',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const installDir = ctx.installation.installDir;

    let entries: Dirent<string>[];
    try {
      entries = await readdir(installDir, { withFileTypes: true, recursive: true, encoding: 'utf-8' });
    } catch {
      return {
        id: 'POL-003',
        name: 'Session Credential Permissions',
        category: 'policy',
        severity: 'warning',
        passed: true,
        message: 'Install directory not accessible',
      };
    }

    for (const entry of entries) {
      if (!entry.isFile()) continue;

      const matches = CREDENTIAL_FILE_PATTERNS.some(p => p.test(entry.name));
      if (!matches) continue;

      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(installDir, entry.name);
      try {
        const stats = await stat(fullPath);
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not be accessible
      }
    }

    return {
      id: 'POL-003',
      name: 'Session Credential Permissions',
      category: 'policy',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All session/credential files have restrictive permissions'
        : `${evidence.length} session/credential file(s) have overly permissive permissions`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const cdx003: CheckModule = {
  id: 'CDX-003',
  name: 'Codex Auth File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that ~/.codex/auth.json is not readable by other users',
  supportedAgents: ['codex'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const authPath = join(ctx.installation.installDir, 'auth.json');

    if (!(await ctx.fs.access(authPath))) {
      return passed('auth.json not present');
    }

    try {
      const stat = await ctx.fs.stat(authPath);
      const perms = stat.mode & 0o777;
      // Allow 0600/0400; flag if group or other has any access
      if ((perms & 0o077) !== 0) {
        evidence.push({
          file: authPath,
          snippet: `mode 0${perms.toString(8)}`,
          detail: 'auth.json is readable or writable by group/other — credentials may be exposed',
        });
      }
    } catch {
      // Can't stat — skip silently
    }

    return {
      id: 'CDX-003',
      name: 'Codex Auth File Permissions',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Codex auth.json has restricted permissions'
        : 'Codex auth.json is over-permissive — restrict it to 0600',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Run `chmod 600 ~/.codex/auth.json` to restrict access to the owner',
    };
  },
};

function passed(msg: string): CheckResult {
  return {
    id: 'CDX-003',
    name: 'Codex Auth File Permissions',
    category: 'coding-agent',
    severity: 'warning',
    passed: true,
    message: msg,
    evidence: undefined,
  } as CheckResult;
}

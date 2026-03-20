import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

// Known malicious VS Code extension IDs
const MALICIOUS_EXTENSIONS = new Set([
  'openclaw-tools.unofficial-helper',
  'claw-extensions.free-copilot',
  'ai-agent-plugins.claw-boost',
  'clawhavoc.malicious-skill-loader',
]);

export const run003: CheckModule = {
  id: 'RUN-003',
  name: 'VS Code Extension Trojans',
  category: 'runtime',
  severity: 'critical',
  description: 'Check for known malicious VS Code extension IDs',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();

    const extensionDirs = [
      join(home, '.vscode', 'extensions'),
      join(home, '.vscode-insiders', 'extensions'),
      join(home, '.cursor', 'extensions'),
    ];

    for (const dir of extensionDirs) {
      try {
        const entries = await ctx.fs.readdir(dir);

        for (const entry of entries) {
          const lower = entry.toLowerCase();
          for (const malId of MALICIOUS_EXTENSIONS) {
            if (lower.startsWith(malId.split('.')[0]) && lower.includes(malId.split('.')[1])) {
              evidence.push({
                file: join(dir, entry),
                detail: `Known malicious extension: ${malId}`,
              });
            }
          }
        }
      } catch {}
    }

    return {
      id: 'RUN-003',
      name: 'VS Code Extension Trojans',
      category: 'runtime',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No known malicious VS Code extensions found'
        : `Found ${evidence.length} malicious VS Code extension(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

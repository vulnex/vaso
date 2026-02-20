import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const SUSPICIOUS_KEYWORDS = [
  'openclaw', 'nanoclaw', 'picoclaw', 'claw', 'agent',
  'skill', 'moltbot', 'clawdbot',
];

export const run001: CheckModule = {
  id: 'RUN-001',
  name: 'Unauthorized LaunchAgents',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for unauthorized LaunchAgents (macOS) or systemd services (Linux) referencing agents',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    if (ctx.platform === 'darwin') {
      const launchDirs = [
        join(homedir(), 'Library', 'LaunchAgents'),
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons',
      ];

      for (const dir of launchDirs) {
        try {
          const entries = await readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                const filePath = join(dir, entry);
                let detail = `LaunchAgent references "${keyword}"`;
                try {
                  const content = await readFile(filePath, 'utf-8');
                  if (content.includes('ProgramArguments')) {
                    detail += ` — has ProgramArguments`;
                  }
                } catch {}
                evidence.push({ file: filePath, detail });
                break;
              }
            }
          }
        } catch {}
      }
    }

    if (ctx.platform === 'linux') {
      const systemdDirs = [
        join(homedir(), '.config', 'systemd', 'user'),
        '/etc/systemd/system',
      ];

      for (const dir of systemdDirs) {
        try {
          const entries = await readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                evidence.push({
                  file: join(dir, entry),
                  detail: `Systemd service references "${keyword}"`,
                });
                break;
              }
            }
          }
        } catch {}
      }
    }

    return {
      id: 'RUN-001',
      name: 'Unauthorized LaunchAgents',
      category: 'runtime',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No suspicious persistence mechanisms found'
        : `Found ${evidence.length} suspicious persistence mechanism(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

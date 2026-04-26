import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

const SUSPICIOUS_KEYWORDS = [
  'claw',          // catches openclaw, nanoclaw, picoclaw, ironclaw, zeroclaw, nemoclaw, clawdbot
  'nanobot',
  'moltbot',
  'hermes-agent',  // specific enough to avoid Facebook Hermes / unrelated tooling
];

export const run001 = defineCheck({
  id: 'RUN-001',
  name: 'Unauthorized LaunchAgents',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for unauthorized LaunchAgents (macOS) or systemd services (Linux) referencing agents',
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    if (ctx.platform === 'darwin') {
      const home = ctx.fs.homedir();
      const launchDirs = [
        join(home, 'Library', 'LaunchAgents'),
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons',
      ];

      for (const dir of launchDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                const filePath = join(dir, entry);
                let detail = `LaunchAgent references "${keyword}"`;
                try {
                  const content = await ctx.fs.readFile(filePath);
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
      const home = ctx.fs.homedir();
      const systemdDirs = [
        join(home, '.config', 'systemd', 'user'),
        '/etc/systemd/system',
      ];

      for (const dir of systemdDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
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

    return h.fromEvidence(evidence, {
      passed: 'No suspicious persistence mechanisms found',
      failed: (n) => `Found ${n} suspicious persistence mechanism(s)`,
    });
  },
});

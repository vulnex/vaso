import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

/**
 * Malicious editor extensions, each from a published report. Installed
 * extension folders are named `<publisher>.<name>-<version>[-<platform>]`;
 * `versions` limits an entry to trojanized releases of a legitimate extension.
 */
const MALICIOUS_EXTENSIONS: ReadonlyArray<{ id: string; versions?: string[]; source: string }> = [
  // "ClawdBot Agent": a fake Clawdbot (OpenClaw) assistant on the VS Code
  // Marketplace that installs ScreenConnect (Aikido, Jan 2026; removed by Microsoft)
  { id: 'clawdbot.clawdbot-agent', source: 'fake ClawdBot agent that installs a ScreenConnect remote-access client (Aikido, Jan 2026)' },
  // Trojanized Claude Code releases on Cursor's extension marketplace — their
  // C2 address and payload hashes are in the IOC database (StepSecurity; OX Security, 2026-10-30)
  { id: 'anthropic.claude-code', versions: ['2.1.312', '2.1.313'], source: 'trojanized release that plants an SSH key and opens a reverse tunnel (StepSecurity / OX Security, Oct 2026)' },
];

/** `<publisher>.<name>` and version of an installed extension folder. */
export function parseExtensionDir(entry: string): { id: string; version: string } | undefined {
  const m = /^([^.\s]+\.\S+?)-(\d+\.\d+\.\d+)(?:-[a-z0-9_-]+)?$/i.exec(entry);
  return m ? { id: m[1].toLowerCase(), version: m[2] } : undefined;
}

export const run003 = defineCheck({
  id: 'RUN-003',
  name: 'VS Code Extension Trojans',
  category: 'runtime',
  severity: 'critical',
  description: 'Check for known malicious VS Code / Cursor extensions',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
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
          const ext = parseExtensionDir(entry);
          if (!ext) continue;
          const hit = MALICIOUS_EXTENSIONS.find(m => m.id === ext.id && (!m.versions || m.versions.includes(ext.version)));
          if (hit) {
            evidence.push({
              file: join(dir, entry),
              detail: `Known malicious extension ${ext.id} ${ext.version}: ${hit.source}`,
            });
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious VS Code extensions found',
      failed: (n) => `Found ${n} malicious VS Code extension(s)`,
    });
  },
});

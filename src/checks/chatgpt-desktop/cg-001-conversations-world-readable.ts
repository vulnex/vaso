import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SCAN_DIR_PREFIXES = [
  'conversations-v3-',
  'drafts-v2-',
  'gizmos-',
  'system-hints-',
  'health-system-hints-',
  'pinned-items-user-',
  'order-orders-',
];
const MAX_SAMPLES = 3;

export const cg001 = defineCheck({
  id: 'CG-001',
  name: 'Workspace Data Files World-Readable',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when ChatGPT workspace data files (.data) carry mode 644+ and leak filenames/sizes to other local users',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const supportDir = ctx.installation.installDir;

    let topEntries;
    try {
      topEntries = await ctx.fs.readdirEntries(supportDir);
    } catch {
      return h.passed('ChatGPT support directory not readable');
    }

    for (const entry of topEntries) {
      if (!entry.isDirectory) continue;
      if (!SCAN_DIR_PREFIXES.some(p => entry.name.startsWith(p))) continue;
      const subDir = join(supportDir, entry.name);

      let files;
      try {
        files = await ctx.fs.readdirEntries(subDir);
      } catch {
        continue;
      }

      let sampled = 0;
      for (const f of files) {
        if (!f.isFile) continue;
        if (sampled >= MAX_SAMPLES) break;
        const fullPath = join(subDir, f.name);
        try {
          const stat = await ctx.fs.stat(fullPath);
          // Other-readable bit set => any local user (or backup target) can list/read
          if ((stat.mode & 0o004) !== 0) {
            evidence.push({
              file: subDir,
              snippet: `${f.name} (mode ${(stat.mode & 0o777).toString(8)})`,
              detail: 'Workspace artifact is other-readable — even when encrypted, filenames/sizes/count leak to local processes and backups',
            });
            break;
          }
        } catch {}
        sampled++;
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'ChatGPT workspace data files are not other-readable',
      failed: (n) => `Found ${n} workspace director(ies) with other-readable artifacts`,
      fixDescription: 'chmod -R o-r ~/Library/Application\\ Support/com.openai.chat — note ChatGPT may rewrite these on next launch',
    });
  },
});

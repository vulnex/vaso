import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, expandHome, isBroadPath } from '../../analyzers/broad-paths.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';
import { canonicalSystemPath, markUntrustedProject, settingsConfigs } from './shared.js';

export const aba013 = defineCheck({
  id: 'ABA-013',
  name: 'Abacus.AI Sensitive Additional Directories',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI additionalDirectories granting read/edit access to the whole disk, the home directory, shared temp dirs or credential locations (~/.ssh, ~/.aws, shell startup files, /etc)',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home);

    for (const config of settingsConfigs(ctx.configs)) {
      const dirs = config.data.additionalDirectories;
      if (!Array.isArray(dirs)) continue;
      for (const dir of dirs) {
        if (typeof dir !== 'string' || !dir.trim()) continue;
        const snippet = `additionalDirectories: "${dir}"`;
        const path = canonicalSystemPath(dir.trim());
        const broad = isBroadPath(path, broadPaths, home);
        const sinks = classifySensitivePath(expandHome(path, home));
        if (broad && broad.path.endsWith('tmp')) {
          warning.push({ file: config.filePath, snippet, detail: `Agent may read and edit a directory ${broad.reason}` });
        } else if (broad) {
          critical.push({ file: config.filePath, snippet, detail: `Agent may read and edit everything in "${dir.trim()}", which ${broad.reason}` });
        } else if (sinks.length > 0) {
          critical.push({ file: config.filePath, snippet, detail: `Agent may read and edit ${sinks.join(', ')}` });
        }
      }
    }

    await markUntrustedProject(ctx, critical);
    await markUntrustedProject(ctx, warning);
    const liveCritical = critical.some(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Abacus.AI additionalDirectories are scoped',
      failed: (n) => `Found ${n} sensitive Abacus.AI additional director(ies)`,
      severity: liveCritical ? undefined : 'warning',
      fixDescription: 'Limit additionalDirectories to specific project folders; never add /, the home directory or credential locations',
    });
  },
});

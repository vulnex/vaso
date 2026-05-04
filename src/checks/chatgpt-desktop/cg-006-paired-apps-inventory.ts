import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PAIRING_DIR = 'app_pairing_extensions';

export const cg006 = defineCheck({
  id: 'CG-006',
  name: 'Paired Apps Inventory',
  category: 'coding-agent',
  severity: 'info',
  description: 'Inventory connectors/Apps paired with ChatGPT — when populated, this is the on-disk crumb of the connector trust set',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const dir = join(ctx.installation.installDir, PAIRING_DIR);
    if (!(await ctx.fs.access(dir))) {
      return h.passed('No app_pairing_extensions directory present');
    }

    let entries;
    try {
      entries = await ctx.fs.readdirEntries(dir);
    } catch {
      return h.passed('app_pairing_extensions directory not readable');
    }

    const items = entries.filter(e => e.isFile || e.isDirectory).map(e => e.name);
    if (items.length === 0) {
      return h.passed('No connectors / Apps paired with ChatGPT');
    }

    const evidence: Evidence[] = items.map(name => ({
      file: join(dir, name),
      snippet: name,
      detail: 'Paired connector — review whether this app should retain access to ChatGPT prompts/results',
    }));

    return h.result({
      passed: true,
      message: `${items.length} ChatGPT connector(s) / paired app(s) on disk — review the trust set`,
      evidence,
    });
  },
});

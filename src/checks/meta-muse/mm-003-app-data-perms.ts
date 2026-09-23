import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, readableByOthers } from '../../core/permissions.js';

export const mm003 = defineCheck({
  id: 'MM-003',
  name: 'Muse Application Data Readable by Others',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Check that Muse’s Application Support data (analytics identity, and conversation data once configured) is not readable by other local users',
  supportedAgents: ['meta-muse'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const supportDir = ctx.installation.installDir;
    if (!(await ctx.fs.access(supportDir))) {
      return h.passed('Muse application data directory not present');
    }

    const evidence: Evidence[] = [];
    let entries: string[] = [];
    try {
      entries = await ctx.fs.readdir(supportDir);
    } catch {
      return h.passed('Muse application data directory not readable');
    }

    for (const name of [/* the dir itself first */ '', ...entries]) {
      const target = name === '' ? supportDir : join(supportDir, name);
      let facts;
      try {
        facts = await queryPermissions(ctx.fs, target);
      } catch {
        continue;
      }
      if (facts === 'unsupported') continue;
      if (readableByOthers(facts)) {
        evidence.push({
          file: target,
          snippet: facts.octal,
          detail: 'Readable by other local users — contains analytics identity today and conversation data once the agent is configured',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Muse application data is not readable by other users',
      failed: (n) => `Found ${n} Muse data path(s) readable by other users`,
      fixDescription: 'chmod go-rwx the flagged paths under ~/Library/Application Support/com.meta.endo',
    });
  },
});

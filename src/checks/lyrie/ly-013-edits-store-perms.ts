import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable } from '../../core/permissions.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';
import { worldAccessEvidence } from './state-perms.js';

export const ly013 = defineCheck({
  id: 'LY-013',
  name: 'Edit Ledger Accessible to Other Users',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/edits.json is not world-readable or world-writable. EditEngine writes it 0600; pending plans carry full file contents, and a writable ledger lets another local user swap a plan\'s content between operator review and apply.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const path = join(lyrieStateDir(ctx.fs), 'edits.json');
    const evidence: Evidence[] = [];
    const e = await worldAccessEvidence(ctx.fs, path, 'edits.json (pending edit plans with file contents)');
    if (e) evidence.push(e);

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'edits.json is absent or not accessible to other users',
      failed: () => 'edits.json is accessible to other local users',
      fixDescription: 'Run `chmod 600 ~/.lyrie/edits.json`',
    });
  },
});

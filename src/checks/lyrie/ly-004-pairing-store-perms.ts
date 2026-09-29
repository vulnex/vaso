import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable } from '../../core/permissions.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';
import { worldAccessEvidence } from './state-perms.js';

export const ly004 = defineCheck({
  id: 'LY-004',
  name: 'DM Pairing Store Accessible to Other Users',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/pairing.json is not world-readable or world-writable. The gateway writes it 0600; a widened mode lets other local users read pending pairing codes and approve themselves (approved senders bypass the pairing gate).',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const path = join(lyrieStateDir(ctx.fs), 'pairing.json');
    const evidence: Evidence[] = [];
    const e = await worldAccessEvidence(ctx.fs, path, 'pairing.json (pending codes + approved senders)');
    if (e) evidence.push(e);

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'pairing.json is absent or not accessible to other users',
      failed: () => 'pairing.json is accessible to other local users',
      fixDescription: 'Run `chmod 600 ~/.lyrie/pairing.json`',
    });
  },
});

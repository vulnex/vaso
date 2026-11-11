import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { isProjectInstall } from './shared.js';
import { readTextIfPresent } from '../../adapters/load-if-present.js';

export const aba012 = defineCheck({
  id: 'ABA-012',
  name: 'Abacus.AI AGENTS.md Secret Leak',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Scan the AGENTS.md files Abacus.AI sends on the first turn of every conversation (<workspace>/AGENTS.md, <workspace>/.abacusai/AGENTS.md) for plaintext secrets and high-entropy strings',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const installDir = ctx.installation.installDir;
    const files = isProjectInstall(ctx)
      ? [join(dirname(installDir), 'AGENTS.md'), join(installDir, 'AGENTS.md')]
      : [join(installDir, 'AGENTS.md')];

    const evidence: Evidence[] = [];
    let scanned = 0;
    for (const file of files) {
      // Present but unreadable: reported as CONFIG-LOAD
      const content = await readTextIfPresent(file, ctx.fs);
      if (content === undefined) continue;
      scanned++;
      // the same key formats, keyed values and entropy scan as every other memory file
      for (const e of scanMemorySecrets(file, content, 'AGENTS.md')) evidence.push(e);
    }

    if (scanned === 0) return h.passed('No AGENTS.md files for this Abacus.AI installation');
    return h.fromEvidence(evidence, {
      passed: `No secrets detected in ${scanned} AGENTS.md file(s)`,
      failed: (n) => `Found ${n} potential secret(s) in AGENTS.md`,
      fixDescription: 'Remove the secret from AGENTS.md and rotate it — the file is sent to the model with every new conversation (disable with autoLoadAgentsMd: false)',
    });
  },
});

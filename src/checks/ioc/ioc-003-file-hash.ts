import { createHash } from 'node:crypto';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { skillFilesOf, skillsDirsOf } from '../skills/skill-files.js';
import { readCappedBytes } from '../../core/file-limits.js';

export const ioc003 = defineCheck({
  id: 'IOC-003',
  name: 'File Hash Match',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and compare against known malicious hashes',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const hashSet = new Set(db.fileHashes);
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        // Raw bytes: a UTF-8 decode would replace the invalid sequences of a
        // compiled binary and hash something else.
        const content = await readCappedBytes(ctx.fs, file);
        // Empty files carry no payload and share one universal hash
        if (content.byteLength === 0) continue;
        const hash = createHash('sha256').update(content).digest('hex');

        if (hashSet.has(hash)) {
          evidence.push({
            file,
            detail: `SHA-256 hash matches known malicious file: ${hash}`,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious file hashes found',
      failed: (n) => `Found ${n} file(s) matching known malicious hashes`,
    });
  },
});

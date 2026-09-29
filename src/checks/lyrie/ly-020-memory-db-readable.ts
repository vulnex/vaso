import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable } from '../../core/permissions.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';
import { envString, isConfigured, lyrieEnvConfigs } from './env.js';
import { worldAccessEvidence } from './state-perms.js';

/**
 * MemoryCore stores conversation memory in ~/.lyrie/memory/lyrie-memory.db
 * (+ archive/). Rows are encrypted at rest only when LYRIE_MEMORY_KEY is set;
 * the directory is created with the default umask.
 */
export const ly020 = defineCheck({
  id: 'LY-020',
  name: 'Conversation Memory Readable by Other Users',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect a world-readable ~/.lyrie/memory/lyrie-memory.db (or archive) while LYRIE_MEMORY_KEY is unset — Lyrie then stores conversation memory in plaintext, and any local user can read everything said to the agent over every channel.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const encrypted = lyrieEnvConfigs(ctx.configs)
      .some(c => isConfigured(envString(c, 'LYRIE_MEMORY_KEY')));
    if (encrypted) return h.passed('Memory rows are encrypted at rest (LYRIE_MEMORY_KEY set)');

    const memoryDir = join(lyrieStateDir(ctx.fs), 'memory');
    if (!(await ctx.fs.access(memoryDir))) return h.passed('No Lyrie memory store present');

    const candidates = [join(memoryDir, 'lyrie-memory.db')];
    try {
      for (const name of await ctx.fs.readdir(join(memoryDir, 'archive'))) {
        candidates.push(join(memoryDir, 'archive', name));
      }
    } catch {
      // no archive
    }

    const evidence: Evidence[] = [];
    for (const path of candidates) {
      const e = await worldAccessEvidence(ctx.fs, path, 'Plaintext conversation memory');
      if (e) evidence.push(e);
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Conversation memory is not readable by other users',
      failed: n => `${n} plaintext memory database file(s) readable by other users`,
      fixDescription: 'Run `chmod 700 ~/.lyrie ~/.lyrie/memory && chmod 600 ~/.lyrie/memory/*.db`, and set LYRIE_MEMORY_KEY (base64 32-byte key) in the .env to encrypt memory at rest',
    });
  },
});

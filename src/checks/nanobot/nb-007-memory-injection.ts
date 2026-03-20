import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { join } from 'node:path';

export const nb007: CheckModule = {
  id: 'NB-007',
  name: 'MEMORY.md Prompt Injection',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check if MEMORY.md is loaded into the system prompt — persistent prompt injection vector',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const memoryPath = join(installDir, 'MEMORY.md');
    const memoryExists = await ctx.fs.access(memoryPath);

    // Check if memory feature is enabled in config
    let memoryEnabled = false;
    for (const config of ctx.configs) {
      const memoryConfig = getNestedValue(config.data, 'memory')
        ?? getNestedValue(config.data, 'systemPrompt.memory')
        ?? getNestedValue(config.data, 'agent.memory');

      if (memoryConfig !== undefined && memoryConfig !== false) {
        memoryEnabled = true;
      }

      // Check if MEMORY.md is referenced in system prompt includes
      const raw = config.raw;
      if (raw.includes('MEMORY.md') || raw.includes('memory.md')) {
        memoryEnabled = true;
      }
    }

    if (memoryExists && memoryEnabled) {
      try {
        const info = await ctx.fs.stat(memoryPath);
        const worldWritable = (info.mode & 0o002) !== 0;

        evidence.push({
          file: memoryPath,
          detail: worldWritable
            ? 'MEMORY.md is world-writable AND loaded into system prompt — critical prompt injection risk'
            : 'MEMORY.md is loaded into system prompt — content becomes part of agent instructions and can persistently alter behavior',
        });
      } catch {
        evidence.push({
          file: memoryPath,
          detail: 'MEMORY.md exists and memory is enabled — persistent prompt injection vector',
        });
      }
    } else if (memoryExists) {
      evidence.push({
        file: memoryPath,
        detail: 'MEMORY.md exists in workspace — verify it is not loaded into system prompt',
      });
    }

    return {
      id: 'NB-007', name: 'MEMORY.md Prompt Injection', category: 'nanobot',
      severity: 'critical', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No MEMORY.md prompt injection risk detected'
        : 'MEMORY.md may be injected into system prompt — persistent prompt injection vector',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false, fixDescription: 'Restrict write access to MEMORY.md (chmod 400) and audit its contents regularly',
    };
  },
};

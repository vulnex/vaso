import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

export const ws007 = defineCheck({
  id: 'WS-007',
  name: 'Windsurf Legacy Plaintext API Key File',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that the legacy ~/.codeium/config.json (plaintext Codeium API key) is not readable by other users',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const configPath = join(ctx.fs.homedir(), '.codeium', 'config.json');
    if (!(await ctx.fs.access(configPath))) {
      return h.passed('Legacy ~/.codeium/config.json not present');
    }

    const evidence: Evidence[] = [];
    try {
      const perms = await queryPermissions(ctx.fs, configPath);
      if (perms === 'unsupported') {
        return h.passed('Permission facts unavailable on this platform — skipping');
      }
      if (readableByOthers(perms)) {
        evidence.push({
          file: configPath,
          snippet: `mode 0${perms.octal}`,
          detail: 'Legacy Codeium config.json holds a plaintext API key and is readable by group/other',
        });
      }
    } catch {
      // Can't stat — skip silently
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Legacy Codeium config.json has restricted permissions',
      failed: () => 'Legacy Codeium config.json is readable by other users — restrict it to 0600',
      fixable: true,
      fixDescription: 'Remove group/other access from ~/.codeium/config.json (chmod go-rwx ~/.codeium/config.json)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('WS-007', [join(ctx.fs.homedir(), '.codeium', 'config.json')]);
  },
});

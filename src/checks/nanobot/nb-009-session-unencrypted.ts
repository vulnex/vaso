import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const nb009 = defineCheck({
  id: 'NB-009',
  name: 'Unencrypted Session Files',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if session files (JSONL) exist without encryption configured',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;

    let encryptionEnabled = false;
    for (const config of ctx.configs) {
      const encryption = getNestedValue(config.data, 'sessions.encryption')
        ?? getNestedValue(config.data, 'session.encryption')
        ?? getNestedValue(config.data, 'encryption');

      if (encryption === true || (typeof encryption === 'object' && encryption !== null)) {
        encryptionEnabled = true;
        break;
      }
    }

    const sessionDirs = [
      join(installDir, 'workspace', 'sessions'),
      join(installDir, 'sessions'),
      join(installDir, '.sessions'),
      join(installDir, 'data', 'sessions'),
    ];

    let sessionFilesFound = false;
    for (const dir of sessionDirs) {
      try {
        const entries = await ctx.fs.readdir(dir);
        const jsonlFiles = entries.filter(f => f.endsWith('.jsonl') || f.endsWith('.session'));
        if (jsonlFiles.length > 0) {
          sessionFilesFound = true;
          if (!encryptionEnabled) {
            evidence.push({
              file: dir,
              detail: `Found ${jsonlFiles.length} session file(s) in ${dir} without encryption — conversation history is stored in plaintext`,
            });
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: sessionFilesFound ? 'Session files found with encryption enabled' : 'No session files found',
      failed: () => 'Session files found without encryption — plaintext conversation history',
      fixable: true,
      fixDescription: 'Enable session encryption in config: "sessions": { "encryption": true }',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'NB-009',
      path: 'sessions.encryption',
      value: true,
      message: 'Enabled session encryption',
      noConfigMessage: 'No JSON config file found',
    });
  },
});

import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, redactSecretsInLine, isPlaceholderSecret } from '../../core/patterns.js';
import { hookCommandSecrets, hookItems } from '../../analyzers/hook-commands.js';

/** Framework-designated secret files (PicoClaw keeps model/channel keys in
 *  `.security.yml`, written 0600, instead of config.json). */
const SECRET_STORES = new Set(['.security.yml']);

export const cfg002 = defineCheck({
  id: 'CFG-002',
  name: 'API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check for exposed API keys and secrets in config files',

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Skip .env files and dedicated secret stores — they're expected to
      // contain keys (their permissions are CFG-003's concern).
      if (config.format === 'env' || SECRET_STORES.has(basename(config.filePath))) continue;

      const lines = config.raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          const m = pattern.exec(lines[i]);
          if (m && !isPlaceholderSecret(m[0])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: redactSecretsInLine(lines[i]),
              detail: `Found ${name}`,
            });
          }
        }
      }

      // Passwords in hook commands that no token format covers
      // (`--password <pw>`, `https://user:<pw>@host`, `Authorization: Basic …`,
      // `mysql -p<pw>`, `sshpass -p <pw>`)
      const scripts = hookItems(config.data.hooks).flatMap(item => item.scripts);
      const seen = new Set<string>();
      for (const secret of scripts.flatMap(hookCommandSecrets)) {
        if (seen.has(secret.value) || API_KEY_PATTERNS.some(({ pattern }) => pattern.test(secret.value))) continue;
        seen.add(secret.value);
        const at = lines.findIndex(l => l.includes(secret.value));
        evidence.push({
          file: config.filePath,
          ...(at >= 0 ? { line: at + 1 } : {}),
          snippet: redactSecretsInLine(at >= 0 ? lines[at].split(secret.value).join('***') : secret.masked),
          detail: `Found ${secret.kind} in a hook command`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No API keys found in config files',
      failed: (n) => `Found ${n} exposed API key(s) in config files`,
    });
  },
});

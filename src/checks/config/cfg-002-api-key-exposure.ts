import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, redactSecretsAround, redactSecretsInLine, isPlaceholderSecret } from '../../core/patterns.js';
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
              snippet: redactSecretsAround(lines[i], m.index, m[0].length),
              detail: `Found ${name}`,
            });
          }
        }
      }

      // Passwords in hook commands that no token format covers
      // (`--password <pw>`, `https://user:<pw>@host`, `Authorization: Basic …`,
      // `mysql -p<pw>`, `sshpass -p <pw>`)
      // one evidence per value, naming every hook that holds it
      const found = new Map<string, { secret: ReturnType<typeof hookCommandSecrets>[number]; hooks: string[] }>();
      for (const item of hookItems(config.data.hooks)) {
        const hook = item.matcher ? `${item.event} (${item.matcher})` : item.event;
        for (const secret of item.scripts.flatMap(hookCommandSecrets)) {
          if (API_KEY_PATTERNS.some(({ pattern }) => pattern.test(secret.value))) continue;
          const prev = found.get(secret.value);
          if (!prev) found.set(secret.value, { secret, hooks: [hook] });
          else if (!prev.hooks.includes(hook)) prev.hooks.push(hook);
        }
      }
      for (const { secret, hooks } of found.values()) {
        const at = lines.findIndex(l => l.includes(secret.value));
        const pos = at >= 0 ? lines[at].indexOf(secret.value) : -1;
        evidence.push({
          file: config.filePath,
          ...(at >= 0 ? { line: at + 1 } : {}),
          snippet: at >= 0
            ? redactSecretsAround(lines[at].split(secret.value).join('***'), pos, 3)
            : redactSecretsInLine(secret.masked),
          detail: hooks.length > 1
            ? `Found ${secret.kind} in hook commands (${hooks.join(', ')} — same value)`
            : `Found ${secret.kind} in a hook command`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No API keys found in config files',
      failed: (n) => `Found ${n} exposed API key(s) in config files`,
    });
  },
});

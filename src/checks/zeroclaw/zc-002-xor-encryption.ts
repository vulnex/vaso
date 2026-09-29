import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { secretSources } from './zc-secrets.js';

/** Legacy `enc:<hex>` XOR ciphertext as a quoted TOML/JSON string. `enc2:`
 *  (ChaCha20-Poly1305, the current format) does not match. */
const XOR_CIPHER_PATTERN = /["']enc:[0-9A-Za-z+/=]*["']/g;

export const zc002 = defineCheck({
  id: 'ZC-002',
  name: 'Legacy XOR-Encrypted Secrets',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect secrets still stored with the legacy `enc:` XOR cipher (vulnerable to known-plaintext recovery) instead of `enc2:` ChaCha20-Poly1305',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const src of await secretSources(ctx)) {
      const lines = src.raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trim();
        if (t.startsWith('#')) continue;
        const matches = lines[i].match(XOR_CIPHER_PATTERN);
        if (!matches) continue;
        const key = t.split(/\s*[=:]\s*/)[0]?.replace(/["']/g, '') ?? 'value';
        evidence.push({
          file: src.filePath,
          line: i + 1,
          detail: `${key}: ${matches.length} legacy enc: XOR value(s) — upgrade to enc2:`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No legacy XOR-encrypted (enc:) secrets found',
      failed: (n) => `Found ${n} secret(s) still using the legacy XOR cipher`,
      fixDescription:
        'Re-enter the affected secrets with `zeroclaw config set <path>` so they are re-encrypted as enc2: (ChaCha20-Poly1305); remove config.toml.backup once migrated',
    });
  },
});

import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { asRecord, isFalse, mainConfig, writeMainConfig } from './zc-config.js';
import { findPlaintextSecrets, secretSources } from './zc-secrets.js';

export const zc001 = defineCheck({
  id: 'ZC-001',
  name: 'Plaintext Secrets in Config',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect plaintext secret values (provider api_key, reliability.api_keys, channel tokens, webhook secrets, OAuth tokens) in config.toml, auth-profiles.json or the migration backup — typically from secrets.encrypt=false',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let encryptDisabled = false;

    for (const src of await secretSources(ctx)) {
      const secrets = findPlaintextSecrets(src.data);
      const encryptOff = src.main && isFalse(asRecord(src.data.secrets)?.encrypt);
      if (encryptOff) encryptDisabled = true;
      if (secrets.length === 0) continue;
      const shown = secrets.slice(0, 5).map(s => s.path).join(', ');
      const more = secrets.length > 5 ? ` (+${secrets.length - 5} more)` : '';
      evidence.push({
        file: src.filePath,
        detail:
          `${secrets.length} plaintext secret value(s): ${shown}${more}` +
          (encryptOff ? ' — secrets.encrypt=false' : src.main ? '' : ' — not encrypted at rest'),
      });
    }

    // Plaintext secrets in a file other local users can read are directly
    // exploitable; otherwise they are defence-in-depth (the file is 0600).
    let exposed = false;
    const permEvidence: Evidence[] = [];
    for (const e of evidence) {
      try {
        const perms = await queryPermissions(ctx.fs, e.file);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          permEvidence.push({ file: e.file, detail: `mode ${perms.octal}` });
        }
      } catch {}
    }
    await markUnreachable(ctx.fs, permEvidence);
    for (const p of permEvidence) {
      if (p.mitigated) continue;
      exposed = true;
      const e = evidence.find(x => x.file === p.file);
      if (e) e.detail += ` — file is readable by other users (${p.detail})`;
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets found in ZeroClaw config files',
      failed: (n) => `Found plaintext secrets in ${n} ZeroClaw file(s)`,
      severity: exposed ? 'critical' : undefined,
      fixable: encryptDisabled && mainConfig(ctx.configs) !== undefined,
      fixDescription:
        'Set secrets.encrypt=true, then re-enter each secret with `zeroclaw config set <path>` (masked input) so it is stored as enc2: ciphertext; delete config.toml.backup once migrated',
    });
  },

  async fix(ctx) {
    return writeMainConfig(
      ctx,
      'ZC-001',
      [['secrets.encrypt', true]],
      'Set secrets.encrypt=true — re-enter secrets with `zeroclaw config set <path>` so they are written encrypted',
    );
  },
});

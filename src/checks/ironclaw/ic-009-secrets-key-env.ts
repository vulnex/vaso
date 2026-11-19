import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { REBORN_MASTER_KEY_FILE, REBORN_STORAGE_SUBDIRS } from '../../adapters/ironclaw.js';
import { isLegacy, legacyEnv, legacyToml, lineOf, str } from './layout.js';
import { secretShape } from '../../core/patterns.js';

/*
 * The secrets master key decrypts every stored credential (LLM keys, channel
 * tokens, OAuth refresh tokens).
 * 1.x: prefers the OS keychain or $SECRETS_MASTER_KEY; otherwise it persists
 * one to `<reborn home>/<storage>/.reborn-local-dev-secrets-master-key`
 * (0600 by design — only a readable-by-others file is a finding).
 * 0.x: a plaintext SECRETS_MASTER_KEY in ~/.ironclaw/.env (or a
 * secrets_master_key_hex in the settings overlay) sits next to the database
 * it protects. Evaluated even for 0.x state left behind by an upgrade — the
 * key still decrypts the old ironclaw.db.
 */

const PLACEHOLDER = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;

export const ic009 = defineCheck({
  id: 'IC-009',
  name: 'Secrets Master Key Exposure',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check that the secrets master key is not readable by other users (1.x fallback key file) or stored in plaintext next to the database (0.x SECRETS_MASTER_KEY in .env)',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    if (!isLegacy(ctx)) {
      for (const sub of REBORN_STORAGE_SUBDIRS) {
        const keyPath = join(ctx.installation.installDir, sub, REBORN_MASTER_KEY_FILE);
        try {
          if (!(await ctx.fs.access(keyPath))) continue;
          const perms = await queryPermissions(ctx.fs, keyPath);
          if (perms !== 'unsupported' && readableByOthers(perms)) {
            evidence.push({
              file: keyPath,
              snippet: `mode 0${perms.octal ?? '?'}`,
              detail: 'Secrets master key file is readable by group/other — it decrypts every credential in the secrets store',
            });
          }
        } catch {
          // can't stat — skip
        }
      }
      await markUnreachable(ctx.fs, evidence);
    } else {
      const env = legacyEnv(ctx);
      const key = str(env?.data?.SECRETS_MASTER_KEY);
      if (env && key && !PLACEHOLDER.test(key)) {
        const line = lineOf(env, 'SECRETS_MASTER_KEY');
        evidence.push({
          file: env.filePath,
          ...(line ? { line } : {}),
          snippet: `SECRETS_MASTER_KEY=${secretShape(key)}`,
          detail: 'Plaintext secrets master key in .env — anyone who can read this file can decrypt ironclaw.db secrets',
        });
      }
      const toml = legacyToml(ctx);
      const hex = str(toml?.data?.secrets_master_key_hex);
      if (toml && hex) {
        const line = lineOf(toml, 'secrets_master_key_hex');
        evidence.push({
          file: toml.filePath,
          ...(line ? { line } : {}),
          detail: 'secrets_master_key_hex stored in config.toml — plaintext master key next to the database',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Secrets master key is not exposed',
      failed: () => isLegacy(ctx)
        ? 'Secrets master key stored in plaintext config — use the OS keychain'
        : 'Secrets master key file is readable by other users',
      fixDescription: isLegacy(ctx)
        ? 'Move SECRETS_MASTER_KEY out of ~/.ironclaw/.env into the OS keychain (or a secrets manager that injects the env var) and chmod 600 the .env'
        : 'Run `chmod 600` on the .reborn-local-dev-secrets-master-key file, or enable the OS keychain / SECRETS_MASTER_KEY so the file is not needed',
    });
  },
});

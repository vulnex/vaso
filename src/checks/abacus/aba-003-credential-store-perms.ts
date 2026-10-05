import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { abacusDesktopDataDir } from '../../adapters/abacus.js';
import { abacusDir, isProjectInstall } from './shared.js';

export const aba003 = defineCheck({
  id: 'ABA-003',
  name: 'Abacus.AI Credential Store Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify the Abacus.AI keystore (~/.abacusai/keystore.enc — AES-GCM keyed from hostname + $USER, so anyone who can read it can decrypt it) and the desktop app\'s provider-key stores and session cookies are not readable by other users',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) {
      return h.passed('Credential stores are user-level — evaluated on the user installation');
    }

    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const desktop = abacusDesktopDataDir(ctx.fs.homedir(), ctx.fs);
    const targets: { path: string; level: 'critical' | 'warning'; detail: string }[] = [
      { path: join(abacusDir(ctx), 'keystore.enc'), level: 'critical', detail: 'Encrypted with a key derived from hostname + $USER — any reader can decrypt the stored Abacus.AI credentials' },
      { path: join(abacusDir(ctx), 'keystore.enc.unreadable'), level: 'critical', detail: 'Quarantined keystore — still holds the old credentials, decryptable with the old hostname/user' },
      { path: join(desktop, 'provider-keys.json'), level: 'warning', detail: 'Desktop model-provider API keys (Electron safeStorage — weak on Linux without a keyring)' },
      { path: join(desktop, 'cowork-provider-keys.json'), level: 'warning', detail: 'Desktop cowork-mode provider API keys (Electron safeStorage — weak on Linux without a keyring)' },
      { path: join(desktop, 'Cookies'), level: 'warning', detail: 'Desktop session cookies — reuse grants the signed-in Abacus.AI session' },
    ];

    for (const t of targets) {
      if (!(await ctx.fs.access(t.path))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, t.path);
        if (perms === 'unsupported') continue;
        if (!readableByOthers(perms)) continue;
        (t.level === 'critical' ? critical : warning).push({ file: t.path, snippet: `mode 0${perms.octal}`, detail: t.detail });
      } catch {
        // can't stat — skip
      }
    }

    await markUnreachable(ctx.fs, critical);
    await markUnreachable(ctx.fs, warning);
    const liveCritical = critical.some(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Abacus.AI credential stores are owner-only',
      failed: (n) => `Found ${n} Abacus.AI credential store(s) readable by other users`,
      severity: liveCritical ? undefined : 'warning',
      fixDescription: 'chmod 600 ~/.abacusai/keystore.enc and the AbacusAI Desktop provider-keys/cowork-provider-keys/Cookies files; log out and back in (abacusai auth logout) if exposure is suspected',
    });
  },
});

import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const STATSIG_PLIST = 'com.openai.chat.StatsigService.plist';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function maskEmail(addr: string): string {
  const at = addr.indexOf('@');
  if (at <= 1) return '…@…';
  return `${addr.slice(0, 1)}…@${addr.slice(at + 1)}`;
}

export const cg002 = defineCheck({
  id: 'CG-002',
  name: 'Account Email Stored in Plaintext',
  category: 'coding-agent',
  severity: 'info',
  description: 'ChatGPT writes the signed-in account email plaintext to StatsigService.plist; surfaces in Time Machine / iCloud backups',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(STATSIG_PLIST)) continue;
      const email = config.data.userEmail;
      if (typeof email !== 'string' || !EMAIL_RE.test(email)) continue;

      evidence.push({
        file: config.filePath,
        snippet: `userEmail = ${maskEmail(email)}`,
        detail: 'Account email persists in cleartext outside the keychain — included in Time Machine snapshots and any FileVault-decrypted backup',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext account email detected in ChatGPT preferences',
      failed: () => 'ChatGPT account email is stored in plaintext in StatsigService.plist',
      fixDescription: 'Sign out and back in via the app — note OpenAI re-populates this on session restore; consider excluding the plist from backups',
    });
  },
});

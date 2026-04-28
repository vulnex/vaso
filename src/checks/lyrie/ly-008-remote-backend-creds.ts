import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ly008 = defineCheck({
  id: 'LY-008',
  name: 'Remote Backend Credentials in Plaintext .env',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_BACKEND=daytona or modal with API credentials stored plaintext in .env — every Lyrie scan ships repo contents to the remote backend.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const backend = config.data.LYRIE_BACKEND as string | undefined;
      if (backend !== 'daytona' && backend !== 'modal') continue;

      const isPlaceholder = (v: string) => /^\$\{?[A-Z_]+\}?$/.test(v.trim());

      if (backend === 'daytona') {
        const key = config.data.DAYTONA_API_KEY as string | undefined;
        if (key && key.trim() !== '' && !isPlaceholder(key)) {
          evidence.push({
            file: config.filePath,
            detail: 'LYRIE_BACKEND=daytona with plaintext DAYTONA_API_KEY — every scan exfiltrates repo contents to Daytona',
          });
        }
      }

      if (backend === 'modal') {
        const tokenId = config.data.MODAL_TOKEN_ID as string | undefined;
        const tokenSecret = config.data.MODAL_TOKEN_SECRET as string | undefined;
        if (
          (tokenId && tokenId.trim() !== '' && !isPlaceholder(tokenId)) ||
          (tokenSecret && tokenSecret.trim() !== '' && !isPlaceholder(tokenSecret))
        ) {
          evidence.push({
            file: config.filePath,
            detail: 'LYRIE_BACKEND=modal with plaintext MODAL_TOKEN_* — every scan exfiltrates repo contents to Modal',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No remote-backend credentials in plaintext .env',
      failed: () => 'Remote backend uses plaintext credentials and exfiltrates scan inputs',
      fixDescription: 'Move DAYTONA_API_KEY / MODAL_TOKEN_* to a secrets manager and reference via $ENV_VAR substitution; or set LYRIE_BACKEND=local',
    });
  },
});

import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envString, isRealValue, lyrieEnvConfigs } from './env.js';

/**
 * packages/core/src/backends/factory.ts: LYRIE_BACKEND=daytona|modal runs
 * scans in a remote sandbox (DAYTONA_API_KEY / MODAL_TOKEN_ID+SECRET), which
 * uploads the scanned repository to that provider.
 */
export const ly008 = defineCheck({
  id: 'LY-008',
  name: 'Remote Scan Backend With Plaintext Credentials',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_BACKEND=daytona or modal with DAYTONA_API_KEY / MODAL_TOKEN_* stored in plaintext in the .env — every Lyrie scan ships the target repository to the remote sandbox provider, and the long-lived provider credential sits on disk.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieEnvConfigs(ctx.configs)) {
      const backend = envString(config, 'LYRIE_BACKEND')?.toLowerCase();
      if (backend === 'daytona' && isRealValue(envString(config, 'DAYTONA_API_KEY'))) {
        evidence.push({
          file: config.filePath,
          snippet: 'LYRIE_BACKEND=daytona',
          detail: 'Scans run on Daytona with a plaintext DAYTONA_API_KEY — repository contents leave the host',
        });
      }
      if (backend === 'modal' && (isRealValue(envString(config, 'MODAL_TOKEN_ID')) || isRealValue(envString(config, 'MODAL_TOKEN_SECRET')))) {
        evidence.push({
          file: config.filePath,
          snippet: 'LYRIE_BACKEND=modal',
          detail: 'Scans run on Modal with plaintext MODAL_TOKEN_* — repository contents leave the host',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No remote scan backend with plaintext credentials',
      failed: () => 'Remote scan backend configured with plaintext credentials',
      fixDescription: 'Unset LYRIE_BACKEND (defaults to local), or inject DAYTONA_API_KEY / MODAL_TOKEN_* from a secrets manager at runtime instead of the .env',
    });
  },
});

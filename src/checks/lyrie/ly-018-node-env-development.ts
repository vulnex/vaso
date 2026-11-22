import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { envString, lyrieEnvConfigs } from './env.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

/**
 * ShieldManager.isUrlSafe() (packages/core/src/engine/shield-manager.ts)
 * blocks web_fetch/web_search to localhost, 127.0.0.1, 0.0.0.0, 10/8,
 * 192.168/16, 172.16.x, ::1, *.internal and *.local — unless
 * NODE_ENV === "development", in which case it allows them. .env.example
 * ships NODE_ENV=development, so a copied config disables the SSRF guard.
 */
function isDevelopment(v: string | undefined): boolean {
  // exact, like isUrlSafe; `Development` fails config validation (zod enum)
  return v === 'development';
}

export const ly018 = defineCheck({
  id: 'LY-018',
  name: 'NODE_ENV=development Disables Shield SSRF Guard',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect NODE_ENV=development in the Lyrie .env (the .env.example default). In development mode the Shield\'s URL filter lets web_fetch/web_search reach localhost, private networks (10/8, 192.168/16, 172.16) and *.internal/*.local hosts, so a prompt-injected agent can probe and pull data from internal services.',
  supportedAgents: ['lyrie'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieEnvConfigs(ctx.configs)) {
      if (!isDevelopment(envString(config, 'NODE_ENV'))) continue;
      evidence.push({
        file: config.filePath,
        snippet: 'NODE_ENV=development',
        detail: 'Shield URL filter allows requests to localhost and private/internal addresses (SSRF guard off)',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'NODE_ENV is not development — Shield blocks internal URLs',
      failed: () => 'NODE_ENV=development turns off the Shield\'s internal-address URL blocking',
      fixable: true,
      fixDescription: 'Set NODE_ENV=production in the Lyrie .env',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(
      lyrieEnvConfigs(ctx.configs).filter(c => isDevelopment(envString(c, 'NODE_ENV'))),
      {
        checkId: 'LY-018',
        env: 'NODE_ENV',
        value: 'production',
        message: 'Set NODE_ENV=production',
        noConfigMessage: 'No .env with NODE_ENV=development found',
      },
    );
  },
});

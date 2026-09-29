import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { REBORN_WEBUI_TOKEN_FILE } from '../../adapters/ironclaw.js';
import { isLegacy, legacyToml, lineOf, str, table } from './layout.js';

/*
 * 1.x: `<reborn home>/webui-token` (written 0600 by `ironclaw onboard`) is the
 * WebChat v2 bearer token when $IRONCLAW_REBORN_WEBUI_TOKEN is unset. It is
 * also the HMAC key that signs SSO / admin session tokens, so anyone who can
 * read it controls the agent and can mint sessions for any user.
 * 0.x: GATEWAY_AUTH_TOKEN is env-only — a `channels.gateway_auth_token` in the
 * config.toml overlay is ignored with a warning and just leaves a plaintext
 * token in a non-secret file. (An unset token is not a finding: the gateway
 * generates a random one per start.)
 */

export const ic004 = defineCheck({
  id: 'IC-004',
  name: 'WebUI Bearer Token Exposure',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check that the WebChat v2 bearer token file (webui-token, also the session-signing key) is not readable by other users, and that 0.x gateway tokens are not left in the config.toml overlay',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let severity: 'critical' | 'warning' = 'warning';

    if (!isLegacy(ctx)) {
      const tokenPath = join(ctx.installation.installDir, REBORN_WEBUI_TOKEN_FILE);
      try {
        if (await ctx.fs.access(tokenPath)) {
          const perms = await queryPermissions(ctx.fs, tokenPath);
          if (perms !== 'unsupported' && readableByOthers(perms)) {
            severity = 'critical';
            evidence.push({
              file: tokenPath,
              snippet: `mode 0${perms.octal ?? '?'}`,
              detail: 'webui-token is readable by group/other — it authenticates WebChat v2 and signs session tokens',
            });
          }
        }
      } catch {
        // can't stat — skip
      }
      await markUnreachable(ctx.fs, evidence);
    } else {
      const toml = legacyToml(ctx);
      const token = str(table(toml?.data?.channels)?.gateway_auth_token);
      if (toml && token) {
        const line = lineOf(toml, 'gateway_auth_token');
        evidence.push({
          file: toml.filePath,
          ...(line ? { line } : {}),
          detail: 'channels.gateway_auth_token is stored in config.toml — 0.x ignores it (GATEWAY_AUTH_TOKEN is env-only) and the token sits in plaintext',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WebUI/gateway bearer token is not exposed',
      failed: () => isLegacy(ctx)
        ? 'Gateway auth token stored in the config.toml overlay'
        : 'webui-token is readable by other users',
      severity,
      fixDescription: isLegacy(ctx)
        ? 'Remove channels.gateway_auth_token from config.toml and set GATEWAY_AUTH_TOKEN in ~/.ironclaw/.env (mode 600); rotate the token'
        : 'Run `chmod 600 <reborn home>/webui-token` and rotate it (`ironclaw config set` / re-run onboard); prefer $IRONCLAW_REBORN_WEBUI_TOKEN from a secret manager',
    });
  },
});

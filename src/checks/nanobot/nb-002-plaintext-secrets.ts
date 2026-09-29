import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
import { asRecord, nanobotConfigs, worldTraversalBarrier } from './shared.js';

// Secret-bearing leaf keys in nanobot's schema: providers.<p>.apiKey,
// api.apiKey, tools.web.search.apiKey, channel credentials (telegram.token,
// slack.botToken/appToken, feishu.appSecret/encryptKey, email.imapPassword,
// websocket.tokenIssueSecret, …) and MCP server env / headers.
const SECRET_KEY = /(?:api[_-]?key|token|secret|password|passwd|encrypt[_-]?key|credential)$/i;
const AUTH_HEADER = /^(?:authorization|proxy-authorization|x-api-key|api-key)$/i;
// Keys that end like a secret but hold none.
const NOT_SECRET = /^(?:max_?tokens|token_?ttl_?s|token_?issue_?path|webhook_?secret_?token_?path)$/i;
// nanobot resolves ${VAR} references at load time — the recommended form.
const ENV_REF = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/;
const PLACEHOLDER = /^(?:your[-_ ]|xxx|changeme|placeholder|<|replace|todo|example)/i;

interface Hit { path: string; value: string }

function findSecrets(node: unknown, path: string, out: Hit[], depth = 0, underEnvOrHeaders = false): void {
  if (depth > 10) return;
  const rec = asRecord(node);
  if (!rec) return;
  for (const [key, value] of Object.entries(rec)) {
    const p = path ? `${path}.${key}` : key;
    if (typeof value === 'string') {
      const v = value.trim();
      if (!v || ENV_REF.test(v) || PLACEHOLDER.test(v)) continue;
      const secretKey = (SECRET_KEY.test(key) && !NOT_SECRET.test(key)) || AUTH_HEADER.test(key);
      // MCP env / headers: any key naming a credential
      if (secretKey || (underEnvOrHeaders && /(?:key|token|secret|password|auth)/i.test(key))) {
        out.push({ path: p, value: v });
      }
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      const envLike = /^(?:env|headers|extra_?headers)$/i.test(key);
      findSecrets(value, p, out, depth + 1, envLike);
    }
  }
}

function mask(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

export const nb002 = defineCheck({
  id: 'NB-002',
  name: 'Plaintext Secrets in config.json',
  category: 'nanobot',
  severity: 'warning',
  description: 'Find provider API keys, channel bot tokens/passwords and MCP credentials stored as literals in ~/.nanobot/config.json instead of ${VAR} environment references (resolved by nanobot at load time). Escalates to critical when config.json is readable by other users.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let exposed = false;

    for (const config of nanobotConfigs(ctx.configs)) {
      const hits: Hit[] = [];
      findSecrets(config.data, '', hits);
      if (hits.length === 0) continue;

      let exposure = '';
      try {
        const perms = await queryPermissions(ctx.fs, config.filePath);
        // Critical only when every user can actually reach the file: a
        // parent without world traversal (e.g. a 0750 home) blocks it.
        if (perms !== 'unsupported' && perms.worldRead && !(await worldTraversalBarrier(ctx, config.filePath))) {
          exposed = true;
          exposure = ` — and config.json (mode 0${perms.octal}) is readable by all users`;
        }
      } catch {
        // permissions unknown — keep default severity
      }

      for (const hit of hits) {
        evidence.push({
          file: config.filePath,
          snippet: `${hit.path}: ${mask(hit.value)}`,
          detail: `Plaintext secret at ${hit.path}${exposure}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets in nanobot config.json (literals absent or ${VAR} references)',
      failed: (n) => `${n} plaintext secret(s) in nanobot config.json`,
      severity: exposed ? 'critical' : undefined,
      fixDescription: 'Replace literal values with ${VAR} references (e.g. "apiKey": "${OPENROUTER_API_KEY}") and export the variables from the service environment; keep config.json at mode 0600',
    });
  },
});

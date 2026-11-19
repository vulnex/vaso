import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, isCredentialReference, isPlaceholderSecret, secretShape } from '../../core/patterns.js';
import { shannonEntropy } from '../../analyzers/entropy.js';
import { findSourceSecrets } from '../../analyzers/source-secrets.js';
import { findArgSecrets, findUrlSecrets, findValueSecrets, headerSecret, type ConfigSecret } from '../../mcp/config-secrets.js';
import { isHashedValue } from '../../analyzers/secret-values.js';

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 16;

export const mcp003 = defineCheck({
  id: 'MCP-003',
  name: 'Credential Exposure',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for plaintext secrets in MCP server env blocks, config values and server source',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // Scan both the env block and remote-server HTTP headers — a plaintext
        // token in `headers.Authorization` is just as exposed as one in `env`.
        const sources: Array<[string, Record<string, string>]> = [];
        if (server.env) sources.push(['env block', server.env]);
        if (server.headers) sources.push(['header', server.headers]);
        const seen = new Set<string>();
        // credentials inside a value whose name says nothing: a connection URL
        // (`DATABASE_URL=postgres://u:<pw>@db`), a connection string's
        // `Password=`, a session cookie — reported with the argv/URL ones below
        const inValues: ConfigSecret[] = [];

        for (const [location, values] of sources) {
        for (const [key, value] of Object.entries(values)) {
          // a docs example, or where the key is kept (a variable, a secret manager, a file, a profile)
          if (isPlaceholderSecret(value) || isCredentialReference(value)) continue;
          const before = evidence.length;
          // Check against known API key patterns
          for (const { pattern, name } of API_KEY_PATTERNS) {
            if (pattern.test(value)) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${key}=${secretShape(value)}`,
                detail: `Plaintext ${name} in ${location}`,
              });
            }
          }

          // Check for high-entropy values that look like secrets
          const secretKeyPattern = /(?:key|token|secret|password|credential|auth|api_key|apikey|pass)/i;
          // a password hash or digest (`ADMIN_PASSWORD_HASH=$2b$…`) is not the credential
          const hashed = isHashedValue(value) || /[_-]?(?:hash(?:ed)?|digest|fingerprint|checksum)$/i.test(key);
          if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH && !hashed) {
            const entropy = shannonEntropy(value);
            if (entropy > HIGH_ENTROPY_THRESHOLD) {
              // Avoid duplicate if already caught by pattern above
              const alreadyCaught = evidence.some(e =>
                e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${secretShape(value)}`,
                  detail: `High-entropy value (${entropy.toFixed(1)} bits) in secret-named ${location === 'header' ? 'header' : 'env var'}`,
                });
              }
            }
          }
          if (evidence.length > before) {
            seen.add(value.replace(/^\s*(?:Bearer|Basic|Token)\s+/i, '').trim());
            continue;
          }
          const where = `${location === 'header' ? 'headers' : 'env'}.${key}`;
          inValues.push(...findValueSecrets(value, where));
          const cookie = location === 'header' && /^\s*cookie\s*$/i.test(key) ? headerSecret(key, value) : undefined;
          if (cookie) inValues.push({ location: where, kind: cookie, masked: `${key}: ***`, value });
        }
        }

        // The same credentials written into argv or the server URL instead
        // (`--token ghp_…`, `-e KEY=…`, `?api_key=…`, `https://user:pass@…`,
        // `/bot<token>/`) — just as plaintext, and also visible in `ps`
        const placed = [
          ...inValues,
          ...findArgSecrets(server.args ?? [], server.command),
          ...(server.url ? findUrlSecrets(server.url) : []),
        ];
        for (const secret of placed) {
          // One credential is one finding, wherever else the server repeats it
          if ([...seen].some(v => v === secret.value || (v.length >= 12 && (v.includes(secret.value) || secret.value.includes(v))))) continue;
          seen.add(secret.value);
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${secret.location} ${secret.masked}`,
            detail: secret.location.startsWith('args')
              ? `Plaintext ${secret.kind} in server arguments — readable in the config and by any local user via the process list; pass it through the env block from a variable instead`
              : secret.location === 'url'
                ? `Plaintext ${secret.kind} — the URL is stored, logged and sent as written; use a header sourced from a variable instead`
                : `Plaintext ${secret.kind} in ${secret.location} — stored in the config as written; source it from a variable or a secret manager instead`,
          });
        }
      }
    }

    // Only config values can be moved out automatically; source can't.
    const configFindings = evidence.length;

    // Credentials compiled into the server itself ship to every install.
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      const file = source.localPath ?? source.packageName ?? source.serverName;
      for (const secret of findSourceSecrets(source.sourceCode)) {
        evidence.push({
          file,
          line: secret.line,
          snippet: `${secret.key ? `${secret.key}: ` : ''}${secret.masked}`,
          detail: secret.declaredPublic
            ? `Hardcoded ${secret.kind === 'secret-named value' ? 'key' : secret.kind} in server "${source.serverName}" source that the code documents as public by design — confirm it grants nothing beyond what the author says`
            : `Hardcoded ${secret.kind === 'secret-named value' ? 'credential' : secret.kind} in server "${source.serverName}" source — anyone with the package or checkout can use it; load it from the environment instead`,
          ...(secret.declaredPublic ? { mitigated: true } : {}),
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext credentials found in MCP configs or server source',
      failed: (n) => `Found ${n} exposed credential(s) in MCP configs or server source`,
      fixable: configFindings > 0,
      fixDescription: 'Move secrets to environment variables or a secrets manager',
    });
  },
});

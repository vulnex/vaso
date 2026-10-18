import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, isEnvReference, isPlaceholderSecret } from '../../core/patterns.js';
import { shannonEntropy } from '../../analyzers/entropy.js';
import { findSourceSecrets } from '../../analyzers/source-secrets.js';
import { findArgSecrets, findUrlSecrets } from '../../mcp/config-secrets.js';

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

        for (const [location, values] of sources) {
        for (const [key, value] of Object.entries(values)) {
          if (isPlaceholderSecret(value) || isEnvReference(value)) continue; // a docs example or a reference, not a key
          seen.add(value.replace(/^\s*(?:Bearer|Basic|Token)\s+/i, '').trim());
          // Check against known API key patterns
          for (const { pattern, name } of API_KEY_PATTERNS) {
            if (pattern.test(value)) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}${'*'.repeat(Math.max(0, value.length - 8))}`,
                detail: `Plaintext ${name} in ${location}`,
              });
            }
          }

          // Check for high-entropy values that look like secrets
          const secretKeyPattern = /(?:key|token|secret|password|credential|auth|api_key|apikey|pass)/i;
          if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH) {
            const entropy = shannonEntropy(value);
            if (entropy > HIGH_ENTROPY_THRESHOLD) {
              // Avoid duplicate if already caught by pattern above
              const alreadyCaught = evidence.some(e =>
                e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}...`,
                  detail: `High-entropy value (${entropy.toFixed(1)} bits) in secret-named ${location === 'header' ? 'header' : 'env var'}`,
                });
              }
            }
          }
        }
        }

        // The same credentials written into argv or the server URL instead
        // (`--token ghp_…`, `-e KEY=…`, `?api_key=…`, `https://user:pass@…`,
        // `/bot<token>/`) — just as plaintext, and also visible in `ps`
        const placed = [
          ...findArgSecrets(server.args ?? []),
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
              : `Plaintext ${secret.kind} — the URL is stored, logged and sent as written; use a header sourced from a variable instead`,
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

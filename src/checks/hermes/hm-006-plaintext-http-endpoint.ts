import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const LOOPBACK_HTTP = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?\b/i;

interface Found {
  path: string;
  url: string;
}

function walk(obj: unknown, path: string, found: Found[]): void {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === 'string') {
      // Match base_url (any depth) and mcp_servers.<n>.url
      if ((key === 'base_url' || key === 'url' || key === 'http_url' || key === 'sse_url')
          && value.startsWith('http://') && !LOOPBACK_HTTP.test(value)) {
        found.push({ path: here, url: value });
      }
    } else if (value && typeof value === 'object') {
      walk(value, here, found);
    }
  }
}

export const hm006 = defineCheck({
  id: 'HM-006',
  name: 'Hermes Inference / MCP Endpoint Over Plaintext HTTP',
  category: 'hermes',
  severity: 'critical',
  description: 'Detect non-loopback http:// URLs in model.base_url, auxiliary.*.base_url, delegation.base_url, or mcp_servers.<n>.url — prompts, tool calls, and bearer tokens traverse unencrypted.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('cli-config.yaml') && !config.filePath.endsWith('config.yaml')) continue;
      const found: Found[] = [];
      walk(config.data, '', found);
      for (const f of found) {
        evidence.push({
          file: config.filePath,
          snippet: `${f.path} = ${f.url}`,
          detail: 'Inference traffic over plaintext HTTP — credentials, tool args, and prompts traverse unencrypted',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'All Hermes endpoints use HTTPS or loopback transports',
      failed: (n) => `Found ${n} Hermes endpoint(s) using plaintext HTTP`,
      fixDescription: 'Switch to https:// or front the endpoint with a TLS-terminating proxy',
    });
  },
});

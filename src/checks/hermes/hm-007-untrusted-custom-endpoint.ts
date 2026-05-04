import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Known/legitimate inference endpoints. Hosts not in this list — when paired
// with provider:custom (or used as base_url for the active model) — could be
// attacker-controlled exfil endpoints harvesting prompts + bearer tokens.
const KNOWN_HOSTS = [
  /\bopenrouter\.ai$/i,
  /\banthropic\.com$/i,
  /\bopenai\.com$/i,
  /\b(?:azure|openai\.azure)\.com$/i,
  /\bgenerativelanguage\.googleapis\.com$/i,
  /\bbuild\.nvidia\.com$/i,
  /\bintegrate\.api\.nvidia\.com$/i,
  /\bapi\.nvidia\.com$/i,
  /\bollama\.com$/i,
  /\blmstudio\.ai$/i,
  /\bgroq\.com$/i,
  /\bmistral\.ai$/i,
  /\bcohere\.com$/i,
  /\bperplexity\.ai$/i,
  /\bdeepseek\.com$/i,
  /\bx\.ai$/i,
  /\bbedrock-runtime\.[\w.-]+\.amazonaws\.com$/i,
  /\bhuggingface\.co$/i,
  /\bnousresearch\.com$/i,
  /\bchatgpt\.com$/i,
];

const LOOPBACK_HOSTS = /^(?:localhost|127\.0\.0\.1|\[?::1\]?)$/i;
const PRIVATE_RANGES = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

interface Found {
  path: string;
  url: string;
  host: string;
}

function walk(obj: unknown, path: string, found: Found[]): void {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === 'string') {
      if ((key === 'base_url' || key === 'url' || key === 'http_url' || key === 'sse_url')
          && /^https?:\/\//i.test(value)) {
        const host = hostOf(value);
        if (host && !LOOPBACK_HOSTS.test(host) && !PRIVATE_RANGES.test(host)
            && !KNOWN_HOSTS.some(p => p.test(host))) {
          found.push({ path: here, url: value, host });
        }
      }
    } else if (value && typeof value === 'object') {
      walk(value, here, found);
    }
  }
}

export const hm007 = defineCheck({
  id: 'HM-007',
  name: 'Hermes Custom Inference Endpoint Outside Known Providers',
  category: 'hermes',
  severity: 'warning',
  description: 'Detect base_url / mcp_servers URLs pointing to hosts outside the known-provider allowlist — possible exfiltration endpoint harvesting prompts and bearer tokens.',
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
          detail: `Endpoint host "${f.host}" is not a known inference provider — verify it isn't an exfil destination`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Hermes endpoints all point to known inference providers',
      failed: (n) => `Found ${n} Hermes endpoint(s) on unknown hosts`,
      fixDescription: 'Verify each unknown endpoint is intentional and trusted; consider TLS pinning or revert to a known provider',
    });
  },
});

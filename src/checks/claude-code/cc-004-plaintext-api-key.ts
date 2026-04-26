import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shannonEntropy } from '../../analyzers/entropy.js';

const SECRET_KEY_NAMES = /(?:api[_-]?key|token|secret|password|credential|auth)/i;
const KNOWN_KEY_PREFIXES = [
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xoxb-[A-Za-z0-9-]{20,}/,
];
const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_LENGTH = 20;
const ENV_REF_PATTERN = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;

function isSecretValue(value: string): boolean {
  if (value.length < MIN_LENGTH) return false;
  if (ENV_REF_PATTERN.test(value)) return false;
  if (KNOWN_KEY_PREFIXES.some(p => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD;
}

function walkEnv(env: Record<string, unknown>, file: string, prefix: string, evidence: Evidence[]): void {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== 'string') continue;
    if (!SECRET_KEY_NAMES.test(key)) continue;
    if (!isSecretValue(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 6)}…`,
      detail: 'Plaintext secret stored in Claude Code config — use $-references or apiKeyHelper',
    });
  }
}

export const cc004 = defineCheck({
  id: 'CC-004',
  name: 'Plaintext API Key in Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect API keys or tokens stored in plaintext inside Claude Code settings',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const env = config.data.env as Record<string, unknown> | undefined;
      if (env && typeof env === 'object') {
        walkEnv(env, config.filePath, 'env.', evidence);
      }

      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (mcpServers && typeof mcpServers === 'object') {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== 'object') continue;
          const serverEnv = (server as Record<string, unknown>).env as Record<string, unknown> | undefined;
          if (serverEnv && typeof serverEnv === 'object') {
            walkEnv(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext API keys detected in Claude Code settings',
      failed: (n) => `Found ${n} plaintext credential(s) in Claude Code settings`,
      fixDescription: 'Reference secrets via env vars ("$ANTHROPIC_API_KEY") or apiKeyHelper instead of inlining',
    });
  },
});

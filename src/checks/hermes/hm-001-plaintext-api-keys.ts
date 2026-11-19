import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shannonEntropy } from '../../analyzers/entropy.js';
import { isEnvReference, isPlaceholderSecret, secretShape } from '../../core/patterns.js';
import { hermesConfigAsWritten } from '../../adapters/hermes-config.js';

const KEY_NAME_PATTERN = /(?:api[_-]?key|token|secret|password|credential|auth|bot[_-]?token)/i;
const KNOWN_PREFIXES = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^gho_[A-Za-z0-9]{20,}/,
  /^github_pat_[A-Za-z0-9_]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/,
  /^xai-[A-Za-z0-9_-]{20,}/,
  /^\d{8,}:[A-Za-z0-9_-]{35}$/,           // Telegram bot
  /^[MN][\w-]{23,28}\.[\w-]{6,7}\.[\w-]{27,38}$/, // Discord bot
];
const HIGH_ENTROPY = 4.5;
const MIN_LEN = 20;

function isSecret(raw: string): boolean {
  // a YAML `|` block scalar keeps its trailing newline
  const value = raw.trim();
  if (value.length < MIN_LEN) return false;
  if (isPlaceholderSecret(value)) return false;
  if (isEnvReference(value)) return false;
  if (KNOWN_PREFIXES.some(p => p.test(value))) return true;
  // Secrets are single tokens; prose (personality prompts, descriptions —
  // emoji push its entropy past the threshold) is not a credential.
  if (/\s/.test(value)) return false;
  return shannonEntropy(value) > HIGH_ENTROPY;
}

function walk(obj: unknown, file: string, path: string, evidence: Evidence[]): void {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === 'string') {
      const looksSecret = KEY_NAME_PATTERN.test(key) || isSecret(value);
      if (looksSecret && isSecret(value)) {
        evidence.push({
          file,
          snippet: `${here} = ${secretShape(value)}`,
          detail: 'Plaintext credential in Hermes config — move to .env or use ${ENV_VAR} reference',
        });
      }
    } else if (value && typeof value === 'object') {
      walk(value, file, here, evidence);
    }
  }
}

export const hm001 = defineCheck({
  id: 'HM-001',
  name: 'Plaintext API Keys in Hermes Config',
  category: 'hermes',
  severity: 'critical',
  description: 'Detect API keys, OAuth tokens, channel bot tokens, or other secrets stored in plaintext in ~/.hermes/config.yaml (model.api_key, auxiliary.*.api_key, delegation.api_key, mcp_servers.<n>.env.*).',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('cli-config.yaml') && !config.filePath.endsWith('config.yaml')) continue;
      // As written: a ${VAR} reference expands to a secret the file doesn't hold
      walk(hermesConfigAsWritten(config), config.filePath, '', evidence);
    }
    return h.fromEvidence(evidence, {
      passed: 'No plaintext credentials in Hermes config.yaml',
      failed: (n) => `Found ${n} plaintext credential(s) in Hermes config`,
      fixDescription: 'Move secrets to ~/.hermes/.env (with mode 0600) and reference them via ${ENV_VAR} in config.yaml',
    });
  },
});

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

const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;

/** Secrets in each server's env and headers (`Authorization: Bearer …`). */
function walkServers(servers: unknown, file: string, prefix: string, evidence: Evidence[]): void {
  if (!servers || typeof servers !== 'object') return;
  for (const [name, server] of Object.entries(servers as Record<string, unknown>)) {
    if (!server || typeof server !== 'object') continue;
    const { env, headers } = server as Record<string, unknown>;
    if (env && typeof env === 'object') walkEnv(env as Record<string, unknown>, file, `${prefix}${name}.env.`, evidence);
    if (headers && typeof headers === 'object') {
      const literal = Object.fromEntries(Object.entries(headers as Record<string, unknown>)
        .map(([k, v]) => [k, typeof v === 'string' ? v.replace(AUTH_SCHEME, '').trim() : v]));
      walkEnv(literal, file, `${prefix}${name}.headers.`, evidence);
    }
  }
}

const HELPER_KEY_PATTERN = /\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,})/;

/** HTTP hook headers (`type: "http"`). The hooks docs reference secrets as
 *  `$VAR`/`${VAR}` listed in allowedEnvVars; a literal token sits in the file. */
function walkHttpHooks(hooks: unknown, file: string, evidence: Evidence[]): void {
  if (!hooks || typeof hooks !== 'object') return;
  for (const [event, entries] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const list = (entry as Record<string, unknown> | null)?.hooks;
      if (!Array.isArray(list)) continue;
      for (const hook of list as Array<Record<string, unknown> | null>) {
        if (hook?.type !== 'http' || !hook.headers || typeof hook.headers !== 'object') continue;
        const literal = Object.fromEntries(Object.entries(hook.headers as Record<string, unknown>)
          .map(([k, v]) => [k, typeof v === 'string' ? v.replace(AUTH_SCHEME, '').trim() : v]));
        walkEnv(literal, file, `hooks.${event}[http].headers.`, evidence);
      }
    }
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

      walkServers(config.data.mcpServers, config.filePath, 'mcpServers.', evidence);
      walkHttpHooks(config.data.hooks, config.filePath, evidence);

      // apiKeyHelper is a shell command; `echo sk-ant-…` just inlines the key
      const helper = config.data.apiKeyHelper;
      const inline = typeof helper === 'string' ? HELPER_KEY_PATTERN.exec(helper) : null;
      if (inline) {
        evidence.push({
          file: config.filePath,
          snippet: `apiKeyHelper=${inline[0].slice(0, 6)}…`,
          detail: 'apiKeyHelper prints a key written into the command itself — it is plaintext in settings',
        });
      }
      // `claude mcp add` (default local scope) writes per-project servers to
      // ~/.claude.json under projects[path].mcpServers
      const projects = config.data.projects;
      if (projects && typeof projects === 'object') {
        for (const [projectPath, project] of Object.entries(projects as Record<string, unknown>)) {
          walkServers((project as Record<string, unknown> | null)?.mcpServers, config.filePath, `projects[${projectPath}].mcpServers.`, evidence);
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

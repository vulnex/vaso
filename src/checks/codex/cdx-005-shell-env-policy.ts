import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';

type Policy = Record<string, unknown>;

function shellPolicy(data: Record<string, unknown>): Policy | undefined {
  const p = data.shell_environment_policy ?? data.shellEnvironmentPolicy;
  return p && typeof p === 'object' && !Array.isArray(p) ? p as Policy : undefined;
}

/** The policy's `inherit`, lower-cased, or undefined when the file doesn't set it. */
export function inheritOf(policy: Policy | undefined): string | undefined {
  const v = policy?.inherit;
  return typeof v === 'string' ? v.toLowerCase() : undefined;
}

const narrowPattern = (p: unknown) => typeof p === 'string' && p !== '' && !/^\*+$/.test(p);

/**
 * How the policy keeps secrets out of an inherited environment, or undefined.
 * Codex drops names containing KEY/SECRET/TOKEN only with
 * ignore_default_excludes = false (it defaults to true), and an include
 * allowlist — legacy include_only, or `include` entries in the `filters` map —
 * keeps just the matching names (learn.chatgpt.com/docs/config-file).
 */
export function envMitigation(policy: Policy | undefined): string | undefined {
  if (!policy) return undefined;
  if (policy.ignore_default_excludes === false) {
    return 'ignore_default_excludes = false removes every variable named *KEY*, *SECRET* or *TOKEN* first';
  }
  const includeOnly = policy.include_only;
  if (Array.isArray(includeOnly) && includeOnly.length > 0 && includeOnly.every(narrowPattern)) {
    return 'narrowed by an include_only allowlist';
  }
  const filters = policy.filters;
  if (filters && typeof filters === 'object' && !Array.isArray(filters)) {
    const includes = Object.entries(filters as Record<string, unknown>)
      .filter(([, v]) => typeof v === 'string' && v.toLowerCase() === 'include')
      .map(([k]) => k);
    if (includes.length > 0 && includes.every(narrowPattern)) return 'narrowed by `include` filters (an allowlist)';
  }
  return undefined;
}

export const cdx005 = defineCheck({
  id: 'CDX-005',
  name: 'Codex Shell Env Inherits All',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when shell_environment_policy.inherit = "all" (also the default when unset) leaks every env var (including secrets) to subprocess shells without an allowlist or the default secret excludes',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const isProject = ctx.installation.profile === 'project';
    // Profile files only apply under `codex -p <name>` — CDX-008's finding
    const configs = ctx.configs.filter(c => !codexProfileName(c.filePath));
    let explicit = false;

    for (const config of configs) {
      const policy = shellPolicy(config.data);
      const inherit = inheritOf(policy);
      if (inherit !== undefined) explicit = true;
      if (inherit !== 'all') continue;
      const mitigation = envMitigation(policy);
      evidence.push(mitigation
        ? { file: config.filePath, mitigated: true, detail: `shell_environment_policy.inherit = "all", but ${mitigation}` }
        : { file: config.filePath, detail: 'shell_environment_policy.inherit = "all" — every parent env var (incl. AWS_*, GITHUB_TOKEN, ANTHROPIC_API_KEY) is exposed to tool subprocesses and MCP servers' });
    }

    // Unset, Codex inherits everything (ShellEnvironmentPolicyInherit's
    // default is All) — the same exposure, but the vendor default rather than
    // a choice: advice, not a scored finding. The user config decides it; a
    // project layer that sets nothing changes nothing.
    if (!explicit && !isProject) {
      const main = configs.find(c => c.filePath.endsWith('config.toml'));
      if (!envMitigation(main ? shellPolicy(main.data) : undefined)) {
        evidence.push({
          file: main?.filePath ?? join(ctx.installation.installDir, 'config.toml'),
          mitigated: true,
          detail: 'shell_environment_policy.inherit is unset — Codex defaults to "all", passing every parent env var (secrets included) to tool subprocesses; set inherit = "core" or an include allowlist',
        });
      }
    }

    const live = evidence.some(e => !e.mitigated);
    return h.fromEvidence(evidence, {
      passed: 'Codex shell environment policy is restricted',
      failed: () => live
        ? 'Codex inherits the entire process environment into tool subprocesses'
        : 'Codex passes the full process environment to tool subprocesses by default',
      fixDescription: 'Set [shell_environment_policy] inherit = "core" (or "none") and use an include allowlist (filters / include_only) and set for the specific vars tools need',
    });
  },
});

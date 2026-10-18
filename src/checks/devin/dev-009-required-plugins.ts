import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

function describeSource(entry: unknown): { label: string; insecure: boolean } | undefined {
  if (typeof entry === 'string') return { label: entry, insecure: entry.startsWith('http://') };
  if (entry && typeof entry === 'object') {
    const e = entry as Record<string, unknown>;
    const ref = typeof e.url === 'string' ? e.url
      : typeof e.repo === 'string' ? `${String(e.source ?? 'github')}:${e.repo}`
      : undefined;
    if (ref) return { label: ref, insecure: ref.startsWith('http://') };
  }
  return undefined;
}

/**
 * The configuration reference lists only permissions, hooks, mcpServers and
 * read_config_from as project *settings*, but plugin governance reads the
 * checkout's .devin/config.json on its own: the plugins reference names "the
 * requiredPlugins / optionalPlugins / forbiddenPlugins in a checkout's
 * .devin/config.json" as the repo scope (found walking up from cwd), and the
 * 3000.11.3 binary has a `RequirementOrigin::Repo` / `repo:` governance scope.
 * config.local.json is not a governance source.
 *
 * A repo's committed .devin/config.json can declare `requiredPlugins`, which
 * Devin auto-installs (recursively) from git sources for everyone who opens
 * the checkout. Plugins ship skills, hooks, MCP servers and rules, and plugin
 * hooks fail open — so a PR that adds one is a code-execution vector.
 */
export const dev009 = defineCheck({
  id: 'DEV-009',
  name: 'Devin Repository Config Auto-Installs Plugins',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Flag requiredPlugins in a committed project .devin/config.json — Devin auto-installs them (recursively) for everyone who opens the repo; plugins carry hooks, MCP servers and skills',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let insecure = false;

    for (const config of ctx.configs) {
      // config.local.json is gitignored and personal; only committed config is a repo-borne vector
      if (basename(config.filePath) !== 'config.json' || ctx.installation.profile !== 'project') continue;
      const required = config.data.requiredPlugins;
      if (!Array.isArray(required)) continue;
      for (const entry of required) {
        const src = describeSource(entry);
        if (!src) continue;
        if (src.insecure) insecure = true;
        evidence.push({
          file: config.filePath,
          snippet: `requiredPlugins: ${src.label}`,
          detail: src.insecure
            ? 'Required plugin fetched over plaintext http:// — installable code can be swapped in transit'
            : 'Repository requires this plugin — it is auto-installed with its hooks, MCP servers and skills when the repo is opened',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No repository-required Devin plugins',
      failed: (n) => `Repository config auto-installs ${n} Devin plugin(s) — review their sources`,
      severity: insecure ? 'critical' : undefined,
      fixDescription: 'Review each required plugin source; pin to a trusted org/repo over https, or move it to optionalPlugins so it is not auto-installed',
    });
  },
});

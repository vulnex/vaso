import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const DANGEROUS_COMMANDS = new Set([
  'curl', 'wget', 'bash', 'sh', 'zsh', 'perl', 'python', 'python3', 'node',
  'ruby', 'npx', 'uvx', 'ssh', 'scp', 'chmod', 'sudo', 'eval',
]);

/** Allowlists at or above this size without any deny rules get flagged. */
const NON_TRIVIAL_ALLOWLIST = 3;

/** Read a windsurf.* editor setting — flat VS Code key or nested object form. */
function windsurfSetting(data: Record<string, unknown>, key: string): unknown {
  const flat = data[`windsurf.${key}`];
  if (flat !== undefined) return flat;
  const ns = data.windsurf;
  if (ns && typeof ns === 'object') return (ns as Record<string, unknown>)[key];
  return undefined;
}

function stringEntries(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((e): e is string => typeof e === 'string')
    : [];
}

/**
 * An entry is dangerous when it grants a shell/interpreter/downloader either
 * bare ("bash") or as an open prefix ("sh *", "curl *"). Entries ending in
 * " *" are prefix matches; anything after the command name narrows the grant
 * ("python3 scripts/build.py *") and is not flagged.
 */
function dangerousEntry(entry: string): boolean {
  const trimmed = entry.trim();
  const isPrefix = trimmed.endsWith(' *');
  const base = (isPrefix ? trimmed.slice(0, -2) : trimmed).trim();
  const tokens = base.split(/\s+/).filter(t => t.length > 0);
  if (tokens.length !== 1) return false;
  const cmd = tokens[0].split('/').pop() ?? tokens[0];
  return DANGEROUS_COMMANDS.has(cmd.toLowerCase());
}

export const ws002 = defineCheck({
  id: 'WS-002',
  name: 'Windsurf Over-Broad Command Allowlist',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Cascade command allowlist entries that grant shells, interpreters or downloaders, or a non-trivial allowlist with no deny list',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const allowList = stringEntries(windsurfSetting(config.data, 'cascadeCommandsAllowList'));
      if (allowList.length === 0) continue;

      for (const entry of allowList) {
        if (!dangerousEntry(entry)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `windsurf.cascadeCommandsAllowList: "${entry}"`,
          detail: `Allowlisting "${entry}" grants arbitrary command execution — a shell/interpreter/downloader runs anything passed to it`,
        });
      }

      const denyList = stringEntries(windsurfSetting(config.data, 'cascadeCommandsDenyList'));
      if (allowList.length >= NON_TRIVIAL_ALLOWLIST && denyList.length === 0) {
        evidence.push({
          file: config.filePath,
          snippet: `windsurf.cascadeCommandsAllowList: ${allowList.length} entries, windsurf.cascadeCommandsDenyList: empty`,
          detail: 'Non-trivial command allowlist with no deny list — add explicit deny rules for destructive commands',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Windsurf command allowlist contains no over-broad grants',
      failed: (n) => `Found ${n} over-broad Windsurf command allowlist issue(s)`,
      fixDescription: 'Remove bare shell/interpreter entries from cascadeCommandsAllowList and add a cascadeCommandsDenyList',
    });
  },
});
